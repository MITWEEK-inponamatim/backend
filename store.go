package main

// Dual-mode data access (handoff 2.2).
//
// The Go API talks to Supabase Postgres directly through pgx when DATABASE_URL is set,
// using the simple query protocol required by the transaction pooler. When DATABASE_URL is
// empty it keeps using PostgREST, so the stack still runs without a direct database DSN.
// Both backends implement the same small interface so handlers never branch on transport.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type sessionInfo struct {
	ID             string
	CreatedAt      time.Time
	LastActivityAt time.Time
	RevokedAt      *time.Time
	RevokedReason  string
}

type preflightInfo struct {
	ExpiresAt time.Time
	UsedAt    *time.Time
}

type dataStore interface {
	InsertScan(ctx context.Context, row map[string]any) error
	PatchScan(ctx context.Context, scanID string, fields map[string]any) error
	GetScan(ctx context.Context, userID, scanID string) (map[string]any, bool, error)
	ListScans(ctx context.Context, userID string, limit, offset int) ([]any, error)
	InsertFile(ctx context.Context, row map[string]any) error

	InsertPhoneReport(ctx context.Context, row map[string]any) error
	PhoneReportExists(ctx context.Context, userID, numberE164 string) (bool, error)

	GetSession(ctx context.Context, userID, sessionID string) (*sessionInfo, bool, error)
	TouchSession(ctx context.Context, userID, sessionID string, at time.Time) error
	RevokeSessionByID(ctx context.Context, id, reason string) error
	RevokeSessionByToken(ctx context.Context, userID, sessionID, reason string) error
	SessionExists(ctx context.Context, sessionID string) (bool, error)
	InsertSession(ctx context.Context, userID, sessionID, ip, userAgent string) error

	InsertPreflight(ctx context.Context, nonce string, createdAt, expiresAt time.Time, ip string) error
	GetPreflight(ctx context.Context, nonce string) (*preflightInfo, bool, error)
	ConsumePreflight(ctx context.Context, nonce string, at time.Time) (bool, error)

	InsertAuthEvent(ctx context.Context, userID, event, ip string) error
	InsertLLMUsage(ctx context.Context, row map[string]any) error
	Kind() string
	Close()
}

func newStore(s *server) dataStore {
	if dsn := strings.TrimSpace(s.cfg.databaseURL); dsn != "" {
		config, err := pgxpool.ParseConfig(dsn)
		if err == nil {
			// The transaction pooler does not support prepared statements.
			config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
			config.MaxConns = 8
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pool, poolErr := pgxpool.NewWithConfig(ctx, config)
			if poolErr == nil {
				log.Printf("data store: pgx direct Postgres")
				return &pgxStore{pool: pool}
			}
			err = poolErr
		}
		log.Printf("data store: pgx unavailable (%v); falling back to PostgREST", err)
	}
	log.Printf("data store: PostgREST")
	return &restStore{server: s}
}

// ---------------------------------------------------------------- PostgREST backend

type restStore struct {
	server *server
}

func (r *restStore) call(ctx context.Context, method, path string, body any, out any) error {
	return r.server.supabase(ctx, method, path, body, "", out)
}

func (r *restStore) InsertScan(ctx context.Context, row map[string]any) error {
	return r.call(ctx, "POST", "/rest/v1/scans", row, nil)
}

func (r *restStore) PatchScan(ctx context.Context, scanID string, fields map[string]any) error {
	return r.call(ctx, "PATCH", "/rest/v1/scans?id=eq."+url.QueryEscape(scanID), fields, nil)
}

func (r *restStore) GetScan(ctx context.Context, userID, scanID string) (map[string]any, bool, error) {
	path := "/rest/v1/scans?select=id,type,status,outcome,risk_level,report,error,created_at,updated_at,finished_at&user_id=eq." + url.QueryEscape(userID) + "&id=eq." + url.QueryEscape(scanID) + "&limit=1"
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return rows[0], true, nil
}

func (r *restStore) ListScans(ctx context.Context, userID string, limit, offset int) ([]any, error) {
	path := fmt.Sprintf("/rest/v1/scans?select=id,type,input_ref,status,outcome,risk_level,created_at,updated_at,finished_at&user_id=eq.%s&order=created_at.desc&limit=%d&offset=%d", url.QueryEscape(userID), limit, offset)
	var rows []any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (r *restStore) InsertFile(ctx context.Context, row map[string]any) error {
	return r.call(ctx, "POST", "/rest/v1/files", row, nil)
}

func (r *restStore) InsertPhoneReport(ctx context.Context, row map[string]any) error {
	return r.call(ctx, "POST", "/rest/v1/phone_reports", row, nil)
}

// PhoneReportExists backs both the friendly "you already reported this number" answer and the
// race-safe recovery when the unique index rejects a concurrent duplicate insert.
func (r *restStore) PhoneReportExists(ctx context.Context, userID, numberE164 string) (bool, error) {
	path := "/rest/v1/phone_reports?select=id&reported_by=eq." + url.QueryEscape(userID) +
		"&number_e164=eq." + url.QueryEscape(numberE164) + "&limit=1"
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

func (r *restStore) GetSession(ctx context.Context, userID, sessionID string) (*sessionInfo, bool, error) {
	path := "/rest/v1/app_sessions?select=id,created_at,last_activity_at,revoked_at,revoked_reason&user_id=eq." + url.QueryEscape(userID) + "&supabase_session_id=eq." + url.QueryEscape(sessionID) + "&limit=1"
	var rows []struct {
		ID             string     `json:"id"`
		CreatedAt      time.Time  `json:"created_at"`
		LastActivityAt time.Time  `json:"last_activity_at"`
		RevokedAt      *time.Time `json:"revoked_at"`
		RevokedReason  string     `json:"revoked_reason"`
	}
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	row := rows[0]
	return &sessionInfo{ID: row.ID, CreatedAt: row.CreatedAt, LastActivityAt: row.LastActivityAt, RevokedAt: row.RevokedAt, RevokedReason: row.RevokedReason}, true, nil
}

func (r *restStore) TouchSession(ctx context.Context, userID, sessionID string, at time.Time) error {
	path := "/rest/v1/app_sessions?user_id=eq." + url.QueryEscape(userID) + "&supabase_session_id=eq." + url.QueryEscape(sessionID) + "&revoked_at=is.null"
	return r.call(ctx, "PATCH", path, map[string]any{"last_activity_at": at.UTC()}, nil)
}

func (r *restStore) RevokeSessionByID(ctx context.Context, id, reason string) error {
	path := "/rest/v1/app_sessions?id=eq." + url.QueryEscape(id) + "&revoked_at=is.null"
	return r.call(ctx, "PATCH", path, map[string]any{"revoked_at": time.Now().UTC(), "revoked_reason": reason}, nil)
}

func (r *restStore) RevokeSessionByToken(ctx context.Context, userID, sessionID, reason string) error {
	path := "/rest/v1/app_sessions?user_id=eq." + url.QueryEscape(userID) + "&supabase_session_id=eq." + url.QueryEscape(sessionID) + "&revoked_at=is.null"
	return r.call(ctx, "PATCH", path, map[string]any{"revoked_at": time.Now().UTC(), "revoked_reason": reason}, nil)
}

func (r *restStore) SessionExists(ctx context.Context, sessionID string) (bool, error) {
	var rows []struct {
		ID string `json:"id"`
	}
	path := "/rest/v1/app_sessions?select=id&supabase_session_id=eq." + url.QueryEscape(sessionID) + "&limit=1"
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

func (r *restStore) InsertSession(ctx context.Context, userID, sessionID, ip, userAgent string) error {
	return r.call(ctx, "POST", "/rest/v1/app_sessions", map[string]any{"user_id": userID, "supabase_session_id": sessionID, "ip": ip, "user_agent": userAgent}, nil)
}

func (r *restStore) InsertPreflight(ctx context.Context, nonce string, createdAt, expiresAt time.Time, ip string) error {
	return r.call(ctx, "POST", "/rest/v1/auth_preflight", map[string]any{"nonce": nonce, "created_at": createdAt, "expires_at": expiresAt, "ip": ip}, nil)
}

func (r *restStore) GetPreflight(ctx context.Context, nonce string) (*preflightInfo, bool, error) {
	var rows []struct {
		ExpiresAt time.Time  `json:"expires_at"`
		UsedAt    *time.Time `json:"used_at"`
	}
	path := "/rest/v1/auth_preflight?select=expires_at,used_at&nonce=eq." + url.QueryEscape(nonce) + "&limit=1"
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return &preflightInfo{ExpiresAt: rows[0].ExpiresAt, UsedAt: rows[0].UsedAt}, true, nil
}

func (r *restStore) ConsumePreflight(ctx context.Context, nonce string, at time.Time) (bool, error) {
	var consumed []struct {
		Nonce string `json:"nonce"`
	}
	path := "/rest/v1/auth_preflight?select=nonce&nonce=eq." + url.QueryEscape(nonce) + "&used_at=is.null"
	if err := r.call(ctx, "PATCH", path, map[string]any{"used_at": at}, &consumed); err != nil {
		return false, err
	}
	return len(consumed) == 1, nil
}

func (r *restStore) InsertAuthEvent(ctx context.Context, userID, event, ip string) error {
	var user any
	if userID != "" {
		user = userID
	}
	return r.call(ctx, "POST", "/rest/v1/auth_events", map[string]any{"user_id": user, "event": event, "ip": ip}, nil)
}

func (r *restStore) InsertLLMUsage(ctx context.Context, row map[string]any) error {
	return r.call(ctx, "POST", "/rest/v1/llm_usage", row, nil)
}

func (r *restStore) Close() {}

func (r *restStore) Kind() string { return "postgrest" }

// ---------------------------------------------------------------- pgx backend

type pgxStore struct {
	pool *pgxpool.Pool
}

func (p *pgxStore) Close() {
	if p.pool != nil {
		p.pool.Close()
	}
}

func (p *pgxStore) Kind() string { return "pgx" }

func (p *pgxStore) InsertScan(ctx context.Context, row map[string]any) error {
	report, err := marshalJSON(row["report"])
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx,
		`insert into public.scans (id, user_id, type, input_ref, status, report) values ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb)`,
		str(row["id"]), str(row["user_id"]), str(row["type"]), nullableString(row["input_ref"]), str(row["status"]), report)
	return err
}

func (p *pgxStore) PatchScan(ctx context.Context, scanID string, fields map[string]any) error {
	sets := make([]string, 0, 6)
	args := make([]any, 0, 7)
	args = append(args, scanID)
	add := func(column string, value any) {
		args = append(args, value)
		sets = append(sets, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	if value, ok := fields["status"]; ok {
		add("status", str(value))
	}
	if value, ok := fields["outcome"]; ok {
		add("outcome", nullableString(value))
	}
	if value, ok := fields["risk_level"]; ok {
		add("risk_level", nullableString(value))
	}
	if value, ok := fields["error"]; ok {
		add("error", nullableString(value))
	}
	if value, ok := fields["report"]; ok {
		encoded, err := marshalJSON(value)
		if err != nil {
			return err
		}
		args = append(args, encoded)
		sets = append(sets, fmt.Sprintf("report = $%d::jsonb", len(args)))
	}
	if value, ok := fields["finished_at"]; ok {
		if moment, ok := value.(time.Time); ok {
			add("finished_at", moment.UTC())
		}
	}
	if len(sets) == 0 {
		return nil
	}
	_, err := p.pool.Exec(ctx, fmt.Sprintf(`update public.scans set %s where id = $1::uuid`, strings.Join(sets, ", ")), args...)
	return err
}

func (p *pgxStore) GetScan(ctx context.Context, userID, scanID string) (map[string]any, bool, error) {
	var (
		id, kind, status   string
		outcome, riskLevel *string
		report             []byte
		errText            *string
		createdAt          time.Time
		updatedAt          time.Time
		finishedAt         *time.Time
	)
	row := p.pool.QueryRow(ctx,
		`select id, type, status, outcome, risk_level, report, error, created_at, updated_at, finished_at
		 from public.scans where id = $1::uuid and user_id = $2::uuid`, scanID, userID)
	if err := row.Scan(&id, &kind, &status, &outcome, &riskLevel, &report, &errText, &createdAt, &updatedAt, &finishedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	record := map[string]any{
		"id": id, "type": kind, "status": status, "created_at": createdAt, "updated_at": updatedAt,
	}
	if outcome != nil {
		record["outcome"] = *outcome
	}
	if riskLevel != nil {
		record["risk_level"] = *riskLevel
	}
	if errText != nil {
		record["error"] = *errText
	}
	if finishedAt != nil {
		record["finished_at"] = *finishedAt
	}
	if len(report) > 0 {
		var decoded any
		if json.Unmarshal(report, &decoded) == nil {
			record["report"] = decoded
		}
	}
	return record, true, nil
}

func (p *pgxStore) ListScans(ctx context.Context, userID string, limit, offset int) ([]any, error) {
	rows, err := p.pool.Query(ctx,
		`select id, type, input_ref, status, outcome, risk_level, created_at, updated_at, finished_at
		 from public.scans where user_id = $1::uuid order by created_at desc limit $2 offset $3`, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]any, 0, limit)
	for rows.Next() {
		var (
			id, kind, status   string
			inputRef           *string
			outcome, riskLevel *string
			createdAt          time.Time
			updatedAt          time.Time
			finishedAt         *time.Time
		)
		if err := rows.Scan(&id, &kind, &inputRef, &status, &outcome, &riskLevel, &createdAt, &updatedAt, &finishedAt); err != nil {
			return nil, err
		}
		record := map[string]any{"id": id, "type": kind, "status": status, "created_at": createdAt, "updated_at": updatedAt}
		if inputRef != nil {
			record["input_ref"] = *inputRef
		}
		if outcome != nil {
			record["outcome"] = *outcome
		}
		if riskLevel != nil {
			record["risk_level"] = *riskLevel
		}
		if finishedAt != nil {
			record["finished_at"] = *finishedAt
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (p *pgxStore) InsertFile(ctx context.Context, row map[string]any) error {
	_, err := p.pool.Exec(ctx,
		`insert into public.files (user_id, scan_id, bucket, storage_path, sha256, size_bytes, mime, expires_at)
		 values ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)`,
		str(row["user_id"]), str(row["scan_id"]), str(row["bucket"]), str(row["storage_path"]),
		str(row["sha256"]), int64Value(row["size_bytes"]), str(row["mime"]), timeValue(row["expires_at"]))
	return err
}

func (p *pgxStore) InsertPhoneReport(ctx context.Context, row map[string]any) error {
	// The note column is additive (migration 0005); reports never depend on it, so a database
	// that has not applied it yet still accepts the report through the shorter statement.
	if str(row["note"]) != "" {
		_, err := p.pool.Exec(ctx,
			`insert into public.phone_reports (number_e164, category, source, reported_by, status, note)
			 values ($1, $2, $3, $4::uuid, $5, $6)`,
			str(row["number_e164"]), str(row["category"]), str(row["source"]),
			nullableString(row["reported_by"]), str(row["status"]), str(row["note"]))
		return err
	}
	_, err := p.pool.Exec(ctx,
		`insert into public.phone_reports (number_e164, category, source, reported_by, status)
		 values ($1, $2, $3, $4::uuid, $5)`,
		str(row["number_e164"]), str(row["category"]), str(row["source"]),
		nullableString(row["reported_by"]), str(row["status"]))
	return err
}

func (p *pgxStore) PhoneReportExists(ctx context.Context, userID, numberE164 string) (bool, error) {
	var found bool
	err := p.pool.QueryRow(ctx,
		`select exists (select 1 from public.phone_reports where reported_by = $1::uuid and number_e164 = $2)`,
		userID, numberE164).Scan(&found)
	return found, err
}

func (p *pgxStore) GetSession(ctx context.Context, userID, sessionID string) (*sessionInfo, bool, error) {
	var (
		id             string
		createdAt      time.Time
		lastActivityAt time.Time
		revokedAt      *time.Time
		revokedReason  *string
	)
	row := p.pool.QueryRow(ctx,
		`select id, created_at, last_activity_at, revoked_at, revoked_reason from public.app_sessions
		 where user_id = $1::uuid and supabase_session_id = $2 order by created_at desc limit 1`, userID, sessionID)
	if err := row.Scan(&id, &createdAt, &lastActivityAt, &revokedAt, &revokedReason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	info := &sessionInfo{ID: id, CreatedAt: createdAt, LastActivityAt: lastActivityAt, RevokedAt: revokedAt}
	if revokedReason != nil {
		info.RevokedReason = *revokedReason
	}
	return info, true, nil
}

func (p *pgxStore) TouchSession(ctx context.Context, userID, sessionID string, at time.Time) error {
	_, err := p.pool.Exec(ctx,
		`update public.app_sessions set last_activity_at = $3
		 where user_id = $1::uuid and supabase_session_id = $2 and revoked_at is null`, userID, sessionID, at.UTC())
	return err
}

func (p *pgxStore) RevokeSessionByID(ctx context.Context, id, reason string) error {
	_, err := p.pool.Exec(ctx,
		`update public.app_sessions set revoked_at = now(), revoked_reason = $2 where id = $1::uuid and revoked_at is null`, id, reason)
	return err
}

func (p *pgxStore) RevokeSessionByToken(ctx context.Context, userID, sessionID, reason string) error {
	_, err := p.pool.Exec(ctx,
		`update public.app_sessions set revoked_at = now(), revoked_reason = $3
		 where user_id = $1::uuid and supabase_session_id = $2 and revoked_at is null`, userID, sessionID, reason)
	return err
}

func (p *pgxStore) SessionExists(ctx context.Context, sessionID string) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx, `select exists(select 1 from public.app_sessions where supabase_session_id = $1)`, sessionID).Scan(&exists)
	return exists, err
}

func (p *pgxStore) InsertSession(ctx context.Context, userID, sessionID, ip, userAgent string) error {
	_, err := p.pool.Exec(ctx,
		`insert into public.app_sessions (user_id, supabase_session_id, ip, user_agent) values ($1::uuid, $2, $3, $4)`,
		userID, sessionID, ip, userAgent)
	return err
}

func (p *pgxStore) InsertPreflight(ctx context.Context, nonce string, createdAt, expiresAt time.Time, ip string) error {
	_, err := p.pool.Exec(ctx,
		`insert into public.auth_preflight (nonce, created_at, expires_at, ip) values ($1, $2, $3, $4)`,
		nonce, createdAt.UTC(), expiresAt.UTC(), ip)
	return err
}

func (p *pgxStore) GetPreflight(ctx context.Context, nonce string) (*preflightInfo, bool, error) {
	var (
		expiresAt time.Time
		usedAt    *time.Time
	)
	row := p.pool.QueryRow(ctx, `select expires_at, used_at from public.auth_preflight where nonce = $1`, nonce)
	if err := row.Scan(&expiresAt, &usedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &preflightInfo{ExpiresAt: expiresAt, UsedAt: usedAt}, true, nil
}

func (p *pgxStore) ConsumePreflight(ctx context.Context, nonce string, at time.Time) (bool, error) {
	tag, err := p.pool.Exec(ctx, `update public.auth_preflight set used_at = $2 where nonce = $1 and used_at is null`, nonce, at.UTC())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (p *pgxStore) InsertAuthEvent(ctx context.Context, userID, event, ip string) error {
	var user any
	if userID != "" {
		user = userID
	}
	_, err := p.pool.Exec(ctx, `insert into public.auth_events (user_id, event, ip) values ($1::uuid, $2, $3)`, user, event, ip)
	return err
}

func (p *pgxStore) InsertLLMUsage(ctx context.Context, row map[string]any) error {
	_, err := p.pool.Exec(ctx,
		`insert into public.llm_usage (scan_id, model, prompt_tokens, completion_tokens, latency_ms, status)
		 values ($1::uuid, $2, $3, $4, $5, $6)`,
		str(row["scan_id"]), str(row["model"]), intValue(row["prompt_tokens"]), intValue(row["completion_tokens"]),
		intValue(row["latency_ms"]), str(row["status"]))
	return err
}

// ---------------------------------------------------------------- helpers

func marshalJSON(value any) ([]byte, error) {
	if value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(value)
}

func str(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}

func nullableString(value any) any {
	text := str(value)
	if text == "" {
		return nil
	}
	return text
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return int(parsed)
		}
	case string:
		if parsed, err := strconv.Atoi(typed); err == nil {
			return parsed
		}
	}
	return 0
}

func int64Value(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return parsed
		}
	}
	return int64(intValue(value))
}

func timeValue(value any) any {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC()
	case string:
		if parsed, err := time.Parse(time.RFC3339, typed); err == nil {
			return parsed.UTC()
		}
	}
	return nil
}
