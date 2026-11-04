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

// postFilter is the community feed query the handlers can express; both stores read it the same
// way. Sort is "new" or "top", and Number is already a canonical +62 E.164 value.
type postFilter struct {
	Sort     string
	Category string
	Number   string
	Limit    int
	Offset   int
}

// communityPostColumns is shared so a feed row and a detail row never disagree about which
// fields the browser is allowed to see. author_user_id is deliberately absent: only the alias
// leaves this service. status is read because the handlers refuse anything a moderator took
// down, and it is always "active" by the time a row reaches the browser.
const communityPostColumns = "id,number_e164,category,title,body,evidence_url,author_alias,up_count,down_count,score,comment_count,created_at,status"
const communityCommentColumns = "id,post_id,parent_id,body,author_alias,created_at"

type dataStore interface {
	InsertScan(ctx context.Context, row map[string]any) error
	PatchScan(ctx context.Context, scanID string, fields map[string]any) error
	GetScan(ctx context.Context, userID, scanID string) (map[string]any, bool, error)
	ListScans(ctx context.Context, userID string, limit, offset int) ([]any, error)
	InsertFile(ctx context.Context, row map[string]any) error

	InsertPhoneReport(ctx context.Context, row map[string]any) error
	PhoneReportExists(ctx context.Context, userID, numberE164 string) (bool, error)

	InsertCommunityPost(ctx context.Context, row map[string]any) error
	ListCommunityPosts(ctx context.Context, filter postFilter) ([]map[string]any, error)
	GetCommunityPost(ctx context.Context, postID string) (map[string]any, bool, error)
	CastCommunityVote(ctx context.Context, postID, userID string, value int) (map[string]any, bool, error)
	CommunityVotesBy(ctx context.Context, userID string, postIDs []string) (map[string]int, error)
	InsertCommunityComment(ctx context.Context, row map[string]any) error
	GetCommunityComment(ctx context.Context, postID, commentID string) (map[string]any, bool, error)
	ListCommunityComments(ctx context.Context, postID string, limit, offset int) ([]map[string]any, error)
	DangerousNumbers(ctx context.Context, limit, offset int) ([]map[string]any, error)

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

func (r *restStore) InsertCommunityPost(ctx context.Context, row map[string]any) error {
	return r.call(ctx, "POST", "/rest/v1/community_posts", row, nil)
}

// ListCommunityPosts orders inside the database. "top" sorts on the stored generated column
// score, because PostgREST only accepts column names in order=, never an expression.
func (r *restStore) ListCommunityPosts(ctx context.Context, filter postFilter) ([]map[string]any, error) {
	order := "created_at.desc"
	if filter.Sort == "top" {
		order = "score.desc,created_at.desc"
	}
	path := "/rest/v1/community_posts?select=" + communityPostColumns + "&status=eq.active&order=" + order
	if filter.Category != "" {
		path += "&category=eq." + url.QueryEscape(filter.Category)
	}
	if filter.Number != "" {
		path += "&number_e164=eq." + url.QueryEscape(filter.Number)
	}
	path += fmt.Sprintf("&limit=%d&offset=%d", filter.Limit, filter.Offset)
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (r *restStore) GetCommunityPost(ctx context.Context, postID string) (map[string]any, bool, error) {
	path := "/rest/v1/community_posts?select=" + communityPostColumns + "&id=eq." + url.QueryEscape(postID) + "&limit=1"
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return rows[0], true, nil
}

// CastCommunityVote runs the one-statement RPC: an upsert keyed on (post_id, user_id) cannot be
// expressed over REST without a transaction, and two clicks arriving together would otherwise be
// able to write two rows.
func (r *restStore) CastCommunityVote(ctx context.Context, postID, userID string, value int) (map[string]any, bool, error) {
	var rows []map[string]any
	body := map[string]any{"p_post_id": postID, "p_user_id": userID, "p_value": value}
	if err := r.call(ctx, "POST", "/rest/v1/rpc/cast_vote", body, &rows); err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return rows[0], true, nil
}

func (r *restStore) CommunityVotesBy(ctx context.Context, userID string, postIDs []string) (map[string]int, error) {
	votes := map[string]int{}
	if len(postIDs) == 0 {
		return votes, nil
	}
	quoted := make([]string, 0, len(postIDs))
	for _, id := range postIDs {
		quoted = append(quoted, "%22"+url.QueryEscape(id)+"%22")
	}
	path := "/rest/v1/community_votes?select=post_id,value&user_id=eq." + url.QueryEscape(userID) +
		"&post_id=in.(" + strings.Join(quoted, ",") + ")"
	var rows []struct {
		PostID string `json:"post_id"`
		Value  int    `json:"value"`
	}
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		votes[row.PostID] = row.Value
	}
	return votes, nil
}

func (r *restStore) InsertCommunityComment(ctx context.Context, row map[string]any) error {
	return r.call(ctx, "POST", "/rest/v1/community_comments", row, nil)
}

// GetCommunityComment is the reply guard: the caller has to prove the parent lives in this post,
// is still active, and is itself a top-level comment.
func (r *restStore) GetCommunityComment(ctx context.Context, postID, commentID string) (map[string]any, bool, error) {
	path := "/rest/v1/community_comments?select=" + communityCommentColumns +
		"&id=eq." + url.QueryEscape(commentID) + "&post_id=eq." + url.QueryEscape(postID) + "&status=eq.active&limit=1"
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return rows[0], true, nil
}

func (r *restStore) ListCommunityComments(ctx context.Context, postID string, limit, offset int) ([]map[string]any, error) {
	path := "/rest/v1/community_comments?select=" + communityCommentColumns +
		"&post_id=eq." + url.QueryEscape(postID) + "&status=eq.active" +
		"&order=created_at.asc" + fmt.Sprintf("&limit=%d&offset=%d", limit, offset)
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (r *restStore) DangerousNumbers(ctx context.Context, limit, offset int) ([]map[string]any, error) {
	path := "/rest/v1/dangerous_numbers?select=*&order=verified_reports.desc,last_report_at.desc" +
		fmt.Sprintf("&limit=%d&offset=%d", limit, offset)
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
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
	// Optional columns are only named when they carry a value, so a database that has not applied
	// a later migration still accepts the reports that do not use it. The handler decides which
	// of them it can live without: the note may be dropped, the evidence may not.
	columns := []string{"number_e164", "category", "source", "reported_by", "status"}
	values := []any{
		str(row["number_e164"]), str(row["category"]), str(row["source"]),
		nullableString(row["reported_by"]), str(row["status"]),
	}
	placeholders := []string{"$1", "$2", "$3", "$4::uuid", "$5"}
	for _, key := range []string{"note", "evidence_url", "evidence_public_id"} {
		if str(row[key]) != "" {
			columns = append(columns, key)
			values = append(values, str(row[key]))
			placeholders = append(placeholders, fmt.Sprintf("$%d", len(values)))
		}
	}
	_, err := p.pool.Exec(ctx, fmt.Sprintf(
		"insert into public.phone_reports (%s) values (%s)",
		strings.Join(columns, ", "), strings.Join(placeholders, ", ")), values...)
	return err
}

func (p *pgxStore) PhoneReportExists(ctx context.Context, userID, numberE164 string) (bool, error) {
	var found bool
	err := p.pool.QueryRow(ctx,
		`select exists (select 1 from public.phone_reports where reported_by = $1::uuid and number_e164 = $2)`,
		userID, numberE164).Scan(&found)
	return found, err
}

func (p *pgxStore) InsertCommunityPost(ctx context.Context, row map[string]any) error {
	// score is a generated column: naming it in an insert is an error, so it is left out here
	// and read back from the database.
	_, err := p.pool.Exec(ctx,
		`insert into public.community_posts
		 (id, number_e164, category, title, body, evidence_url, evidence_public_id, author_user_id, author_alias, status)
		 values ($1::uuid, $2, $3, $4, $5, $6, $7, $8::uuid, $9, $10)`,
		str(row["id"]), str(row["number_e164"]), str(row["category"]), str(row["title"]), str(row["body"]),
		str(row["evidence_url"]), str(row["evidence_public_id"]), str(row["author_user_id"]),
		str(row["author_alias"]), str(row["status"]))
	return err
}

func (p *pgxStore) ListCommunityPosts(ctx context.Context, filter postFilter) ([]map[string]any, error) {
	args := []any{filter.Limit, filter.Offset}
	sql := `select id, number_e164, category, title, body, evidence_url, author_alias,
	               up_count, down_count, score, comment_count, created_at, status
	          from public.community_posts
	         where status = 'active'`
	if filter.Category != "" {
		args = append(args, filter.Category)
		sql += fmt.Sprintf(" and category = $%d", len(args))
	}
	if filter.Number != "" {
		args = append(args, filter.Number)
		sql += fmt.Sprintf(" and number_e164 = $%d", len(args))
	}
	if filter.Sort == "top" {
		sql += " order by score desc, created_at desc"
	} else {
		sql += " order by created_at desc"
	}
	sql += " limit $1 offset $2"
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]map[string]any, 0, filter.Limit)
	for rows.Next() {
		var row postFields
		if err := rows.Scan(&row.id, &row.number, &row.category, &row.title, &row.body, &row.evidence, &row.alias,
			&row.up, &row.down, &row.score, &row.comments, &row.createdAt, &row.state); err != nil {
			return nil, err
		}
		result = append(result, postRecord(row))
	}
	return result, rows.Err()
}

func (p *pgxStore) GetCommunityPost(ctx context.Context, postID string) (map[string]any, bool, error) {
	var row postFields
	err := p.pool.QueryRow(ctx,
		`select id, number_e164, category, title, body, evidence_url, author_alias,
		        up_count, down_count, score, comment_count, created_at, status
		   from public.community_posts where id = $1::uuid`, postID).
		Scan(&row.id, &row.number, &row.category, &row.title, &row.body, &row.evidence, &row.alias,
			&row.up, &row.down, &row.score, &row.comments, &row.createdAt, &row.state)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return postRecord(row), true, nil
}

func (p *pgxStore) CastCommunityVote(ctx context.Context, postID, userID string, value int) (map[string]any, bool, error) {
	var up, down, mine int
	err := p.pool.QueryRow(ctx,
		`select up_count, down_count, my_vote from public.cast_vote($1::uuid, $2::uuid, $3)`,
		postID, userID, value).Scan(&up, &down, &mine)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return map[string]any{"up_count": up, "down_count": down, "my_vote": mine}, true, nil
}

func (p *pgxStore) CommunityVotesBy(ctx context.Context, userID string, postIDs []string) (map[string]int, error) {
	votes := map[string]int{}
	if len(postIDs) == 0 {
		return votes, nil
	}
	args := []any{userID}
	marks := make([]string, 0, len(postIDs))
	for _, id := range postIDs {
		args = append(args, id)
		marks = append(marks, fmt.Sprintf("$%d::uuid", len(args)))
	}
	rows, err := p.pool.Query(ctx,
		fmt.Sprintf(`select post_id, value from public.community_votes
		              where user_id = $1::uuid and post_id in (%s)`, strings.Join(marks, ", ")), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var postID string
		var value int
		if err := rows.Scan(&postID, &value); err != nil {
			return nil, err
		}
		votes[postID] = value
	}
	return votes, rows.Err()
}

func (p *pgxStore) InsertCommunityComment(ctx context.Context, row map[string]any) error {
	_, err := p.pool.Exec(ctx,
		`insert into public.community_comments (id, post_id, parent_id, body, author_user_id, author_alias, status)
		 values ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6, $7)`,
		str(row["id"]), str(row["post_id"]), nullableString(row["parent_id"]), str(row["body"]),
		str(row["author_user_id"]), str(row["author_alias"]), str(row["status"]))
	return err
}

func (p *pgxStore) GetCommunityComment(ctx context.Context, postID, commentID string) (map[string]any, bool, error) {
	var (
		id, body, alias string
		parentID        *string
		createdAt       time.Time
	)
	err := p.pool.QueryRow(ctx,
		`select id, post_id, parent_id, body, author_alias, created_at
		   from public.community_comments
		  where id = $1::uuid and post_id = $2::uuid and status = 'active'`, commentID, postID).
		Scan(&id, &postID, &parentID, &body, &alias, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return commentRecord(id, postID, parentID, body, alias, createdAt), true, nil
}

func (p *pgxStore) ListCommunityComments(ctx context.Context, postID string, limit, offset int) ([]map[string]any, error) {
	rows, err := p.pool.Query(ctx,
		`select id, post_id, parent_id, body, author_alias, created_at
		   from public.community_comments
		  where post_id = $1::uuid and status = 'active'
		  order by created_at asc limit $2 offset $3`, postID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]map[string]any, 0, limit)
	for rows.Next() {
		var (
			id, related, body, alias string
			parentID                 *string
			createdAt                time.Time
		)
		if err := rows.Scan(&id, &related, &parentID, &body, &alias, &createdAt); err != nil {
			return nil, err
		}
		result = append(result, commentRecord(id, related, parentID, body, alias, createdAt))
	}
	return result, rows.Err()
}

func (p *pgxStore) DangerousNumbers(ctx context.Context, limit, offset int) ([]map[string]any, error) {
	rows, err := p.pool.Query(ctx,
		`select number_e164, verified_reports, verified_reporters, total_reports, last_report_at,
		        community_posts, community_score
		   from public.dangerous_numbers
		  order by verified_reports desc, last_report_at desc limit $1 offset $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]map[string]any, 0, limit)
	for rows.Next() {
		var (
			number                                   string
			verified, reporters, total, posts, score int
			lastReportAt                             *time.Time
		)
		if err := rows.Scan(&number, &verified, &reporters, &total, &lastReportAt, &posts, &score); err != nil {
			return nil, err
		}
		record := map[string]any{
			"number_e164": number, "verified_reports": verified, "verified_reporters": reporters,
			"total_reports": total, "community_posts": posts, "community_score": score,
		}
		if lastReportAt != nil {
			record["last_report_at"] = moment(*lastReportAt)
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

// moment keeps the two stores producing the same JSON: PostgREST already hands back timestamp
// strings, so the direct-database path formats them the same way instead of shipping Go's own.
func moment(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

// postFields is one scanned community_posts row; postRecord gives it the same JSON shape the
// PostgREST path returns, so the handlers never learn which store answered.
type postFields struct {
	id, number, category, title, body, evidence, alias, state string
	up, down, score, comments                                 int
	createdAt                                                 time.Time
}

func postRecord(row postFields) map[string]any {
	return map[string]any{
		"id": row.id, "number_e164": row.number, "category": row.category, "title": row.title,
		"body": row.body, "evidence_url": row.evidence, "author_alias": row.alias,
		"up_count": row.up, "down_count": row.down, "score": row.score,
		"comment_count": row.comments, "created_at": moment(row.createdAt), "status": row.state,
	}
}

func commentRecord(id, postID string, parentID *string, body, alias string, createdAt time.Time) map[string]any {
	record := map[string]any{
		"id": id, "post_id": postID, "body": body, "author_alias": alias, "created_at": moment(createdAt),
	}
	if parentID != nil {
		record["parent_id"] = *parentID
	}
	return record
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
