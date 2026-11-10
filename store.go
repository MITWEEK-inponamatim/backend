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
	"net/http"
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

// queueFilter is one moderation queue: a status bucket, an optional search, and a page. Which
// columns a free-text search may reach belongs to the table, so each store supplies its own.
type queueFilter struct {
	Status string
	Search string
	Limit  int
	Offset int
}

// phoneReportSearchCols and communityPostSearchCols are the columns the console's search box can
// read. Both start with the number, because that is what a moderator is usually looking for.
var (
	phoneReportSearchCols   = []string{"number_e164", "note", "category"}
	communityPostSearchCols = []string{"number_e164", "title", "body"}
)

// rest renders the filter as PostgREST query parameters.
func (f queueFilter) rest(columns ...string) string {
	var clauses []string
	if f.Status != "" && f.Status != "all" {
		clauses = append(clauses, "status=eq."+url.QueryEscape(f.Status))
	}
	if clause := f.searchClause(columns...); clause != "" {
		clauses = append(clauses, clause)
	}
	if len(clauses) == 0 {
		return ""
	}
	return "&" + strings.Join(clauses, "&")
}

// searchClause narrows a search to one canonical number when the text is a number, and to a
// substring sweep over the queue's own columns when it is not.
func (f queueFilter) searchClause(columns ...string) string {
	if f.Search == "" {
		return ""
	}
	if e164, ok := communityNumberKey(f.Search); ok {
		return "number_e164=eq." + url.QueryEscape(e164)
	}
	pattern := searchPattern(f.Search)
	if pattern == "" {
		return ""
	}
	// Spaces go out as %20: QueryEscape would write a "+" that PostgREST is free to read as a
	// literal plus sign.
	wildcard := strings.ReplaceAll(pattern, " ", "%20")
	likes := make([]string, 0, len(columns))
	for _, column := range columns {
		likes = append(likes, column+".ilike.*"+wildcard+"*")
	}
	return "or=(" + strings.Join(likes, ",") + ")"
}

// MAX_SEARCH_RUNES bounds the query string a console search can produce.
const maxSearchRunes = 60

// searchPattern keeps a free-text search from becoming filter grammar: PostgREST reads
// parentheses, commas, dots and wildcards as instructions, so anything that is not a plain word
// character is cut before the value is handed back to it.
func searchPattern(raw string) string {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return ""
	}
	var kept []rune
	for _, r := range trimmed {
		if len(kept) >= maxSearchRunes {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == ' ':
			kept = append(kept, r)
		}
	}
	return strings.Join(strings.Fields(string(kept)), " ")
}

// where builds the same filter for the direct Postgres path. Placeholders are numbered from
// `first`, so a caller that already bound limit and offset passes 3.
func (f queueFilter) where(first int, columns ...string) (string, []any) {
	var clauses []string
	var args []any
	bind := func(clause string, arg any) {
		clauses = append(clauses, strings.ReplaceAll(clause, "$?", fmt.Sprintf("$%d", first+len(args))))
		args = append(args, arg)
	}
	if f.Status != "" && f.Status != "all" {
		bind("status = $?", f.Status)
	}
	if f.Search != "" {
		if e164, ok := communityNumberKey(f.Search); ok {
			bind("number_e164 = $?", e164)
		} else if pattern := searchPattern(f.Search); pattern != "" {
			likes := make([]string, 0, len(columns))
			for _, column := range columns {
				likes = append(likes, column+" ilike $?")
			}
			bind("("+strings.Join(likes, " or ")+")", "%"+pattern+"%")
		}
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " where " + strings.Join(clauses, " and "), args
}

// communityPostColumns is shared so a feed row and a detail row never disagree about which
// fields the browser is allowed to see. author_user_id is read only so a handler can answer
// "is this the caller's own post" and is stripped before the row leaves this service — the
// account id is a stable identifier, so only the alias reaches the browser. status is read
// because the handlers refuse anything a moderator took down, and it is always "active" by the
// time a row reaches the browser.
const communityPostColumns = "id,number_e164,category,title,body,evidence_url,author_alias,author_user_id,evidence_public_id,up_count,down_count,score,comment_count,created_at,status"
const communityCommentColumns = "id,post_id,parent_id,body,author_alias,author_user_id,created_at"

// phoneReportColumns is read only by the moderation queue, which is the single place allowed to
// see reported_by. The handler turns that account id into an alias before the row leaves the API.
const phoneReportColumns = "id,number_e164,category,source,status,note,evidence_url,reported_by,created_at"

type dataStore interface {
	InsertScan(ctx context.Context, row map[string]any) error
	PatchScan(ctx context.Context, scanID string, fields map[string]any) error
	GetScan(ctx context.Context, userID, scanID string) (map[string]any, bool, error)
	ListScans(ctx context.Context, userID string, types []string, limit, offset int) ([]any, error)
	InsertFile(ctx context.Context, row map[string]any) error

	InsertPhoneReport(ctx context.Context, row map[string]any) error
	PhoneReportExists(ctx context.Context, userID, numberE164 string) (bool, error)

	InsertCommunityPost(ctx context.Context, row map[string]any) error
	ListCommunityPosts(ctx context.Context, filter postFilter) ([]map[string]any, error)
	GetCommunityPost(ctx context.Context, postID string) (map[string]any, bool, error)
	DeleteCommunityPost(ctx context.Context, postID, userID string) (bool, error)
	CastCommunityVote(ctx context.Context, postID, userID string, value int) (map[string]any, bool, error)
	CommunityVotesBy(ctx context.Context, userID string, postIDs []string) (map[string]int, error)
	InsertCommunityComment(ctx context.Context, row map[string]any) error
	GetCommunityComment(ctx context.Context, postID, commentID string) (map[string]any, bool, error)
	ListCommunityComments(ctx context.Context, postID string, limit, offset int) ([]map[string]any, error)
	DeleteCommunityComment(ctx context.Context, postID, commentID, userID string) (bool, error)
	DangerousNumbers(ctx context.Context, limit, offset int) ([]map[string]any, error)

	GetSession(ctx context.Context, userID, sessionID string) (*sessionInfo, bool, error)
	TouchSession(ctx context.Context, userID, sessionID string, at time.Time) error
	RevokeSessionByID(ctx context.Context, id, reason string) error
	GetUserRole(ctx context.Context, userID string) (string, error)
	ListCommunityPostsAdmin(ctx context.Context, filter queueFilter) ([]map[string]any, error)
	UpdateCommunityPostStatus(ctx context.Context, postID, status string) (bool, error)
	CountCommunityPostsAdmin(ctx context.Context, filter queueFilter) (int, error)
	ListPhoneReportsAdmin(ctx context.Context, filter queueFilter) ([]map[string]any, error)
	GetPhoneReportAdmin(ctx context.Context, reportID string) (map[string]any, bool, error)
	CountPhoneReportsAdmin(ctx context.Context, filter queueFilter) (int, error)
	DeskStats(ctx context.Context, rng string) (map[string]any, error)

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
	path := "/rest/v1/scans?select=id,type,input_ref,status,outcome,risk_level,report,error,created_at,updated_at,finished_at&user_id=eq." + url.QueryEscape(userID) + "&id=eq." + url.QueryEscape(scanID) + "&limit=1"
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return rows[0], true, nil
}

func (r *restStore) ListScans(ctx context.Context, userID string, types []string, limit, offset int) ([]any, error) {
	path := fmt.Sprintf("/rest/v1/scans?select=id,type,input_ref,status,outcome,risk_level,created_at,updated_at,finished_at&user_id=eq.%s&order=created_at.desc&limit=%d&offset=%d", url.QueryEscape(userID), limit, offset)
	if len(types) > 0 {
		path += "&type=in.(" + strings.Join(types, ",") + ")"
	}
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

// DeleteCommunityPost erases one post for good. The ownership test is part of the filter rather
// than a check in front of it: "this id AND this author" cannot be talked into deleting somebody
// else's row, and somebody else's post simply answers "nothing was deleted".
func (r *restStore) DeleteCommunityPost(ctx context.Context, postID, userID string) (bool, error) {
	path := "/rest/v1/community_posts?id=eq." + url.QueryEscape(postID) + "&author_user_id=eq." + url.QueryEscape(userID)
	var rows []map[string]any
	if err := r.call(ctx, http.MethodDelete, path, nil, &rows); err != nil {
		return false, err
	}
	return len(rows) > 0, nil
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

// DeleteCommunityComment erases one comment for good. The comment's own replies go with it, because
// parent_id is declared on delete cascade — which is why the confirmation dialog says so out loud
// instead of letting somebody discover it after the click.
func (r *restStore) DeleteCommunityComment(ctx context.Context, postID, commentID, userID string) (bool, error) {
	path := "/rest/v1/community_comments?id=eq." + url.QueryEscape(commentID) +
		"&post_id=eq." + url.QueryEscape(postID) +
		"&author_user_id=eq." + url.QueryEscape(userID)
	var rows []map[string]any
	if err := r.call(ctx, http.MethodDelete, path, nil, &rows); err != nil {
		return false, err
	}
	return len(rows) > 0, nil
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
func (r *restStore) GetUserRole(ctx context.Context, userID string) (string, error) {
	path := "/rest/v1/profiles?select=role&id=eq." + url.QueryEscape(userID) + "&limit=1"
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "user", nil
	}
	if role, ok := rows[0]["role"].(string); ok {
		return role, nil
	}
	return "user", nil
}

func (r *restStore) ListCommunityPostsAdmin(ctx context.Context, filter queueFilter) ([]map[string]any, error) {
	path := "/rest/v1/community_posts?select=" + communityPostColumns + "&order=created_at.desc" +
		filter.rest(communityPostSearchCols...) + pageQuery(filter.Limit, filter.Offset)
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (r *restStore) UpdateCommunityPostStatus(ctx context.Context, postID, status string) (bool, error) {
	path := "/rest/v1/community_posts?id=eq." + url.QueryEscape(postID)
	// supabase() already asks PostgREST for the patched rows back, so one round trip both writes
	// and answers "did that id exist" — an empty result means it did not.
	var rows []map[string]any
	if err := r.call(ctx, "PATCH", path, map[string]any{"status": status}, &rows); err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

func (r *restStore) CountCommunityPostsAdmin(ctx context.Context, filter queueFilter) (int, error) {
	return r.total(ctx, "/rest/v1/community_posts?select=id"+filter.rest(communityPostSearchCols...))
}

func (r *restStore) ListPhoneReportsAdmin(ctx context.Context, filter queueFilter) ([]map[string]any, error) {
	path := "/rest/v1/phone_reports?select=" + phoneReportColumns + "&order=created_at.desc" +
		filter.rest(phoneReportSearchCols...) + pageQuery(filter.Limit, filter.Offset)
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (r *restStore) GetPhoneReportAdmin(ctx context.Context, reportID string) (map[string]any, bool, error) {
	path := "/rest/v1/phone_reports?select=" + phoneReportColumns + "&id=eq." + url.QueryEscape(reportID) + "&limit=1"
	var rows []map[string]any
	if err := r.call(ctx, "GET", path, nil, &rows); err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return rows[0], true, nil
}

func (r *restStore) CountPhoneReportsAdmin(ctx context.Context, filter queueFilter) (int, error) {
	return r.total(ctx, "/rest/v1/phone_reports?select=id"+filter.rest(phoneReportSearchCols...))
}

// DeskStats asks Postgres for the whole console dashboard in one call. Two roads are closed:
// PostgREST cannot group by a truncated date, and pulling the raw rows here to count them in Go
// would run into the 1 MiB cap supabase() puts on every response, which turns a missing month
// into a quiet zero rather than an error. admin_desk_stats() does the arithmetic in the database
// and hands back one jsonb object.
//
// The answer is read as bytes rather than straight into a map because PostgREST does not wrap a
// function that returns jsonb in a row set: the body is the object itself. A function returning a
// composite or a set of rows does come back as an array, so both shapes are accepted and neither
// one is allowed to pass as an empty dashboard.
func (r *restStore) DeskStats(ctx context.Context, rng string) (map[string]any, error) {
	var raw json.RawMessage
	if err := r.call(ctx, "POST", "/rest/v1/rpc/admin_desk_stats", map[string]any{"p_range": rng}, &raw); err != nil {
		return nil, err
	}
	body := strings.TrimSpace(string(raw))
	if body == "" {
		return nil, errors.New("desk stats returned no row")
	}
	if strings.HasPrefix(body, "[") {
		var rows []map[string]any
		if err := json.Unmarshal([]byte(body), &rows); err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, errors.New("desk stats returned no row")
		}
		return rows[0], nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// pageQuery is the paging tail every queue list sends, kept in one place so a queue can never page
// with a limit the count did not see.
func pageQuery(limit, offset int) string {
	return "&limit=" + strconv.Itoa(limit) + "&offset=" + strconv.Itoa(offset)
}

// total counts the rows a filter matches. PostgREST reports it in the Content-Range header of a
// HEAD request, so no body is fetched; a response without that header is an error the caller
// decides how to degrade, never a silent zero.
func (r *restStore) total(ctx context.Context, path string) (int, error) {
	if r.server.cfg.supabaseURL == "" {
		return 0, errors.New("supabase URL missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, r.server.cfg.supabaseURL+path, nil)
	if err != nil {
		return 0, err
	}
	key := r.server.cfg.secretKey
	req.Header.Set("apikey", key)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Prefer", "count=exact")
	resp, err := r.server.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("count returned status %d", resp.StatusCode)
	}
	_, after, ok := strings.Cut(resp.Header.Get("Content-Range"), "/")
	if !ok {
		return 0, errors.New("count header missing")
	}
	total, err := strconv.Atoi(strings.TrimSpace(after))
	if err != nil || total < 0 {
		return 0, fmt.Errorf("count header %q unreadable", after)
	}
	return total, nil
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
		inputRef           *string
		outcome, riskLevel *string
		report             []byte
		errText            *string
		createdAt          time.Time
		updatedAt          time.Time
		finishedAt         *time.Time
	)
	row := p.pool.QueryRow(ctx,
		`select id, type, input_ref, status, outcome, risk_level, report, error, created_at, updated_at, finished_at
		 from public.scans where id = $1::uuid and user_id = $2::uuid`, scanID, userID)
	if err := row.Scan(&id, &kind, &inputRef, &status, &outcome, &riskLevel, &report, &errText, &createdAt, &updatedAt, &finishedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	record := map[string]any{
		"id": id, "type": kind, "status": status, "created_at": createdAt, "updated_at": updatedAt,
	}
	if inputRef != nil {
		record["input_ref"] = *inputRef
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

func (p *pgxStore) ListScans(ctx context.Context, userID string, types []string, limit, offset int) ([]any, error) {
	rows, err := p.pool.Query(ctx,
		`select id, type, input_ref, status, outcome, risk_level, created_at, updated_at, finished_at
		 from public.scans
			 where user_id = $1::uuid and ($2::text[] is null or type = any($2))
			 order by created_at desc limit $3 offset $4`, userID, types, limit, offset)
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
	               author_user_id, evidence_public_id,
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
			&row.authorID, &row.evidenceID,
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
		        author_user_id, evidence_public_id,
		        up_count, down_count, score, comment_count, created_at, status
		   from public.community_posts where id = $1::uuid`, postID).
		Scan(&row.id, &row.number, &row.category, &row.title, &row.body, &row.evidence, &row.alias,
			&row.authorID, &row.evidenceID,
			&row.up, &row.down, &row.score, &row.comments, &row.createdAt, &row.state)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return postRecord(row), true, nil
}

// DeleteCommunityPost erases one post for good. Ownership is part of the predicate, not a check in
// front of it, so somebody else's row simply answers "nothing was deleted" instead of "forbidden".
// Votes and comments go with it: both reference this table on delete cascade.
func (p *pgxStore) DeleteCommunityPost(ctx context.Context, postID, userID string) (bool, error) {
	tag, err := p.pool.Exec(ctx,
		`delete from public.community_posts where id = $1::uuid and author_user_id = $2::uuid`, postID, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
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
		id, body, alias, authorID string
		parentID                  *string
		createdAt                 time.Time
	)
	err := p.pool.QueryRow(ctx,
		`select id, post_id, parent_id, body, author_alias, author_user_id, created_at
		   from public.community_comments
		  where id = $1::uuid and post_id = $2::uuid and status = 'active'`, commentID, postID).
		Scan(&id, &postID, &parentID, &body, &alias, &authorID, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return commentRecord(id, postID, parentID, body, alias, authorID, createdAt), true, nil
}

func (p *pgxStore) ListCommunityComments(ctx context.Context, postID string, limit, offset int) ([]map[string]any, error) {
	rows, err := p.pool.Query(ctx,
		`select id, post_id, parent_id, body, author_alias, author_user_id, created_at
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
			id, related, body, alias, authorID string
			parentID                           *string
			createdAt                          time.Time
		)
		if err := rows.Scan(&id, &related, &parentID, &body, &alias, &authorID, &createdAt); err != nil {
			return nil, err
		}
		result = append(result, commentRecord(id, related, parentID, body, alias, authorID, createdAt))
	}
	return result, rows.Err()
}

// DeleteCommunityComment mirrors the REST path: ownership sits inside the predicate, so another
// account's comment simply answers "nothing was deleted".
func (p *pgxStore) DeleteCommunityComment(ctx context.Context, postID, commentID, userID string) (bool, error) {
	tag, err := p.pool.Exec(ctx,
		`delete from public.community_comments
		  where id = $1::uuid and post_id = $2::uuid and author_user_id = $3::uuid`,
		commentID, postID, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
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

func (p *pgxStore) GetUserRole(ctx context.Context, userID string) (string, error) {
	var role string
	err := p.pool.QueryRow(ctx, `select role from public.profiles where id = $1::uuid`, userID).Scan(&role)
	if err != nil {
		return "user", nil
	}
	return role, nil
}

func (p *pgxStore) ListCommunityPostsAdmin(ctx context.Context, filter queueFilter) ([]map[string]any, error) {
	sql := `select id, number_e164, category, title, body, evidence_url, author_alias,
	               author_user_id, evidence_public_id,
	               up_count, down_count, score, comment_count, created_at, status
	          from public.community_posts`
	where, args := filter.where(3, communityPostSearchCols...)
	sql += where + ` order by created_at desc limit $1 offset $2`
	rows, err := p.pool.Query(ctx, sql, append([]any{filter.Limit, filter.Offset}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]any
	for rows.Next() {
		var row postFields
		if err := rows.Scan(&row.id, &row.number, &row.category, &row.title, &row.body, &row.evidence, &row.alias,
			&row.authorID, &row.evidenceID,
			&row.up, &row.down, &row.score, &row.comments, &row.createdAt, &row.state); err != nil {
			return nil, err
		}
		results = append(results, postRecord(row))
	}
	return results, rows.Err()
}

func (p *pgxStore) UpdateCommunityPostStatus(ctx context.Context, postID, status string) (bool, error) {
	tag, err := p.pool.Exec(ctx, `update public.community_posts set status = $2 where id = $1::uuid`, postID, status)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (p *pgxStore) CountCommunityPostsAdmin(ctx context.Context, filter queueFilter) (int, error) {
	return p.count(ctx, "public.community_posts", filter, communityPostSearchCols...)
}

func (p *pgxStore) CountPhoneReportsAdmin(ctx context.Context, filter queueFilter) (int, error) {
	return p.count(ctx, "public.phone_reports", filter, phoneReportSearchCols...)
}

func (p *pgxStore) count(ctx context.Context, table string, filter queueFilter, columns ...string) (int, error) {
	where, args := filter.where(1, columns...)
	var total int
	err := p.pool.QueryRow(ctx, "select count(*) from "+table+where, args...).Scan(&total)
	return total, err
}

func (p *pgxStore) ListPhoneReportsAdmin(ctx context.Context, filter queueFilter) ([]map[string]any, error) {
	sql := `select id, number_e164, category, source, status,
	               coalesce(note, ''), coalesce(evidence_url, ''),
	               coalesce(reported_by::text, ''), created_at
	          from public.phone_reports`
	where, args := filter.where(3, phoneReportSearchCols...)
	sql += where + " order by created_at desc limit $1 offset $2"
	rows, err := p.pool.Query(ctx, sql, append([]any{filter.Limit, filter.Offset}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := []map[string]any{}
	for rows.Next() {
		var row phoneReportFields
		if err := rows.Scan(&row.id, &row.number, &row.category, &row.source, &row.state,
			&row.note, &row.evidence, &row.reporter, &row.createdAt); err != nil {
			return nil, err
		}
		results = append(results, phoneReportRecord(row))
	}
	return results, rows.Err()
}

func (p *pgxStore) GetPhoneReportAdmin(ctx context.Context, reportID string) (map[string]any, bool, error) {
	var row phoneReportFields
	err := p.pool.QueryRow(ctx,
		`select id, number_e164, category, source, status,
		        coalesce(note, ''), coalesce(evidence_url, ''),
		        coalesce(reported_by::text, ''), created_at
		   from public.phone_reports where id = $1::uuid`, reportID).Scan(
		&row.id, &row.number, &row.category, &row.source, &row.state,
		&row.note, &row.evidence, &row.reporter, &row.createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return phoneReportRecord(row), true, nil
}

// DeskStats runs the same database function the PostgREST path calls, but reads its jsonb straight
// out of a single column instead of through an HTTP wrapper.
func (p *pgxStore) DeskStats(ctx context.Context, rng string) (map[string]any, error) {
	var raw []byte
	if err := p.pool.QueryRow(ctx, `select public.admin_desk_stats($1)`, rng).Scan(&raw); err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// phoneReportFields is one scanned phone_reports row; phoneReportRecord gives it the same JSON shape the
// PostgREST path returns, including the reported_by the moderation handler then replaces.
type phoneReportFields struct {
	id, number, category, source, state, note, evidence, reporter string
	createdAt                                                     time.Time
}

func phoneReportRecord(row phoneReportFields) map[string]any {
	return map[string]any{
		"id": row.id, "number_e164": row.number, "category": row.category, "source": row.source,
		"status": row.state, "note": row.note, "evidence_url": row.evidence,
		"reported_by": row.reporter, "created_at": moment(row.createdAt),
	}
}

func moment(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

// postFields is one scanned community_posts row; postRecord gives it the same JSON shape the
// PostgREST path returns, so the handlers never learn which store answered.
type postFields struct {
	id, number, category, title, body, evidence, alias, authorID, evidenceID, state string
	up, down, score, comments                                                       int
	createdAt                                                                       time.Time
}

func postRecord(row postFields) map[string]any {
	return map[string]any{
		"id": row.id, "number_e164": row.number, "category": row.category, "title": row.title,
		"body": row.body, "evidence_url": row.evidence, "author_alias": row.alias,
		"author_user_id": row.authorID, "evidence_public_id": row.evidenceID,
		"up_count": row.up, "down_count": row.down, "score": row.score,
		"comment_count": row.comments, "created_at": moment(row.createdAt), "status": row.state,
	}
}

func commentRecord(id, postID string, parentID *string, body, alias, authorID string, createdAt time.Time) map[string]any {
	record := map[string]any{
		"id": id, "post_id": postID, "body": body, "author_alias": alias,
		"author_user_id": authorID, "created_at": moment(createdAt),
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
