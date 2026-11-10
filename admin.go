package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// adminOnly is the door every console route hangs on: a verified session first, then the role.
func (s *server) adminOnly(next http.Handler) http.Handler {
	return s.authenticated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.requireAdmin(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// requireAdmin answers the request itself when the account may not pass and reports whether the
// caller may continue. A role the store cannot read is a 500, never a granted request.
func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	id := requestIdentity(r)
	role, err := s.db.GetUserRole(r.Context(), id.ID)
	if err != nil {
		writeError(w, 500, "internal_error")
		return false
	}
	if role != "admin" {
		writeError(w, 403, "admin_required")
		return false
	}
	return true
}

// adminRole answers the one question the navigation needs: is this account an admin. It is behind
// `authenticated`, not `adminOnly`, so a non-admin can learn to hide the link instead of meeting
// a 403.
func (s *server) adminRole(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	role, err := s.db.GetUserRole(r.Context(), id.ID)
	if err != nil {
		writeError(w, 500, "internal_error")
		return
	}
	writeJSON(w, 200, map[string]any{"role": role})
}

// listCommunityPostsAdmin returns all posts including removed ones, sorted by created_at desc.
// Query params: ?status=active|removed|all&q=nomor%20atau%20kata&limit=50&offset=0
func (s *server) listCommunityPostsAdmin(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	status := query.Get("status")
	if status == "" {
		status = "all"
	}
	if status != "all" && status != "active" && status != "removed" {
		writeError(w, 400, "invalid_status")
		return
	}
	filter := queueFilter{Status: status, Search: strings.TrimSpace(query.Get("q")), Limit: pageLimit(query), Offset: pageOffset(query)}
	rows, err := s.db.ListCommunityPostsAdmin(r.Context(), filter)
	if err != nil {
		writeError(w, 500, "internal_error")
		return
	}
	// Same rule as the reporter queue: a moderator reads the story and the screenshot, never the
	// account id behind the alias or the Cloudinary key of the evidence.
	for _, row := range rows {
		delete(row, "author_user_id")
		delete(row, "evidence_public_id")
	}
	writeJSON(w, 200, withTotal(map[string]any{"posts": rows, "status": status, "limit": filter.Limit, "offset": filter.Offset},
		func() (int, error) { return s.db.CountCommunityPostsAdmin(r.Context(), filter) }))
}

// updateCommunityPostStatus soft-deletes (status=removed) or restores (status=active) a post.
// Body: {"status": "active"|"removed"}
func (s *server) updateCommunityPostStatus(w http.ResponseWriter, r *http.Request) {
	postID := r.PathValue("postID")
	if len(postID) != 36 {
		writeError(w, 400, "invalid_post_id")
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "invalid_json")
		return
	}
	if body.Status != "active" && body.Status != "removed" {
		writeError(w, 400, "invalid_status")
		return
	}
	exists, err := s.db.UpdateCommunityPostStatus(r.Context(), postID, body.Status)
	if err != nil {
		writeError(w, 500, "internal_error")
		return
	}
	if !exists {
		writeError(w, 404, "post_not_found")
		return
	}
	writeJSON(w, 200, map[string]any{"id": postID, "status": body.Status})
}

// --------------------------------------------------------------------------- phone report queue

// reportStatuses is the moderation vocabulary and mirrors
// analysis-service/app/phone_reports.py::ALLOWED_STATUSES. Only "verified" raises a number's risk.
var reportStatuses = map[string]bool{
	"pending": true, "verified": true, "rejected": true, "rejected_spam": true,
}

// listPhoneReportsAdmin is the queue a moderator works from: reports in every state, newest
// first, with the proof attached and the reporter reduced to the same alias the board shows.
// Query params: ?status=pending|verified|rejected|rejected_spam|all&q=nomor%20atau%20kata&limit=50&offset=0
func (s *server) listPhoneReportsAdmin(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	status := query.Get("status")
	if status == "" {
		status = "pending"
	}
	if status != "all" && !reportStatuses[status] {
		writeError(w, 400, "invalid_status")
		return
	}
	filter := queueFilter{Status: status, Search: strings.TrimSpace(query.Get("q")), Limit: pageLimit(query), Offset: pageOffset(query)}
	rows, err := s.db.ListPhoneReportsAdmin(r.Context(), filter)
	if err != nil {
		writeError(w, 500, "internal_error")
		return
	}
	for i, row := range rows {
		rows[i] = s.redactReporter(row)
	}
	writeJSON(w, 200, withTotal(map[string]any{"reports": rows, "status": status, "limit": filter.Limit, "offset": filter.Offset},
		func() (int, error) { return s.db.CountPhoneReportsAdmin(r.Context(), filter) }))
}

// updatePhoneReportStatus is the moderation decision the trust model was waiting for: it moves one
// report between the four states by asking the analysis service, which owns that vocabulary and
// counts the outcome. A decision on a report that does not exist stays a 404 instead of quietly
// succeeding.
// Body: {"status": "pending"|"verified"|"rejected"|"rejected_spam"}
func (s *server) updatePhoneReportStatus(w http.ResponseWriter, r *http.Request) {
	reportID := r.PathValue("reportID")
	if len(reportID) != 36 {
		writeError(w, 400, "invalid_report_id")
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "invalid_json")
		return
	}
	if !reportStatuses[body.Status] {
		writeError(w, 400, "invalid_status")
		return
	}
	row, found, err := s.db.GetPhoneReportAdmin(r.Context(), reportID)
	if err != nil {
		writeError(w, 500, "internal_error")
		return
	}
	if !found {
		writeError(w, 404, "report_not_found")
		return
	}
	if str(row["status"]) == body.Status {
		writeJSON(w, 200, map[string]any{"id": reportID, "status": body.Status, "unchanged": true})
		return
	}
	if err := s.analysisRequest(r.Context(), http.MethodPatch,
		"/internal/v1/phone-reports/"+reportID, map[string]any{"status": body.Status}, nil); err != nil {
		s.count("moderation_unavailable")
		writeError(w, 503, "moderation_unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"id": reportID, "status": body.Status})
}

// --------------------------------------------------------------------------- console dashboard

// deskRanges are the four windows the dashboard offers, named exactly the way the database function
// spells them: the range string is passed through untouched, so adding a fifth window means adding
// it here and in admin_desk_stats() and nowhere else.
var deskRanges = map[string]bool{"7d": true, "30d": true, "90d": true, "12m": true}

// deskStats answers the whole dashboard in one payload: totals with their comparison window, the
// four time series, the category breakdown, the queue, the number of dangerous numbers, and a
// preview of the newest reports. Every aggregate is computed by Postgres, so the answer cannot be
// quietly shortened by a response cap.
func (s *server) deskStats(w http.ResponseWriter, r *http.Request) {
	rng := strings.TrimSpace(r.URL.Query().Get("range"))
	if rng == "" {
		rng = "30d"
	}
	if !deskRanges[rng] {
		writeError(w, 400, "invalid_range")
		return
	}
	payload, err := s.db.DeskStats(r.Context(), rng)
	if err != nil {
		s.count("desk_stats_unavailable")
		log.Printf("desk stats %s: %v", rng, err)
		writeError(w, 500, "internal_error")
		return
	}
	// The preview rows arrive with the reporter's account id because turning it into an alias is
	// this service's job, not the database's: the same cut the report queue makes before a row
	// leaves here, so no account id reaches the console either way.
	if rows, ok := payload["recent"].([]any); ok {
		for i, item := range rows {
			if row, ok := item.(map[string]any); ok {
				rows[i] = s.redactReporter(row)
			}
		}
	}
	writeJSON(w, 200, payload)
}

// redactReporter replaces the reporter's account id with the alias the public board already uses:
// a moderator decides on the screenshot and the story, never on who filed them.
func (s *server) redactReporter(row map[string]any) map[string]any {
	userID := str(row["reported_by"])
	delete(row, "reported_by")
	delete(row, "evidence_public_id")
	if userID != "" {
		row["reporter_alias"] = s.communityAlias(userID)
	}
	return row
}

// withTotal adds the row count a queue needs to say "12 dari 214". A count that fails is left out
// rather than guessed at: the list itself is still correct, and the UI falls back to paging
// without a total.
func withTotal(payload map[string]any, count func() (int, error)) map[string]any {
	total, err := count()
	if err == nil {
		payload["total"] = total
	}
	return payload
}
