package main

// Komunitas: warga menceritakan pengalamannya tentang satu nomor +62, memberi vote, dan
// berkomentar. Route-nya semuanya berada di belakang s.authenticated seperti sisa API: identitas
// dibutuhkan untuk alias dan untuk satu-vote-per-akun, tapi tidak pernah ikut keluar ke browser.
//
// Post TIDAK menaikkan risiko suatu nomor. Yang dibaca checker tetap phone_reports (laporan);
// komunitas adalah konteksnya. Tab "Nomor berbahaya" karena itu membaca view dangerous_numbers,
// yang ambangnya persis aturan "high" di analysis-service.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// communityCategories mirrors the check constraint in 202611040007 and the labels in
// frontend/src/lib/community.ts; a category nobody agreed on must never reach storage.
var communityCategories = map[string]bool{
	"phishing": true, "penipuan": true, "pharming": true,
	"spam": true, "peniruan_identitas": true,
}

// communityAlias is deterministic per account: the same person keeps the same handle across
// posts and comments, and nothing that identifies them leaves this service. It is a signature,
// not an encryption, so changing PRE_COOKIE_SECRET changes every alias.
func (s *server) communityAlias(userID string) string {
	return "Warga-" + s.sign(userID)[:6]
}

func validateCommunityPost(number, category, title, body string) string {
	if len(number) < 5 || len(number) > 32 || !validPhoneChars(number) {
		return "invalid_phone"
	}
	if !communityCategories[category] {
		return "invalid_category"
	}
	if runes := utf8.RuneCountInString(title); runes < 4 || runes > 120 {
		return "invalid_title"
	}
	if runes := utf8.RuneCountInString(body); runes < 10 || runes > 4000 {
		return "invalid_body"
	}
	return ""
}

// communityNumberKey turns whatever the feed was asked to filter by into the same canonical
// "+62…" string that posts are stored under, so "0812…", "62812…" and "+62 0812…" all find the
// same story. It is local (fallbackE164) on purpose: a filter must not depend on the analysis
// service being reachable.
func communityNumberKey(raw string) (string, bool) {
	e164, ok := fallbackE164(strings.TrimSpace(raw), "ID")
	if !ok || !indonesianE164(e164) || !communityNumberShape(e164) {
		return "", false
	}
	return e164, true
}

// communityNumberShape is the storage rule (^\+62[0-9]{8,20}$). Digit count is not validity: an
// unlikely subscriber is still a legal story to tell, and judging plausibility is the checker's
// and the community's job, not this insert's.
func communityNumberShape(e164 string) bool {
	digits := strings.TrimPrefix(e164, "+62")
	return len(digits) >= 8 && len(digits) <= 20 && validPhoneChars(digits)
}

func (s *server) createCommunityPost(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	limit := int64(envInt("MAX_EVIDENCE_MB", 5)) << 20
	r.Body = http.MaxBytesReader(w, r.Body, limit+(1<<20))
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		writeError(w, 413, "evidence_too_large")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	number := strings.TrimSpace(r.FormValue("number"))
	category := strings.ToLower(strings.TrimSpace(r.FormValue("category")))
	title := strings.TrimSpace(r.FormValue("title"))
	body := strings.TrimSpace(r.FormValue("body"))
	if code := validateCommunityPost(number, category, title, body); code != "" {
		writeError(w, 400, code)
		return
	}
	// Bukti gambar wajib, sama seperti laporan: cerita tanpa bukti adalah rumor, dan itulah
	// yang paling tidak boleh disebar di sini.
	file, header, err := r.FormFile("evidence")
	if err != nil {
		writeError(w, 400, "evidence_required")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		writeError(w, 413, "evidence_too_large")
		return
	}
	mimeType := evidenceMime(data, header.Header.Get("Content-Type"))
	if mimeType == "" {
		writeError(w, 400, "evidence_unsupported_type")
		return
	}
	if !s.allow("community_post:"+id.ID, envInt("COMMUNITY_POST_HOURLY_LIMIT", 6), time.Hour) {
		writeError(w, 429, "rate_limited")
		return
	}
	// Region is fixed: this board only ever talks about Indonesian numbers.
	e164, domestic := s.normalizePhone(r.Context(), number, "ID")
	if e164 == "" {
		writeError(w, 400, "invalid_phone")
		return
	}
	if !domestic || !communityNumberShape(e164) {
		writeError(w, 400, "not_indonesian")
		return
	}
	stored, ok := s.storePhoneEvidence(r.Context(), id.ID, randomID(), mimeType, data)
	if !ok {
		writeError(w, 503, "evidence_unavailable")
		return
	}
	postID := randomID()
	row := map[string]any{
		"id":                 postID,
		"number_e164":        e164,
		"category":           category,
		"title":              title,
		"body":               body,
		"evidence_url":       stored.URL,
		"evidence_public_id": stored.PublicID,
		"author_user_id":     id.ID,
		"author_alias":       s.communityAlias(id.ID),
		"status":             "active",
	}
	if err := s.db.InsertCommunityPost(r.Context(), row); err != nil {
		s.discardPhoneEvidence(r.Context(), stored.PublicID)
		writeError(w, 503, "service_unavailable")
		return
	}
	s.count("community_posts_created")
	// The counters belong to the database, so the response reports only what this request decided;
	// the feed refetches and reads them back.
	writeJSON(w, http.StatusAccepted, map[string]any{
		"id": postID, "number_e164": e164, "category": category, "title": title, "status": "active",
		"author_alias": row["author_alias"],
	})
}

func (s *server) listCommunityPosts(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	query := r.URL.Query()
	sort := strings.ToLower(strings.TrimSpace(query.Get("sort")))
	if sort != "top" {
		sort = "new"
	}
	filter := postFilter{Sort: sort, Limit: pageLimit(query), Offset: pageOffset(query)}
	if category := strings.ToLower(strings.TrimSpace(query.Get("category"))); category != "" {
		if !communityCategories[category] {
			writeError(w, 400, "invalid_category")
			return
		}
		filter.Category = category
	}
	if raw := strings.TrimSpace(query.Get("number")); raw != "" {
		e164, ok := communityNumberKey(raw)
		if !ok {
			writeError(w, 400, "invalid_phone")
			return
		}
		filter.Number = e164
	}
	rows, err := s.db.ListCommunityPosts(r.Context(), filter)
	if err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	s.attachMyVotes(r.Context(), id.ID, rows)
	for _, row := range rows {
		publicPost(row, id.ID)
	}
	writeJSON(w, 200, map[string]any{"posts": rows, "sort": sort, "limit": filter.Limit, "offset": filter.Offset})
}

func (s *server) getCommunityPost(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	post, found, err := s.communityPost(r.Context(), r.PathValue("postID"))
	if err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	if !found {
		writeError(w, 404, "not_found")
		return
	}
	limit := envInt("COMMENT_PAGE_SIZE", 200)
	comments, err := s.db.ListCommunityComments(r.Context(), str(post["id"]), limit, 0)
	if err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	votes, err := s.db.CommunityVotesBy(r.Context(), id.ID, []string{str(post["id"])})
	if err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	post["my_vote"] = votes[str(post["id"])]
	for _, row := range comments {
		publicComment(row, id.ID)
	}
	writeJSON(w, 200, map[string]any{"post": publicPost(post, id.ID), "comments": commentThread(comments)})
}

// deleteCommunityComment erases one of the caller's own comments, or one of their replies, for good.
// Same rule as deleting a story: no restore, no record kept. What the caller should know before they
// click is that the replies under a comment are children of it in the database, so they go too —
// including replies written by other accounts, which is why the board asks first.
func (s *server) deleteCommunityComment(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	postID, commentID := r.PathValue("postID"), r.PathValue("commentID")
	if len(postID) != 36 || len(commentID) != 36 {
		writeError(w, 404, "not_found")
		return
	}
	deleted, err := s.db.DeleteCommunityComment(r.Context(), postID, commentID, id.ID)
	if err != nil {
		s.count("community_comments_delete_failed")
		writeError(w, 503, "service_unavailable")
		return
	}
	if !deleted {
		// Not yours, not in this story, or already gone: all three answer like a missing comment, so
		// this route cannot be walked to find out who wrote what.
		writeError(w, 404, "not_found")
		return
	}
	s.count("community_comments_deleted")
	w.WriteHeader(http.StatusNoContent)
}

// deleteCommunityPost erases one of the caller's own posts for good: the row, its comments and
// votes (the database cascades those), and the screenshot in Cloudinary. No restore and no record
// is kept — the person who wrote something they regret is allowed to make it actually gone, which
// is the only reason this route exists rather than a request to a moderator.
func (s *server) deleteCommunityPost(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	postID := r.PathValue("postID")
	if len(postID) != 36 {
		writeError(w, 404, "not_found")
		return
	}
	// Read first only to learn the evidence's public id: once the row is gone that key is gone too,
	// and the image would stay in Cloudinary forever with nothing pointing at it.
	post, found, err := s.db.GetCommunityPost(r.Context(), postID)
	if err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	if !found {
		writeError(w, 404, "not_found")
		return
	}
	deleted, err := s.db.DeleteCommunityPost(r.Context(), postID, id.ID)
	if err != nil {
		s.count("community_posts_delete_failed")
		writeError(w, 503, "service_unavailable")
		return
	}
	if !deleted {
		// Somebody else's story answers the same way a missing one does, so this route cannot be
		// used to walk ids and find out which posts belong to other accounts.
		writeError(w, 404, "not_found")
		return
	}
	if publicID := str(post["evidence_public_id"]); publicID != "" {
		s.discardPhoneEvidence(r.Context(), publicID)
	}
	s.count("community_posts_deleted")
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) castCommunityVote(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	var input struct {
		Value *int `json:"value"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&input) != nil || input.Value == nil {
		writeError(w, 400, "invalid_request")
		return
	}
	value := *input.Value
	if value != 1 && value != -1 && value != 0 {
		writeError(w, 400, "invalid_vote")
		return
	}
	postID := r.PathValue("postID")
	// Vote boleh dicabut kapan pun (value 0) supaya mengklik tombol yang sama dua kali tidak
	// pernah mengunci seseorang pada pilihan pertamanya.
	if !s.allow("community_vote:"+id.ID+":"+postID, envInt("VOTE_LIMIT_PER_MINUTE", 30), time.Minute) {
		writeError(w, 429, "rate_limited")
		return
	}
	if _, found, err := s.communityPost(r.Context(), postID); err != nil {
		writeError(w, 503, "service_unavailable")
		return
	} else if !found {
		writeError(w, 404, "not_found")
		return
	}
	result, found, err := s.db.CastCommunityVote(r.Context(), postID, id.ID, value)
	if err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	if !found {
		writeError(w, 404, "not_found")
		return
	}
	s.count("community_votes_cast")
	writeJSON(w, 200, result)
}

func (s *server) createCommunityComment(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	var input struct {
		Body     string `json:"body"`
		ParentID string `json:"parent_id"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&input) != nil {
		writeError(w, 400, "invalid_request")
		return
	}
	body := strings.TrimSpace(input.Body)
	if runes := utf8.RuneCountInString(body); runes < 1 || runes > 1000 {
		writeError(w, 400, "invalid_body")
		return
	}
	if !s.allow("community_comment:"+id.ID, envInt("COMMENT_MINUTE_LIMIT", 5), time.Minute) ||
		!s.allow("community_comment_hour:"+id.ID, envInt("COMMENT_HOURLY_LIMIT", 20), time.Hour) {
		writeError(w, 429, "rate_limited")
		return
	}
	postID := r.PathValue("postID")
	post, found, err := s.communityPost(r.Context(), postID)
	if err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	if !found {
		writeError(w, 404, "not_found")
		return
	}
	comment := map[string]any{
		"id":             randomID(),
		"post_id":        str(post["id"]),
		"body":           body,
		"author_user_id": id.ID,
		"author_alias":   s.communityAlias(id.ID),
		"status":         "active",
	}
	if parentID := strings.TrimSpace(input.ParentID); parentID != "" {
		if len(parentID) != 36 {
			writeError(w, 400, "invalid_parent")
			return
		}
		// Dua tingkat saja: balasan harus menempel pada komentar paling atas, dan komentar itu
		// harus hidup di post yang sama — kalau tidak, seseorang bisa menyambung untaian post lain.
		parent, parentFound, err := s.db.GetCommunityComment(r.Context(), str(post["id"]), parentID)
		if err != nil {
			writeError(w, 503, "service_unavailable")
			return
		}
		if !parentFound {
			writeError(w, 404, "not_found")
			return
		}
		if str(parent["parent_id"]) != "" {
			writeError(w, 400, "reply_too_deep")
			return
		}
		comment["parent_id"] = parentID
	}
	if err := s.db.InsertCommunityComment(r.Context(), comment); err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	s.count("community_comments_created")
	// created_at dihitung database, jadi untaian di-refetch: waktu yang dikirim sini cuma tebakan.
	writeJSON(w, http.StatusAccepted, map[string]any{
		"id": comment["id"], "post_id": comment["post_id"], "body": body,
		"author_alias": comment["author_alias"], "is_author": true,
	})
}

func (s *server) listDangerousNumbers(w http.ResponseWriter, r *http.Request) {
	limit, offset := pageLimit(r.URL.Query()), pageOffset(r.URL.Query())
	rows, err := s.db.DangerousNumbers(r.Context(), limit, offset)
	if err != nil {
		// A database that has not run 202611040007 has no view at all; that is the same answer
		// the phone-report handler gives for missing evidence columns.
		writeError(w, 503, "service_unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"numbers": rows, "limit": limit, "offset": offset})
}

// communityPost reads one post and refuses the ones a moderator has already taken down, so every
// handler that writes under a post shares that single rule.
func (s *server) communityPost(ctx context.Context, postID string) (map[string]any, bool, error) {
	if len(postID) != 36 {
		return nil, false, nil
	}
	post, found, err := s.db.GetCommunityPost(ctx, postID)
	if err != nil || !found {
		return post, found, err
	}
	if str(post["status"]) != "active" {
		return nil, false, nil
	}
	return post, true, nil
}

// publicPost trims the two columns a post row carries only for this service's own decisions.
// author_user_id is a stable account id, so the alias is the handle that goes public, and
// evidence_public_id is the Cloudinary key that would let anybody address the asset directly.
// What the feed gets in their place is is_author: one bit that says this story is yours to delete.
func publicPost(row map[string]any, userID string) map[string]any {
	row["is_author"] = userID != "" && str(row["author_user_id"]) == userID
	delete(row, "author_user_id")
	delete(row, "evidence_public_id")
	return row
}

// publicComment trims a comment row the same way publicPost trims a story: the account id stays
// behind, and the reader gets is_author — one bit that says this reply is theirs to erase.
func publicComment(row map[string]any, userID string) map[string]any {
	row["is_author"] = userID != "" && str(row["author_user_id"]) == userID
	delete(row, "author_user_id")
	return row
}

func (s *server) attachMyVotes(ctx context.Context, userID string, rows []map[string]any) {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, str(row["id"]))
	}
	votes, err := s.db.CommunityVotesBy(ctx, userID, ids)
	if err != nil {
		// my_vote only paints two arrows; a feed without it is still the truth about the scores.
		votes = map[string]int{}
	}
	for _, row := range rows {
		row["my_vote"] = votes[str(row["id"])]
	}
}

// commentThread flattens two levels of comments into parents holding their replies. A reply whose
// parent was not in this page is shown at the top rather than dropped: losing a comment silently
// is worse than an untidy thread.
func commentThread(rows []map[string]any) []map[string]any {
	roots := map[string]bool{}
	for _, row := range rows {
		if str(row["parent_id"]) == "" {
			roots[str(row["id"])] = true
		}
	}
	replies := map[string][]map[string]any{}
	threads := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		parent := str(row["parent_id"])
		if parent == "" || !roots[parent] {
			threads = append(threads, row)
			continue
		}
		replies[parent] = append(replies[parent], row)
	}
	for _, row := range threads {
		nested := replies[str(row["id"])]
		if nested == nil {
			nested = []map[string]any{}
		}
		row["replies"] = nested
	}
	return threads
}

func pageLimit(query url.Values) int {
	limit, _ := strconv.Atoi(query.Get("limit"))
	if limit < 1 || limit > 100 {
		return 20
	}
	return limit
}

func pageOffset(query url.Values) int {
	offset, _ := strconv.Atoi(query.Get("offset"))
	if offset < 0 {
		return 0
	}
	return offset
}
