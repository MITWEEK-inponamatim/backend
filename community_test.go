package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// communityServer reuses the analysis stub from the report tests: post creation walks the same
// evidence path, so the only thing a community test has to add is the store's own answers.
func communityServer(t *testing.T, store *stubStore, normalized string) *server {
	t.Helper()
	return newReportServer(t, store, &analysisStub{normalized: normalized})
}

func communityFields(number, category string) map[string]string {
	return map[string]string{
		"number": number, "category": category,
		"title": "Katanya kurir tapi mintanya OTP",
		"body":  "Nomor ini menejam saya jam 11 malam, mengaku dari bank dan meminta kode OTP. Saya tidak beri.",
	}
}

func communityForm(t *testing.T, fields map[string]string, filename string, evidence []byte, userID string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("write field %s: %v", key, err)
		}
	}
	if filename != "" {
		part, err := writer.CreateFormFile("evidence", filename)
		if err != nil {
			t.Fatalf("create evidence part: %v", err)
		}
		if _, err := part.Write(evidence); err != nil {
			t.Fatalf("write evidence: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/community/posts", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return withIdentity(request, userID)
}

func withIdentity(request *http.Request, userID string) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), identityKey{},
		identity{ID: userID, SessionID: "session"}))
}

// withPostID mimics what Go's ServeMux does for an {postID} pattern, so handlers can be called
// directly in tests without a router.
func withPostID(request *http.Request, postID string) *http.Request {
	request.SetPathValue("postID", postID)
	return request
}

func postRequest(t *testing.T, userID, postID, path string, payload map[string]any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	return withPostID(withIdentity(request, userID), postID)
}

var aliasPattern = regexp.MustCompile(`^Warga-[0-9a-f]{6}$`)

const communityPostID = "2f3e4d5c-6b7a-4980-91a2-b3c4d5e6f708"

func TestCreateCommunityPostStoresAliasAndEvidence(t *testing.T) {
	store := &stubStore{}
	s := communityServer(t, store, "+6281234567890")
	recorder := httptest.NewRecorder()
	s.createCommunityPost(recorder, communityForm(t, communityFields("0812-3456-7890", "PHISHING"), "bukti.png", pngEvidence, testUserID))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.postInserts) != 1 {
		t.Fatalf("expected one stored post, got %d", len(store.postInserts))
	}
	row := store.postInserts[0]
	if row["number_e164"] != "+6281234567890" || row["category"] != "phishing" || row["status"] != "active" {
		t.Fatalf("unexpected row: %v", row)
	}
	if !aliasPattern.MatchString(str(row["author_alias"])) {
		t.Fatalf("alias is not the agreed shape: %v", row["author_alias"])
	}
	if row["author_user_id"] != testUserID {
		t.Fatalf("post not owned by the caller: %v", row["author_user_id"])
	}
	if row["evidence_url"] == nil || row["evidence_public_id"] == nil {
		t.Fatalf("post stored without its evidence: %v", row)
	}
	// The id is minted here so both stores write the same one and the response can name it.
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response body: %s", recorder.Body.String())
	}
	if payload["id"] != row["id"] || payload["author_alias"] != row["author_alias"] {
		t.Fatalf("response does not describe the stored post: %v vs %v", payload, row)
	}
	if strings.Contains(recorder.Body.String(), testUserID) {
		t.Fatalf("user id leaked into the response: %s", recorder.Body.String())
	}
}

func TestCommunityAliasIsStablePerAccountAndOpaqueAcrossAccounts(t *testing.T) {
	s := communityServer(t, &stubStore{}, "+6281234567890")
	first := s.communityAlias(testUserID)
	second := s.communityAlias("1b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d")
	if !aliasPattern.MatchString(first) || first != s.communityAlias(testUserID) {
		t.Fatalf("alias must be stable and shaped, got %q", first)
	}
	if first == second {
		t.Fatalf("two accounts share an alias: %q", first)
	}
}

func TestCreateCommunityPostRejectsInvalidPayloads(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]string
		want   string
	}{
		{"unknown category", communityFields("081234567890", "pinjaman_online"), "invalid_category"},
		{"six categories is not five", map[string]string{"number": "081234567890", "category": "telemarketing", "title": "ABCDEF", "body": strings.Repeat("a", 20)}, "invalid_category"},
		{"letters in number", communityFields("0812bca", "spam"), "invalid_phone"},
		{"short title", func() map[string]string {
			f := communityFields("081234567890", "spam")
			f["title"] = "abc"
			return f
		}(), "invalid_title"},
		{"long title", func() map[string]string {
			f := communityFields("081234567890", "spam")
			f["title"] = strings.Repeat("a", 121)
			return f
		}(), "invalid_title"},
		{"short body", func() map[string]string {
			f := communityFields("081234567890", "spam")
			f["body"] = "cerita"
			return f
		}(), "invalid_body"},
		{"long body", func() map[string]string {
			f := communityFields("081234567890", "spam")
			f["body"] = strings.Repeat("a", 4001)
			return f
		}(), "invalid_body"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store := &stubStore{}
			s := communityServer(t, store, "+6281234567890")
			recorder := httptest.NewRecorder()
			s.createCommunityPost(recorder, communityForm(t, testCase.fields, "bukti.png", pngEvidence, testUserID))
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), testCase.want) {
				t.Fatalf("status = %d, body = %s, want %s", recorder.Code, recorder.Body.String(), testCase.want)
			}
			if len(store.postInserts) != 0 {
				t.Fatalf("a rejected post reached storage: %v", store.postInserts)
			}
		})
	}
}

func TestCreateCommunityPostRequiresEvidenceImage(t *testing.T) {
	store := &stubStore{}
	s := communityServer(t, store, "+6281234567890")
	recorder := httptest.NewRecorder()
	s.createCommunityPost(recorder, communityForm(t, communityFields("081234567890", "penipuan"), "", nil, testUserID))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "evidence_required") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.postInserts) != 0 {
		t.Fatalf("story without proof was stored: %v", store.postInserts)
	}
}

func TestCreateCommunityPostRefusesNonIndonesianNumbers(t *testing.T) {
	store := &stubStore{}
	s := communityServer(t, store, "+1 202 555 0123")
	recorder := httptest.NewRecorder()
	s.createCommunityPost(recorder, communityForm(t, communityFields("+12025550123", "penipuan"), "bukti.png", pngEvidence, testUserID))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "not_indonesian") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.postInserts) != 0 {
		t.Fatalf("a non-+62 story was stored: %v", store.postInserts)
	}
}

// A +62 prefix alone is not enough: the stored shape is +62 followed by 8..20 digits, and the
// analysis service only reports the region. Too short must fail here, not in the database.
func TestCreateCommunityPostRejectsImpossibleNumberShape(t *testing.T) {
	store := &stubStore{}
	s := communityServer(t, store, "+6212")
	recorder := httptest.NewRecorder()
	s.createCommunityPost(recorder, communityForm(t, communityFields("0812", "penipuan"), "bukti.png", pngEvidence, testUserID))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.postInserts) != 0 {
		t.Fatalf("an out-of-shape number was stored: %v", store.postInserts)
	}
}

func TestCreateCommunityPostCleansUpWhenStorageFails(t *testing.T) {
	store := &stubStore{}
	s := newReportServer(t, store, &analysisStub{normalized: "+6281234567890", refuse: true})
	recorder := httptest.NewRecorder()
	s.createCommunityPost(recorder, communityForm(t, communityFields("081234567890", "pharming"), "bukti.png", pngEvidence, testUserID))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "evidence_unavailable") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.postInserts) != 0 {
		t.Fatalf("post stored while its proof was refused: %v", store.postInserts)
	}
}

func TestCreateCommunityPostDestroysEvidenceWhenInsertFails(t *testing.T) {
	store := &stubStore{}
	stub := &analysisStub{normalized: "+6281234567890"}
	s := newReportServer(t, store, stub)
	store.postErr = errors.New("column missing")
	recorder := httptest.NewRecorder()
	s.createCommunityPost(recorder, communityForm(t, communityFields("081234567890", "spam"), "bukti.png", pngEvidence, testUserID))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(stub.destroyed) != 1 {
		t.Fatalf("orphan evidence left in storage: %v", stub.destroyed)
	}
}

func TestCreateCommunityPostRateLimitsPerAccount(t *testing.T) {
	store := &stubStore{}
	s := communityServer(t, store, "+6281234567890")
	var lastCode int
	for range envInt("COMMUNITY_POST_HOURLY_LIMIT", 6) + 1 {
		recorder := httptest.NewRecorder()
		s.createCommunityPost(recorder, communityForm(t, communityFields("081234567890", "spam"), "bukti.png", pngEvidence, testUserID))
		lastCode = recorder.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("the budget after the limit was accepted: status = %d", lastCode)
	}
	if len(store.postInserts) != envInt("COMMUNITY_POST_HOURLY_LIMIT", 6) {
		t.Fatalf("stored posts = %d, want the hourly budget", len(store.postInserts))
	}
}

func TestCommunityNumberKeyCanonicalisesEveryForm(t *testing.T) {
	for _, raw := range []string{"0812-3456-7890", "6281234567890", "+62 812 3456 7890", "62 0812 3456 7890"} {
		e164, ok := communityNumberKey(raw)
		if !ok || e164 != "+6281234567890" {
			t.Fatalf("%q normalised to %q (ok=%v)", raw, e164, ok)
		}
	}
	for _, raw := range []string{"+1 202 555 0123", "abc", "+621"} {
		if _, ok := communityNumberKey(raw); ok {
			t.Fatalf("%q accepted as an Indonesian key", raw)
		}
	}
}

func TestListCommunityPostsPassesSortAndFilters(t *testing.T) {
	store := &stubStore{
		postRows: []map[string]any{
			{"id": "8b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", "title": "Satu", "score": 4},
			{"id": "1b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", "title": "Dua", "score": 9},
		},
		votes: map[string]int{"1b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d": -1},
	}
	s := communityServer(t, store, "+6281234567890")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/community/posts?sort=top&category=spam&number=0812-3456-7890&limit=5&offset=10", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityKey{}, identity{ID: testUserID, SessionID: "session"}))
	recorder := httptest.NewRecorder()
	s.listCommunityPosts(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if store.lastFilter.Sort != "top" || store.lastFilter.Category != "spam" || store.lastFilter.Number != "+6281234567890" {
		t.Fatalf("filter not carried through: %+v", store.lastFilter)
	}
	if store.lastFilter.Limit != 5 || store.lastFilter.Offset != 10 {
		t.Fatalf("paging not carried through: %+v", store.lastFilter)
	}
	var payload struct {
		Posts []map[string]any `json:"posts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response body: %s", recorder.Body.String())
	}
	if payload.Posts[0]["my_vote"] != float64(0) || payload.Posts[1]["my_vote"] != float64(-1) {
		t.Fatalf("my_vote not attached: %v", payload.Posts)
	}
}

func TestListCommunityPostsRejectsUnknownCategory(t *testing.T) {
	s := communityServer(t, &stubStore{}, "+6281234567890")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/community/posts?category=penagih_utang", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityKey{}, identity{ID: testUserID, SessionID: "session"}))
	recorder := httptest.NewRecorder()
	s.listCommunityPosts(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_category") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestCastCommunityVotePassesThroughAndValidates(t *testing.T) {
	store := &stubStore{postFound: true, postRow: map[string]any{"id": communityPostID, "status": "active"}, voteFound: true, voteRow: map[string]any{"up_count": 3, "down_count": 1, "my_vote": 1}}
	s := communityServer(t, store, "+6281234567890")
	votePath := "/api/v1/community/posts/" + communityPostID + "/vote"
	recorder := httptest.NewRecorder()
	s.castCommunityVote(recorder, postRequest(t, testUserID, communityPostID, votePath, map[string]any{"value": 1}))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"up_count":3`) {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.voteCalls) != 1 || store.voteCalls[0]["value"] != 1 || store.voteCalls[0]["post_id"] != communityPostID {
		t.Fatalf("vote not forwarded: %v", store.voteCalls)
	}
	// Casting the same vote twice is the UI's "undo", which the RPC stores as value 0.
	recorder = httptest.NewRecorder()
	s.castCommunityVote(recorder, postRequest(t, testUserID, communityPostID, votePath, map[string]any{"value": 0}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("withdrawing a vote failed: status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	s.castCommunityVote(recorder, postRequest(t, testUserID, communityPostID, votePath, map[string]any{"value": 7}))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_vote") {
		t.Fatalf("bogus vote value: status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestCastCommunityVoteOnRemovedPostIsNotFound(t *testing.T) {
	store := &stubStore{postFound: true, postRow: map[string]any{"id": communityPostID, "status": "removed"}}
	s := communityServer(t, store, "+6281234567890")
	recorder := httptest.NewRecorder()
	s.castCommunityVote(recorder, postRequest(t, testUserID, communityPostID,
		"/api/v1/community/posts/"+communityPostID+"/vote", map[string]any{"value": 1}))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.voteCalls) != 0 {
		t.Fatalf("vote written under a removed post: %v", store.voteCalls)
	}
}

func TestCommentThreadNestsRepliesUnderTheirParent(t *testing.T) {
	rows := []map[string]any{
		{"id": "aaa", "parent_id": ""},
		{"id": "bbb", "parent_id": "aaa"},
		{"id": "ccc", "parent_id": "aaa"},
		{"id": "ddd", "parent_id": ""},
		// A reply whose parent is not on this page must still be readable, not vanish.
		{"id": "eee", "parent_id": "zzz"},
	}
	threads := commentThread(rows)
	if len(threads) != 3 {
		t.Fatalf("threads = %d, want two roots plus one orphan", len(threads))
	}
	if len(threads[0]["replies"].([]map[string]any)) != 2 {
		t.Fatalf("replies not attached to the first root: %v", threads[0])
	}
	if len(threads[1]["replies"].([]map[string]any)) != 0 {
		t.Fatalf("root without replies got one: %v", threads[1])
	}
	if threads[2]["id"] != "eee" {
		t.Fatalf("orphan reply dropped from the page: %v", threads)
	}
}

func TestCreateCommunityCommentStoresAliasAndRejectsDeepReplies(t *testing.T) {
	store := &stubStore{
		postFound:   true,
		postRow:     map[string]any{"id": communityPostID, "status": "active"},
		parentRow:   map[string]any{"id": "1b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", "post_id": communityPostID},
		parentFound: true,
	}
	path := "/api/v1/community/posts/" + communityPostID + "/comments"
	parentID := "1b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	s := communityServer(t, store, "+6281234567890")

	recorder := httptest.NewRecorder()
	s.createCommunityComment(recorder, postRequest(t, testUserID, communityPostID, path, map[string]any{"body": "  Saya juga kena  "}))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	row := store.commentInserts[0]
	if row["body"] != "Saya juga kena" || !aliasPattern.MatchString(str(row["author_alias"])) || row["parent_id"] != nil {
		t.Fatalf("unexpected comment row: %v", row)
	}
	if row["author_user_id"] != testUserID || strings.Contains(recorder.Body.String(), testUserID) {
		t.Fatalf("identity stored wrongly or leaked: %v / %s", row, recorder.Body.String())
	}

	// Replying to a reply is refused before anything is written.
	store.parentRow = map[string]any{"id": parentID, "post_id": communityPostID, "parent_id": "aaa"}
	recorder = httptest.NewRecorder()
	s.createCommunityComment(recorder, postRequest(t, testUserID, communityPostID, path, map[string]any{"body": "balasan", "parent_id": parentID}))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "reply_too_deep") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.commentInserts) != 1 {
		t.Fatalf("a third-level comment was stored: %v", store.commentInserts)
	}

	// A first-level reply, on the other hand, is stored with its parent.
	store.parentRow = map[string]any{"id": parentID, "post_id": communityPostID}
	recorder = httptest.NewRecorder()
	s.createCommunityComment(recorder, postRequest(t, testUserID, communityPostID, path, map[string]any{"body": "balasan", "parent_id": parentID}))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if got := store.commentInserts[1]["parent_id"]; got != parentID {
		t.Fatalf("reply not attached to its parent: %v", got)
	}

	// A parent from another post is not a parent here.
	store.parentFound = false
	recorder = httptest.NewRecorder()
	s.createCommunityComment(recorder, postRequest(t, testUserID, communityPostID, path, map[string]any{"body": "balasan", "parent_id": parentID}))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	s.createCommunityComment(recorder, postRequest(t, testUserID, communityPostID, path, map[string]any{"body": strings.Repeat("a", 1001)}))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_body") {
		t.Fatalf("over-long comment: status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestGetCommunityPostBuildsThreadAndMyVote(t *testing.T) {
	store := &stubStore{
		postFound: true,
		postRow:   map[string]any{"id": communityPostID, "title": "Satu", "status": "active"},
		commentRows: []map[string]any{
			{"id": "aaa", "post_id": communityPostID, "parent_id": ""},
			{"id": "bbb", "post_id": communityPostID, "parent_id": "aaa"},
		},
		votes: map[string]int{communityPostID: 1},
	}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/community/posts/"+communityPostID, nil), testUserID)
	recorder := httptest.NewRecorder()
	// ServeMux fills {postID}; calling the handler directly means setting it the same way.
	s.getCommunityPost(recorder, withPostID(request, communityPostID))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Post     map[string]any   `json:"post"`
		Comments []map[string]any `json:"comments"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("body: %s", recorder.Body.String())
	}
	if payload.Post["my_vote"] != float64(1) {
		t.Fatalf("my_vote missing from detail: %v", payload.Post)
	}
	if len(payload.Comments) != 1 || len(payload.Comments[0]["replies"].([]any)) != 1 {
		t.Fatalf("thread not assembled: %v", payload.Comments)
	}
}

func TestGetCommunityPostNotFoundForUnknownOrMalformedID(t *testing.T) {
	s := communityServer(t, &stubStore{}, "+6281234567890")
	for _, id := range []string{"not-a-uuid", strings.Repeat("a", 36)} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/community/posts/"+id, nil)
		recorder := httptest.NewRecorder()
		s.getCommunityPost(recorder, withPostID(request, id))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("id %q: status = %d", id, recorder.Code)
		}
	}
}

// An author erasing their own story is the one delete allowed here, and it has to take the
// screenshot with it: a row nobody can find but an image still served is a leak waiting for a URL.
func TestDeleteCommunityPostErasesRowAndEvidence(t *testing.T) {
	publicID := "threatlens/phone-reports/" + testUserID + "/evidence-rand"
	stub := &analysisStub{normalized: "+6281234567890"}
	store := &stubStore{
		postFound:   true,
		postRow:     map[string]any{"id": communityPostID, "status": "active", "author_user_id": testUserID, "evidence_public_id": publicID},
		postDeleted: true,
	}
	s := newReportServer(t, store, stub)
	request := withIdentity(httptest.NewRequest(http.MethodDelete, "/api/v1/community/posts/"+communityPostID, nil), testUserID)
	recorder := httptest.NewRecorder()
	s.deleteCommunityPost(recorder, withPostID(request, communityPostID))

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.postDeleteCalls) != 1 || store.postDeleteCalls[0]["user_id"] != testUserID {
		t.Fatalf("delete not asked under the caller's own id: %v", store.postDeleteCalls)
	}
	if len(stub.destroyed) != 1 || stub.destroyed[0] != publicID {
		t.Fatalf("evidence left in storage: %v", stub.destroyed)
	}
}

// Somebody else's story answers exactly like a missing one, and its screenshot stays untouched.
func TestDeleteCommunityPostOfAnotherAccountRevealsNothing(t *testing.T) {
	other := "1b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	stub := &analysisStub{normalized: "+6281234567890"}
	store := &stubStore{
		postFound: true,
		postRow: map[string]any{"id": communityPostID, "status": "active",
			"author_user_id": other, "evidence_public_id": "threatlens/phone-reports/other/evidence"},
	}
	s := newReportServer(t, store, stub)
	request := withIdentity(httptest.NewRequest(http.MethodDelete, "/api/v1/community/posts/"+communityPostID, nil), testUserID)
	recorder := httptest.NewRecorder()
	s.deleteCommunityPost(recorder, withPostID(request, communityPostID))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.postDeleteCalls) != 1 || store.postDeleteCalls[0]["user_id"] != testUserID {
		t.Fatalf("delete not asked under the caller's own id: %v", store.postDeleteCalls)
	}
	if len(stub.destroyed) != 0 {
		t.Fatalf("another account's evidence destroyed: %v", stub.destroyed)
	}
}

func TestDeleteCommunityPostRefusesMalformedIDAndKeepsItsOwnFailuresQuiet(t *testing.T) {
	store := &stubStore{postFound: true, postDeleted: true}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodDelete, "/api/v1/community/posts/not-a-uuid", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.deleteCommunityPost(recorder, withPostID(request, "not-a-uuid"))
	if recorder.Code != http.StatusNotFound || len(store.postDeleteCalls) != 0 {
		t.Fatalf("status = %d, delete calls = %v", recorder.Code, store.postDeleteCalls)
	}

	failing := &stubStore{postFound: true, postRow: map[string]any{"id": communityPostID, "status": "active"}, postDeleteErr: errors.New("connection reset")}
	s2 := communityServer(t, failing, "+6281234567890")
	recorder2 := httptest.NewRecorder()
	s2.deleteCommunityPost(recorder2, withPostID(withIdentity(httptest.NewRequest(http.MethodDelete, "/api/v1/community/posts/"+communityPostID, nil), testUserID), communityPostID))
	if recorder2.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder2.Code, recorder2.Body.String())
	}
}

func TestCommunityFeedNeverCarriesAccountIDOrEvidenceKey(t *testing.T) {
	other := "1b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	store := &stubStore{postRows: []map[string]any{
		{"id": communityPostID, "title": "Punya saya", "author_user_id": testUserID, "evidence_public_id": "threatlens/phone-reports/mine/a"},
		{"id": other, "title": "Punya orang lain", "author_user_id": other, "evidence_public_id": "threatlens/phone-reports/theirs/b"},
	}}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/community/posts", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.listCommunityPosts(recorder, request)

	body := recorder.Body.String()
	if strings.Contains(body, "author_user_id") || strings.Contains(body, "evidence_public_id") {
		t.Fatalf("private columns reached the browser: %s", body)
	}
	var payload struct {
		Posts []map[string]any `json:"posts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("body: %s", recorder.Body.String())
	}
	if payload.Posts[0]["is_author"] != true || payload.Posts[1]["is_author"] != false {
		t.Fatalf("is_author not stamped per row: %v", payload.Posts)
	}
}

// commentRequest mimics the two path values ServeMux fills for
// /api/v1/community/posts/{postID}/comments/{commentID}.
func commentRequest(userID, postID, commentID string) *http.Request {
	request := withIdentity(httptest.NewRequest(http.MethodDelete,
		"/api/v1/community/posts/"+postID+"/comments/"+commentID, nil), userID)
	request.SetPathValue("postID", postID)
	request.SetPathValue("commentID", commentID)
	return request
}

// Erasing your own comment is allowed; erasing somebody else's is not, and both the missing comment
// and the foreign one answer the same way so this route cannot be walked to learn who wrote what.
func TestDeleteCommunityCommentOnlyAnsweredToItsAuthor(t *testing.T) {
	const commentID = "2c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e"

	store := &stubStore{commentDeleted: true}
	s := communityServer(t, store, "+6281234567890")
	recorder := httptest.NewRecorder()
	s.deleteCommunityComment(recorder, commentRequest(testUserID, communityPostID, commentID))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.commentDeletes) != 1 {
		t.Fatalf("delete calls = %v", store.commentDeletes)
	}
	if call := store.commentDeletes[0]; call["post_id"] != communityPostID || call["comment_id"] != commentID || call["user_id"] != testUserID {
		t.Fatalf("delete not scoped to the caller's own comment: %v", call)
	}

	// The store's predicate found no row, because the comment belongs to another account.
	foreign := &stubStore{}
	s2 := communityServer(t, foreign, "+6281234567890")
	recorder2 := httptest.NewRecorder()
	s2.deleteCommunityComment(recorder2, commentRequest(testUserID, communityPostID, commentID))
	if recorder2.Code != http.StatusNotFound || len(foreign.commentDeletes) != 1 {
		t.Fatalf("status = %d, calls = %v", recorder2.Code, foreign.commentDeletes)
	}
}

func TestDeleteCommunityCommentRefusesMalformedIDsAndKeepsItsOwnFailuresQuiet(t *testing.T) {
	const commentID = "2c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e"
	store := &stubStore{commentDeleted: true}
	s := communityServer(t, store, "+6281234567890")
	for _, probe := range []struct{ postID, commentID string }{
		{communityPostID, "not-a-uuid"},
		{communityPostID, strings.Repeat("a", 35)},
		{"not-a-uuid", commentID},
	} {
		recorder := httptest.NewRecorder()
		s.deleteCommunityComment(recorder, commentRequest(testUserID, probe.postID, probe.commentID))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("post %q comment %q: status = %d", probe.postID, probe.commentID, recorder.Code)
		}
	}
	if len(store.commentDeletes) != 0 {
		t.Fatalf("malformed ids reached the store: %v", store.commentDeletes)
	}

	failing := &stubStore{commentDeleteEr: errors.New("connection reset")}
	s2 := communityServer(t, failing, "+6281234567890")
	recorder := httptest.NewRecorder()
	s2.deleteCommunityComment(recorder, commentRequest(testUserID, communityPostID, commentID))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

// Every comment row now carries an account id, which makes the thread the easiest place to leak it.
func TestCommunityThreadNeverCarriesCommentAccountID(t *testing.T) {
	const mine = "2c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e"
	const theirs = "3d3e4f50-6172-4c8d-9e0f-1a2b3c4d5e6f"
	store := &stubStore{
		postFound: true,
		postRow: map[string]any{"id": communityPostID, "title": "Satu", "status": "active",
			"author_user_id": testUserID},
		commentRows: []map[string]any{
			{"id": mine, "post_id": communityPostID, "author_user_id": testUserID},
			{"id": theirs, "post_id": communityPostID, "parent_id": mine, "author_user_id": theirs},
		},
	}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/community/posts/"+communityPostID, nil), testUserID)
	recorder := httptest.NewRecorder()
	s.getCommunityPost(recorder, withPostID(request, communityPostID))

	body := recorder.Body.String()
	if strings.Contains(body, "author_user_id") {
		t.Fatalf("comment account ids reached the browser: %s", body)
	}
	var payload struct {
		Comments []map[string]any `json:"comments"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("body: %s", body)
	}
	if payload.Comments[0]["is_author"] != true {
		t.Fatalf("own comment not offered for deletion: %v", payload.Comments[0])
	}
	replies, _ := payload.Comments[0]["replies"].([]any)
	if len(replies) != 1 {
		t.Fatalf("reply missing: %v", payload.Comments)
	}
	if reply := replies[0].(map[string]any); reply["is_author"] != false {
		t.Fatalf("somebody else's reply marked as mine: %v", reply)
	}
}

func TestListDangerousNumbersReturnsViewRows(t *testing.T) {
	store := &stubStore{dangerousRows: []map[string]any{{"number_e164": "+6281234567890", "verified_reports": 3}}}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/community/dangerous-numbers", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.listDangerousNumbers(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "verified_reports") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestListDangerousNumbersFailsClosedWithoutTheView(t *testing.T) {
	store := &stubStore{dangerousErr: errors.New("relation does not exist")}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/community/dangerous-numbers", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.listDangerousNumbers(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

// A dataStore without the community methods must fail the build, not the first visitor of
// /community.
var _ dataStore = &stubStore{}

func TestCommunityRoutesRequireLogin(t *testing.T) {
	s := &server{cfg: config{}, db: &stubStore{}, client: &http.Client{Timeout: time.Second}, metrics: map[string]int64{}, limits: map[string][]time.Time{}}
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/community/posts", s.authenticated(http.HandlerFunc(s.listCommunityPosts)))
	mux.Handle("POST /api/v1/community/posts", s.authenticated(http.HandlerFunc(s.createCommunityPost)))
	mux.Handle("POST /api/v1/community/posts/{postID}/vote", s.authenticated(http.HandlerFunc(s.castCommunityVote)))
	mux.Handle("DELETE /api/v1/community/posts/{postID}", s.authenticated(http.HandlerFunc(s.deleteCommunityPost)))
	mux.Handle("DELETE /api/v1/community/posts/{postID}/comments/{commentID}",
		s.authenticated(http.HandlerFunc(s.deleteCommunityComment)))
	for _, probe := range []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/community/posts"},
		{http.MethodPost, "/api/v1/community/posts"},
		{http.MethodPost, "/api/v1/community/posts/8b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d/vote"},
		{http.MethodDelete, "/api/v1/community/posts/8b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"},
		{http.MethodDelete, "/api/v1/community/posts/8b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d/comments/2c2d3e4f-5061-4b7c-8d9e-0f1a2b3c4d5e"},
	} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(probe.method, probe.path, nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s served without a session: status = %d", probe.method, probe.path, recorder.Code)
		}
	}
}
