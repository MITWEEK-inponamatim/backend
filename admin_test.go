package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testReportID = "6f1e2d3c-4b5a-4988-8776-5a4b3c2d1e0f"

func adminReportRow(status string) map[string]any {
	return map[string]any{
		"id": testReportID, "number_e164": "+6281234567890", "category": "penipuan",
		"source": "user_report", "status": status, "note": "Minta OTP lewat WhatsApp",
		"evidence_url":       "https://res.cloudinary.com/demo/image/upload/threatlens/phone-reports/x/y.png",
		"evidence_public_id": "threatlens/phone-reports/x/y.png",
		"reported_by":        testUserID,
		"created_at":         "2026-11-08T10:00:00Z",
	}
}

func adminJSON(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode body %q: %v", recorder.Body.String(), err)
	}
	return payload
}

// The gate has to fail closed in both directions: an unverified request never reaches the role
// check at all, and a role the store cannot read is a 500 rather than a granted request.
func TestAdminOnlyGate(t *testing.T) {
	t.Run("no session is a 401", func(t *testing.T) {
		s := communityServer(t, &stubStore{role: "admin"}, "+6281234567890")
		recorder := httptest.NewRecorder()
		s.adminOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Fatal("an unverified request reached the console")
		})).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/community/reports", nil))
		if recorder.Code != http.StatusUnauthorized || adminJSON(t, recorder)["code"] != "unauthenticated" {
			t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
		}
	})

	cases := []struct {
		name        string
		role        string
		roleErr     error
		wantAllowed bool
		wantCode    int
		wantError   string
	}{
		{"admin", "admin", nil, true, 0, ""},
		{"user", "user", nil, false, http.StatusForbidden, "admin_required"},
		{"role unreadable", "", errors.New("column role missing"), false, http.StatusInternalServerError, "internal_error"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store := &stubStore{role: testCase.role, roleErr: testCase.roleErr}
			s := communityServer(t, store, "+6281234567890")
			request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/community/reports", nil), testUserID)
			recorder := httptest.NewRecorder()
			if allowed := s.requireAdmin(recorder, request); allowed != testCase.wantAllowed {
				t.Fatalf("allowed = %v, want %v", allowed, testCase.wantAllowed)
			}
			if testCase.wantError == "" {
				if recorder.Body.Len() != 0 {
					t.Fatalf("a granted request was answered with %s", recorder.Body.String())
				}
				return
			}
			if recorder.Code != testCase.wantCode {
				t.Fatalf("status = %d body = %s, want %d", recorder.Code, recorder.Body.String(), testCase.wantCode)
			}
			if code := adminJSON(t, recorder)["code"]; code != testCase.wantError {
				t.Fatalf("error code = %v, want %s", code, testCase.wantError)
			}
		})
	}
}

// /admin/me answers for everyone, because the navigation needs to know whether to show the door.
func TestAdminRoleAnswersForEveryAccount(t *testing.T) {
	for role, expected := range map[string]string{"admin": "admin", "": "user"} {
		store := &stubStore{role: role}
		s := communityServer(t, store, "+6281234567890")
		recorder := httptest.NewRecorder()
		s.adminRole(recorder, withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/me", nil), testUserID))
		if recorder.Code != http.StatusOK || adminJSON(t, recorder)["role"] != expected {
			t.Fatalf("role %q: status = %d body = %s", role, recorder.Code, recorder.Body.String())
		}
	}
}

func TestListPhoneReportsAdminNeverRevealsTheReporter(t *testing.T) {
	store := &stubStore{reportRows: []map[string]any{adminReportRow("pending")}, reportTotal: 37}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/community/reports?status=pending", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.listPhoneReportsAdmin(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	payload := adminJSON(t, recorder)
	if payload["total"] != float64(37) {
		t.Fatalf("total = %v, want 37", payload["total"])
	}
	body := recorder.Body.String()
	if strings.Contains(body, testUserID) {
		t.Fatalf("reporter account id leaked in %s", body)
	}
	if strings.Contains(body, "evidence_public_id") {
		t.Fatalf("storage public id leaked in %s", body)
	}
	report := payload["reports"].([]any)[0].(map[string]any)
	alias, _ := report["reporter_alias"].(string)
	if !strings.HasPrefix(alias, "Warga-") {
		t.Fatalf("reporter_alias = %q, want an alias", alias)
	}
	if alias != s.communityAlias(testUserID) {
		t.Fatalf("alias %q is not the one the board shows for this account", alias)
	}
}

func TestListPhoneReportsAdminDefaultsToThePendingQueue(t *testing.T) {
	store := &stubStore{}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/community/reports", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.listPhoneReportsAdmin(recorder, request)
	if recorder.Code != http.StatusOK || adminJSON(t, recorder)["status"] != "pending" {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestListPhoneReportsAdminRejectsUnknownStatus(t *testing.T) {
	s := communityServer(t, &stubStore{}, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/community/reports?status=approved", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.listPhoneReportsAdmin(recorder, request)
	if recorder.Code != http.StatusBadRequest || adminJSON(t, recorder)["code"] != "invalid_status" {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

// A decision only means something if the service that owns the trust vocabulary records it.
func TestUpdatePhoneReportStatusAsksTheModerationService(t *testing.T) {
	store := &stubStore{reportRow: adminReportRow("pending"), reportFound: true}
	s, stub := newIndoServer(t, store)
	request := withReportBody(t, withIdentity(httptest.NewRequest(http.MethodPatch,
		"/api/v1/admin/community/reports/"+testReportID+"/status", nil), testUserID), `{"status":"verified"}`)
	request.SetPathValue("reportID", testReportID)
	recorder := httptest.NewRecorder()
	s.updatePhoneReportStatus(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if len(stub.moderations) != 1 || stub.moderations[0]["id"] != testReportID || stub.moderations[0]["status"] != "verified" {
		t.Fatalf("moderation calls = %v", stub.moderations)
	}
}

func TestUpdatePhoneReportStatusSkipsRepeatedDecision(t *testing.T) {
	store := &stubStore{reportRow: adminReportRow("verified"), reportFound: true}
	s, stub := newIndoServer(t, store)
	request := withReportBody(t, withIdentity(httptest.NewRequest(http.MethodPatch,
		"/api/v1/admin/community/reports/"+testReportID+"/status", nil), testUserID), `{"status":"verified"}`)
	request.SetPathValue("reportID", testReportID)
	recorder := httptest.NewRecorder()
	s.updatePhoneReportStatus(recorder, request)

	if recorder.Code != http.StatusOK || adminJSON(t, recorder)["unchanged"] != true {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if len(stub.moderations) != 0 {
		t.Fatalf("an unchanged decision should not reach the service, got %v", stub.moderations)
	}
}

func TestUpdatePhoneReportStatusRejectsUnknownStatus(t *testing.T) {
	store := &stubStore{reportRow: adminReportRow("pending"), reportFound: true}
	s, stub := newIndoServer(t, store)
	request := withReportBody(t, withIdentity(httptest.NewRequest(http.MethodPatch,
		"/api/v1/admin/community/reports/"+testReportID+"/status", nil), testUserID), `{"status":"deleted"}`)
	request.SetPathValue("reportID", testReportID)
	recorder := httptest.NewRecorder()
	s.updatePhoneReportStatus(recorder, request)

	if recorder.Code != http.StatusBadRequest || adminJSON(t, recorder)["code"] != "invalid_status" {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if len(stub.moderations) != 0 {
		t.Fatalf("an invalid status reached the service: %v", stub.moderations)
	}
}

func TestUpdatePhoneReportStatusUnknownReportIsNotFound(t *testing.T) {
	s, stub := newIndoServer(t, &stubStore{})
	request := withReportBody(t, withIdentity(httptest.NewRequest(http.MethodPatch,
		"/api/v1/admin/community/reports/"+testReportID+"/status", nil), testUserID), `{"status":"verified"}`)
	request.SetPathValue("reportID", testReportID)
	recorder := httptest.NewRecorder()
	s.updatePhoneReportStatus(recorder, request)

	if recorder.Code != http.StatusNotFound || adminJSON(t, recorder)["code"] != "report_not_found" {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if len(stub.moderations) != 0 {
		t.Fatalf("a missing report reached the service: %v", stub.moderations)
	}
}

func TestUpdatePhoneReportStatusFailsWhenModerationIsUnreachable(t *testing.T) {
	store := &stubStore{reportRow: adminReportRow("pending"), reportFound: true}
	s, stub := newIndoServer(t, store)
	stub.refuseModeration = true
	request := withReportBody(t, withIdentity(httptest.NewRequest(http.MethodPatch,
		"/api/v1/admin/community/reports/"+testReportID+"/status", nil), testUserID), `{"status":"rejected"}`)
	request.SetPathValue("reportID", testReportID)
	recorder := httptest.NewRecorder()
	s.updatePhoneReportStatus(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable || adminJSON(t, recorder)["code"] != "moderation_unavailable" {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

// The posts queue runs on the same rule: it answers with the number of rows behind the page, so
// the console can say how much work is left instead of guessing from twenty.
func TestListCommunityPostsAdminReportsTotal(t *testing.T) {
	store := &stubStore{adminPostRows: []map[string]any{{"id": testReportID, "status": "active"}}, adminPostTotal: 214}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/community/posts?status=all", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.listCommunityPostsAdmin(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if total := adminJSON(t, recorder)["total"]; total != float64(214) {
		t.Fatalf("total = %v, want 214", total)
	}
}

// The queue reads stories, not identities: the columns the feed also selects must not ride along
// into the moderator's payload.
func TestListCommunityPostsAdminStripsAccountIDAndEvidenceKey(t *testing.T) {
	store := &stubStore{adminPostRows: []map[string]any{{
		"id": testReportID, "status": "active", "author_user_id": testUserID,
		"evidence_public_id": "threatlens/phone-reports/mine/a",
	}}}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/community/posts", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.listCommunityPostsAdmin(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); strings.Contains(body, "author_user_id") || strings.Contains(body, "evidence_public_id") {
		t.Fatalf("private columns reached the moderation desk: %s", body)
	}
}

func withReportBody(t *testing.T, request *http.Request, body string) *http.Request {
	t.Helper()
	replacement := httptest.NewRequest(request.Method, request.URL.Path, strings.NewReader(body))
	replacement.Header.Set("Content-Type", "application/json")
	replacement = replacement.WithContext(request.Context())
	return replacement
}

// The console search box is the only moderator-typed string that reaches the data store, so the
// filter it turns into is worth pinning: a number narrows to that number, a word sweeps the
// queue's own columns, and nothing typed can be read back as filter grammar.
func TestQueueFilterNarrowsWithoutBecomingGrammar(t *testing.T) {
	cases := []struct {
		name    string
		filter  queueFilter
		columns []string
		want    string
	}{
		{"empty queue", queueFilter{Status: "all"}, []string{"note"}, ""},
		{"status bucket", queueFilter{Status: "pending"}, []string{"note"}, "&status=eq.pending"},
		{
			"canonical number",
			queueFilter{Status: "all", Search: "0812345678"},
			[]string{"note"},
			"&number_e164=eq.%2B62812345678",
		},
		{
			"word sweep",
			queueFilter{Status: "verified", Search: "Minta OTP"},
			[]string{"note", "category"},
			"&status=eq.verified&or=(note.ilike.*minta%20otp*,category.ilike.*minta%20otp*)",
		},
		{
			// Parentheses, commas, dots and wildcards are the PostgREST grammar that would let one
			// search value add a filter of its own.
			"punctuation is data",
			queueFilter{Status: "all", Search: `x"),status=eq.rejected,*`},
			[]string{"note"},
			"&or=(note.ilike.*xstatuseqrejected*)",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := testCase.filter.rest(testCase.columns...)
			if got != testCase.want {
				t.Fatalf("rest() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestQueueFilterWhereNumbering(t *testing.T) {
	clause, args := queueFilter{Status: "pending", Search: "minta otp"}.where(3, "note")
	if clause != " where status = $3 and (note ilike $4)" {
		t.Fatalf("clause = %q", clause)
	}
	if len(args) != 2 || args[0] != "pending" || args[1] != "%minta otp%" {
		t.Fatalf("args = %v", args)
	}

	clause, args = queueFilter{Status: "all", Search: "0812345678"}.where(1, "note")
	if clause != " where number_e164 = $1" || len(args) != 1 || args[0] != "+62812345678" {
		t.Fatalf("number filter: clause = %q args = %v", clause, args)
	}

	if clause, args = (queueFilter{Status: "all"}).where(1, "note"); clause != "" || len(args) != 0 {
		t.Fatalf("unfiltered queue: clause = %q args = %v", clause, args)
	}
}

// The filter is only honest if the page and its count are built from the same one, so both queues
// hand the store the whole filter rather than pieces of it.
func TestAdminQueuesPassOneFilterToListAndCount(t *testing.T) {
	store := &stubStore{reportRows: []map[string]any{adminReportRow("verified")}, reportTotal: 4, adminPostRows: []map[string]any{{"id": testReportID}}, adminPostTotal: 9}
	s := communityServer(t, store, "+6281234567890")

	reportRequest := withIdentity(httptest.NewRequest(http.MethodGet,
		"/api/v1/admin/community/reports?status=verified&q=minta%20otp&limit=25&offset=50", nil), testUserID)
	s.listPhoneReportsAdmin(httptest.NewRecorder(), reportRequest)
	if store.reportFilter != (queueFilter{Status: "verified", Search: "minta otp", Limit: 25, Offset: 50}) {
		t.Fatalf("report filter = %+v", store.reportFilter)
	}

	postRequest := withIdentity(httptest.NewRequest(http.MethodGet,
		"/api/v1/admin/community/posts?status=removed&q=kurir&limit=25&offset=0", nil), testUserID)
	s.listCommunityPostsAdmin(httptest.NewRecorder(), postRequest)
	if store.postFilter != (queueFilter{Status: "removed", Search: "kurir", Limit: 25, Offset: 0}) {
		t.Fatalf("post filter = %+v", store.postFilter)
	}
}

// What actually goes on the wire is the point: a search value must arrive as data inside one
// filter parameter, never as a parameter of its own, and the page and its count must be built
// from the same filter.
func TestRestQueueFilterReachesPostgRESTAsData(t *testing.T) {
	var got []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+"?"+r.URL.RawQuery)
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Range", "0-0/1")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(upstream.Close)
	store := &restStore{server: &server{
		cfg:    config{supabaseURL: upstream.URL, secretKey: "unit-test-key"},
		client: upstream.Client(),
	}}
	filter := queueFilter{Status: "pending", Search: `otp status=eq.all,*`, Limit: 20, Offset: 0}
	ctx := context.Background()

	if _, err := store.ListPhoneReportsAdmin(ctx, filter); err != nil {
		t.Fatalf("list: %v", err)
	}
	total, err := store.CountPhoneReportsAdmin(ctx, filter)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("upstream saw %#v", got)
	}

	values, err := url.ParseQuery(strings.TrimPrefix(got[0], "GET?"))
	if err != nil {
		t.Fatalf("parse list query %q: %v", got[0], err)
	}
	if statuses := values["status"]; len(statuses) != 1 || statuses[0] != "eq.pending" {
		t.Fatalf("status parameters = %v, want only the queue's own", statuses)
	}
	if want := "(number_e164.ilike.*otp statuseqall*,note.ilike.*otp statuseqall*,category.ilike.*otp statuseqall*)"; values.Get("or") != want {
		t.Fatalf("or filter = %q, want %q", values.Get("or"), want)
	}
	if len(values) != 6 {
		t.Fatalf("list query grew parameters it should not have: %v", values)
	}
	// The count has to sit behind the same filter as the page, or "12 dari 214" is a guess.
	getFilter := between(got[0], "&status=", "&limit=")
	headFilter := between(got[1], "&status=", "")
	if getFilter != headFilter {
		t.Fatalf("count filter = %q, want the list's %q", headFilter, getFilter)
	}
	if total != 1 {
		t.Fatalf("total = %d, want the 1 the Content-Range reported", total)
	}
}

// between cuts the query fragment from `from` to `to` (or to the end when `to` is empty).
func between(raw, from, to string) string {
	start := strings.Index(raw, from)
	if start < 0 {
		return ""
	}
	rest := raw[start:]
	if to == "" {
		return rest
	}
	end := strings.Index(rest[len(from):], to)
	if end < 0 {
		return rest
	}
	return rest[:len(from)+end]
}

// --------------------------------------------------------------------------- console dashboard

// The dashboard is one call for one range. Everything else — the window comparison, the bucket
// series — is the database's arithmetic, so the handler's job is to name the range, refuse a range
// it does not know, and cut the reporter's account id out of the preview rows the same way the
// report queue does.
func TestDeskStatsPassesTheRangeThrough(t *testing.T) {
	store := &stubStore{statsPayload: map[string]any{
		"range":     "90d",
		"bucket":    "week",
		"dangerous": float64(4),
		"recent":    []any{adminReportRow("pending")},
	}}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/stats/desk?range=90d", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.deskStats(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if store.statsRange != "90d" {
		t.Fatalf("range handed to the store = %q, want 90d", store.statsRange)
	}
	payload := adminJSON(t, recorder)
	if payload["range"] != "90d" || payload["dangerous"] != float64(4) {
		t.Fatalf("payload = %s", recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, testUserID) {
		t.Fatalf("reporter account id leaked in %s", body)
	}
	if strings.Contains(body, "evidence_public_id") {
		t.Fatalf("storage public id leaked in %s", body)
	}
	recent := payload["recent"].([]any)[0].(map[string]any)
	if recent["reporter_alias"] != s.communityAlias(testUserID) {
		t.Fatalf("preview row lost its alias: %v", recent)
	}
}

func TestDeskStatsDefaultsToThirtyDays(t *testing.T) {
	store := &stubStore{statsPayload: map[string]any{"range": "30d"}}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/stats/desk", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.deskStats(recorder, request)
	if recorder.Code != http.StatusOK || store.statsRange != "30d" {
		t.Fatalf("status = %d range = %q body = %s", recorder.Code, store.statsRange, recorder.Body.String())
	}
}

func TestDeskStatsRejectsUnknownRange(t *testing.T) {
	store := &stubStore{statsPayload: map[string]any{"range": "30d"}}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/stats/desk?range=5y", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.deskStats(recorder, request)
	if recorder.Code != http.StatusBadRequest || adminJSON(t, recorder)["code"] != "invalid_range" {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if store.statsRange != "" {
		t.Fatalf("an unknown range still reached the store: %q", store.statsRange)
	}
}

func TestDeskStatsFailsWhenTheAggregateIsUnreadable(t *testing.T) {
	store := &stubStore{statsErr: errors.New("function admin_desk_stats does not exist")}
	s := communityServer(t, store, "+6281234567890")
	request := withIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/admin/stats/desk?range=7d", nil), testUserID)
	recorder := httptest.NewRecorder()
	s.deskStats(recorder, request)
	if recorder.Code != http.StatusInternalServerError || adminJSON(t, recorder)["code"] != "internal_error" {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

// PostgREST answers a function that returns jsonb with the object itself, not a row set — that is
// the shape the live dashboard arrives in. The array shape is still accepted because a function
// returning a composite comes back that way, and neither an empty array nor an empty body may pass:
// a page of zeros is indistinguishable from a page of nothing once it is drawn.
func TestRestDeskStatsReadsBothRPCShapes(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"bare jsonb object", `{"range":"12m","bucket":"month","dangerous":7}`, false},
		{"one-element row set", `[{"range":"12m","bucket":"month","dangerous":7}]`, false},
		{"empty row set", `[]`, true},
		{"empty body", ``, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Method + " " + r.URL.Path
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body["p_range"] != "12m" {
					t.Errorf("rpc body = %v, want p_range 12m", body)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.body))
			}))
			defer upstream.Close()
			store := &restStore{server: &server{
				cfg:    config{supabaseURL: upstream.URL, secretKey: "unit-test-key"},
				client: upstream.Client(),
			}}
			payload, err := store.DeskStats(context.Background(), "12m")
			if test.wantErr {
				if err == nil {
					t.Fatalf("an RPC that answered %q was accepted as a dashboard", test.body)
				}
				return
			}
			if err != nil {
				t.Fatalf("desk stats: %v", err)
			}
			if got != "POST /rest/v1/rpc/admin_desk_stats" {
				t.Fatalf("upstream saw %q", got)
			}
			if payload["range"] != "12m" || payload["dangerous"] != float64(7) {
				t.Fatalf("payload = %v", payload)
			}
		})
	}
}
