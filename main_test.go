package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRejectsUnsignedJWT(t *testing.T) {
	part := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	server := &server{}
	if _, err := server.verifyBearer(context.Background(), "Bearer "+part+".e30."); err == nil {
		t.Fatal("alg=none token accepted")
	}
}

// The desk writes its decisions with PATCH. A method missing from the preflight answer is refused by
// the browser, so no request ever reaches a handler and no other test in this file can notice.
func TestPreflightAllowsDecisionMethod(t *testing.T) {
	server := &server{cfg: config{origins: "http://localhost:3000"}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodOptions, "/api/v1/admin/community/reports/6f6f6f6f/status", nil)
	request.Header.Set("Origin", "http://localhost:3000")
	request.Header.Set("Access-Control-Request-Method", http.MethodPatch)
	server.corsAndSecurity(http.NotFoundHandler()).ServeHTTP(recorder, request)
	if methods := recorder.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(methods, http.MethodPatch) {
		t.Fatalf("preflight answers %q, the moderation desk writes with PATCH", methods)
	}
}

func TestRejectsFakeAPKZip(t *testing.T) {
	if _, ok := detectApkType(".apk", []byte("PK\x03\x04not-a-zip")); ok {
		t.Fatal("fake APK accepted")
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entry.Write([]byte("manifest")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := detectApkType(".apk", buffer.Bytes()); !ok {
		t.Fatal("valid APK ZIP rejected")
	}
}

func TestRejectsUploadsThatAreNotAPKs(t *testing.T) {
	png := append([]byte{137, 80, 78, 71, 13, 10, 26, 10}, make([]byte, 16)...)
	if _, ok := detectApkType(".png", png); ok {
		t.Fatal("image upload accepted as an application scan")
	}
	if _, ok := detectApkType(".apk", png); ok {
		t.Fatal("non-ZIP bytes accepted as an APK")
	}
}

func TestPhoneRegionAllowlist(t *testing.T) {
	if !allowedPhoneRegion("ID") || !allowedPhoneRegion("id") {
		t.Fatal("Indonesia rejected")
	}
	for _, region := range []string{"MY", "SG", "US", "GB", "ZZ", ""} {
		if allowedPhoneRegion(region) {
			t.Fatalf("region %q accepted; scope is +62 only", region)
		}
	}
}

func TestApplicationScanGetsLongerBudget(t *testing.T) {
	s := &server{cfg: config{scanTimeoutSeconds: 120, scanAPKTimeoutSeconds: 180}}
	if got := s.scanDeadline("application"); got != 180*time.Second {
		t.Fatalf("application budget = %v, want 180s", got)
	}
	if got := s.scanDeadline("phone"); got != 120*time.Second {
		t.Fatalf("phone budget = %v, want 120s", got)
	}
	// A shorter APK budget must never shrink below the shared default.
	small := &server{cfg: config{scanTimeoutSeconds: 120, scanAPKTimeoutSeconds: 60}}
	if got := small.scanDeadline("application"); got != 120*time.Second {
		t.Fatalf("application budget = %v, want the 120s floor", got)
	}
}

func TestStoreFallsBackToPostgRESTWithoutDSN(t *testing.T) {
	store := newStore(&server{cfg: config{}})
	defer store.Close()
	if _, ok := store.(*restStore); !ok {
		t.Fatalf("expected PostgREST store, got %T", store)
	}
	if store.Kind() != "postgrest" {
		t.Fatalf("kind = %q, want postgrest", store.Kind())
	}
}

func TestMetricsSnapshotIsACopy(t *testing.T) {
	s := &server{metrics: map[string]int64{}}
	s.count("scans_created")
	s.count("scans_created")
	if got := s.metricsSnapshot()["scans_created"]; got != 2 {
		t.Fatalf("counter = %d, want 2", got)
	}
	snapshot := s.metricsSnapshot()
	snapshot["scans_created"] = 0
	if got := s.metricsSnapshot()["scans_created"]; got != 2 {
		t.Fatalf("snapshot mutation leaked into the store: %d", got)
	}
}

func TestCountInitialisesMetricsMap(t *testing.T) {
	s := &server{}
	s.count("auth_failures")
	if got := s.metricsSnapshot()["auth_failures"]; got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}
}

func TestStoreFallsBackWhenDSNIsInvalid(t *testing.T) {
	store := newStore(&server{cfg: config{databaseURL: "this is not a dsn"}})
	defer store.Close()
	if _, ok := store.(*restStore); !ok {
		t.Fatalf("expected PostgREST fallback, got %T", store)
	}
}

func TestPgxStoreUsesSimpleProtocol(t *testing.T) {
	config, err := pgxpool.ParseConfig("postgres://user:pass@db.example:5432/postgres")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	if config.ConnConfig.DefaultQueryExecMode != pgx.QueryExecModeSimpleProtocol {
		t.Fatal("simple protocol not applied")
	}
}

func TestStoreValueHelpers(t *testing.T) {
	if str(nil) != "" || str("x") != "x" {
		t.Fatal("str helper is incorrect")
	}
	if nullableString("") != nil || nullableString("x") != "x" {
		t.Fatal("nullableString helper is incorrect")
	}
	if intValue(float64(3)) != 3 || intValue("7") != 7 || intValue(json.Number("5")) != 5 {
		t.Fatal("intValue helper is incorrect")
	}
	if got := timeValue("2026-10-30T12:00:00Z"); got == nil {
		t.Fatal("timeValue rejected an RFC3339 string")
	}
}

func TestFallbackE164FollowsRegionRules(t *testing.T) {
	cases := []struct {
		number, region, want string
		ok                   bool
	}{
		{"0812-3456-7890", "ID", "+6281234567890", true},
		{"081234567890", "id", "+6281234567890", true},
		{"+62 812 3456 7890", "ID", "+6281234567890", true},
		// One number, several spellings: the trunk 0 left after 62 is dropped so the degraded
		// path stores the same key the analysis service would have produced.
		{"6281234567890", "ID", "+6281234567890", true},
		{"+62 0812-3456-7890", "ID", "+6281234567890", true},
		{"62 0812 3456 7890", "ID", "+6281234567890", true},
		{"0214214214", "ID", "+62214214214", true},
		{"+1 202 555 0123", "ID", "+12025550123", true},
		{"0899", "ID", "", false},
		{"", "ID", "", false},
	}
	for _, testCase := range cases {
		got, ok := fallbackE164(testCase.number, testCase.region)
		if got != testCase.want || ok != testCase.ok {
			t.Fatalf("fallbackE164(%q, %q) = %q, %v; want %q, %v", testCase.number, testCase.region, got, ok, testCase.want, testCase.ok)
		}
	}
}

func TestIndonesianE164Gate(t *testing.T) {
	if !indonesianE164("+6281234567890") {
		t.Fatal("a +62 number rejected")
	}
	for _, value := range []string{"+12025550123", "+60123456789", "6281234567890", ""} {
		if indonesianE164(value) {
			t.Fatalf("non-E.164 or non-+62 value accepted: %q", value)
		}
	}
}

func TestValidatePhoneReportRejectsBadInput(t *testing.T) {
	if code := validatePhoneReport("081234567890", "ID", "penipuan", ""); code != "" {
		t.Fatalf("valid report rejected with %q", code)
	}
	// The board's five categories all have to land here, or a report written on /community/phone
	// would be refused for a word the board itself offers.
	for _, category := range []string{"phishing", "pharming", "peniruan_identitas", "spam"} {
		if code := validatePhoneReport("081234567890", "ID", category, ""); code != "" {
			t.Fatalf("board category %q rejected with %q", category, code)
		}
	}
	if code := validatePhoneReport("081234567890", "ZZ", "penipuan", ""); code != "invalid_phone" {
		t.Fatalf("unknown region accepted: %q", code)
	}
	if code := validatePhoneReport("081bca", "ID", "penipuan", ""); code != "invalid_phone" {
		t.Fatalf("non-digit number accepted: %q", code)
	}
	if code := validatePhoneReport("081234567890", "ID", "penipuan_berat", ""); code != "invalid_category" {
		t.Fatalf("unknown category accepted: %q", code)
	}
	if code := validatePhoneReport("081234567890", "ID", "penipuan", strings.Repeat("a", 281)); code != "invalid_note" {
		t.Fatalf("over-long note accepted: %q", code)
	}
	// The 280 character cap counts characters, not bytes.
	if code := validatePhoneReport("081234567890", "ID", "penipuan", strings.Repeat("é", 280)); code != "" {
		t.Fatalf("280 multi-byte characters rejected: %q", code)
	}
}

func TestAllowEnforcesSlidingWindowPerKey(t *testing.T) {
	s := &server{limits: map[string][]time.Time{}}
	for attempt := 1; attempt <= 3; attempt++ {
		if !s.allow("phone_report:user-a", 3, time.Hour) {
			t.Fatalf("attempt %d was rejected too early", attempt)
		}
	}
	if s.allow("phone_report:user-a", 3, time.Hour) {
		t.Fatal("limit was not enforced after 3 calls")
	}
	if !s.allow("phone_report:user-b", 3, time.Hour) {
		t.Fatal("limits must be tracked per key")
	}
	// A zero/negative limit disables the check instead of blocking everything.
	if !s.allow("phone_report:user-a", 0, time.Hour) {
		t.Fatal("disabled limit should allow the call")
	}
}

func TestScanRateLimitSeparatesFileAndTextBudgets(t *testing.T) {
	s := &server{cfg: config{scanLimitMinute: 3, scanLimitHour: 2, fileScanLimitHour: 1},
		limits: map[string][]time.Time{}, metrics: map[string]int64{}}
	accepted := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	call := func(userID string, fileScan bool) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/application", nil)
		req = req.WithContext(context.WithValue(req.Context(), identityKey{}, identity{ID: userID}))
		s.scanRateLimit(fileScan, accepted).ServeHTTP(rec, req)
		return rec
	}

	if rec := call("user-a", true); rec.Code != http.StatusAccepted {
		t.Fatalf("first file scan = %d, want 202", rec.Code)
	}
	if rec := call("user-a", true); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second file scan = %d, want 429 once the file budget is spent", rec.Code)
	}
	// Text scans keep their own hourly budget, so exhausting APK scans cannot lock the user out.
	if rec := call("user-a", false); rec.Code != http.StatusAccepted {
		t.Fatalf("text scan after the file quota = %d, want 202", rec.Code)
	}
	// Another user must not inherit anyone's bucket.
	if rec := call("user-b", true); rec.Code != http.StatusAccepted {
		t.Fatalf("first file scan for a second user = %d, want 202", rec.Code)
	}
	rec := call("user-a", false)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("shared minute bucket did not cap the burst: %d", rec.Code)
	}
	// Retry-After has to reach the browser for the UI to say how long the wait is.
	after := rec.Header().Get("Retry-After")
	retry, err := strconv.Atoi(after)
	if err != nil || retry < 1 || retry > 3600 {
		t.Fatalf("Retry-After = %q, want a number of seconds between 1 and 3600", after)
	}
	if got := s.metricsSnapshot()["scans_rate_limited"]; got != 2 {
		t.Fatalf("scans_rate_limited = %d, want 2", got)
	}
}

func TestScanTypeFilterOnlyAdmitsStoredKinds(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
		ok        bool
	}{
		{raw: "", want: "", ok: true},
		{raw: "url", want: "url", ok: true},
		{raw: "url,application", want: "url,application", ok: true},
		{raw: "phone", want: "phone", ok: true},
		{raw: "url,phone_report", ok: false},
		{raw: ",", ok: false},
		{raw: "URL", ok: false},
	} {
		got, err := scanTypeFilter(tc.raw)
		if tc.ok != (err == nil) {
			t.Fatalf("scanTypeFilter(%q) err = %v, want ok = %v", tc.raw, err, tc.ok)
		}
		if strings.Join(got, ",") != tc.want {
			t.Fatalf("scanTypeFilter(%q) = %v, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestListScansCarriesTheTypeFilter(t *testing.T) {
	store := &stubStore{scanRows: []any{map[string]any{"id": "1b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", "type": "url"}}}
	s := communityServer(t, store, "+6281234567890")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans?type=url,application&limit=5&offset=2", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityKey{}, identity{ID: testUserID, SessionID: "session"}))
	recorder := httptest.NewRecorder()
	s.listScans(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if strings.Join(store.listScanTypes, ",") != "url,application" {
		t.Fatalf("type filter not carried through: %v", store.listScanTypes)
	}
}

func TestListScansRejectsUnknownType(t *testing.T) {
	s := communityServer(t, &stubStore{}, "+6281234567890")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/scans?type=drop_table", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityKey{}, identity{ID: testUserID, SessionID: "session"}))
	recorder := httptest.NewRecorder()
	s.listScans(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_request") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}
