package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubStore implements dataStore for handler tests; only the phone-report methods matter here.
type stubStore struct {
	exists    bool
	insertErr error
	inserts   []map[string]any
	failFirst bool
}

func (f *stubStore) InsertScan(context.Context, map[string]any) error { return nil }
func (f *stubStore) PatchScan(context.Context, string, map[string]any) error {
	return nil
}
func (f *stubStore) GetScan(context.Context, string, string) (map[string]any, bool, error) {
	return nil, false, nil
}
func (f *stubStore) ListScans(context.Context, string, int, int) ([]any, error) { return nil, nil }
func (f *stubStore) InsertFile(context.Context, map[string]any) error          { return nil }

func (f *stubStore) InsertPhoneReport(_ context.Context, row map[string]any) error {
	f.inserts = append(f.inserts, row)
	if f.insertErr == nil {
		return nil
	}
	if f.failFirst && len(f.inserts) > 1 {
		return nil
	}
	return f.insertErr
}

func (f *stubStore) PhoneReportExists(context.Context, string, string) (bool, error) {
	return f.exists, nil
}

func (f *stubStore) GetSession(context.Context, string, string) (*sessionInfo, bool, error) {
	return &sessionInfo{ID: "session"}, true, nil
}
func (f *stubStore) TouchSession(context.Context, string, string, time.Time) error { return nil }
func (f *stubStore) RevokeSessionByID(context.Context, string, string) error       { return nil }
func (f *stubStore) RevokeSessionByToken(context.Context, string, string, string) error {
	return nil
}
func (f *stubStore) SessionExists(context.Context, string) (bool, error)          { return true, nil }
func (f *stubStore) InsertSession(context.Context, string, string, string, string) error { return nil }
func (f *stubStore) InsertPreflight(context.Context, string, time.Time, time.Time, string) error {
	return nil
}
func (f *stubStore) GetPreflight(context.Context, string) (*preflightInfo, bool, error) {
	return nil, false, nil
}
func (f *stubStore) ConsumePreflight(context.Context, string, time.Time) (bool, error) {
	return false, nil
}
func (f *stubStore) InsertAuthEvent(context.Context, string, string, string) error { return nil }
func (f *stubStore) InsertLLMUsage(context.Context, map[string]any) error          { return nil }
func (f *stubStore) Kind() string                                                  { return "stub" }
func (f *stubStore) Close()                                                        {}

const testUserID = "8b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"

// newReportServer wires a handler under test to a fake analysis service that normalises
// numbers the same way the Python service does.
func newReportServer(t *testing.T, store *stubStore, normalized string, valid bool) *server {
	t.Helper()
	analysis := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/phone/normalize" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"e164": normalized, "valid": valid})
	}))
	t.Cleanup(analysis.Close)
	return &server{
		cfg:     config{analysisURL: analysis.URL, serviceKey: "unit-test-key"},
		db:      store,
		client:  &http.Client{Timeout: 5 * time.Second},
		metrics: map[string]int64{},
		limits:  map[string][]time.Time{},
	}
}

func reportRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/phone-reports", strings.NewReader(body))
	return request.WithContext(context.WithValue(request.Context(), identityKey{}, identity{ID: testUserID, SessionID: "session"}))
}

func TestCreatePhoneReportStoresPendingE164Row(t *testing.T) {
	store := &stubStore{}
	s := newReportServer(t, store, "+6281234567890", true)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportRequest(`{"number":"0812-3456-7890","default_region":"ID","category":"Penipuan","note":"  Ada OTP  "}`))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.inserts) != 1 {
		t.Fatalf("expected one stored report, got %d", len(store.inserts))
	}
	row := store.inserts[0]
	if row["number_e164"] != "+6281234567890" || row["category"] != "penipuan" || row["status"] != "pending" || row["source"] != "user_report" {
		t.Fatalf("unexpected row: %v", row)
	}
	if row["reported_by"] != testUserID || row["note"] != "Ada OTP" {
		t.Fatalf("ownership or note not recorded: %v", row)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil || payload["note_saved"] != true {
		t.Fatalf("unexpected response body: %s", recorder.Body.String())
	}
}

func TestCreatePhoneReportRejectsInvalidPayloads(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"unknown category", `{"number":"081234567890","category":"penipuan_berat"}`, "invalid_category"},
		{"unknown region", `{"number":"081234567890","default_region":"ZZ","category":"penipuan"}`, "invalid_phone"},
		{"letters in number", `{"number":"0812bca","category":"penipuan"}`, "invalid_phone"},
		{"long note", `{"number":"081234567890","category":"penipuan","note":"` + strings.Repeat("a", 281) + `"}`, "invalid_note"},
	}
	for _, testCase := range cases {
		store := &stubStore{}
		s := newReportServer(t, store, "+6281234567890", true)
		recorder := httptest.NewRecorder()
		s.createPhoneReport(recorder, reportRequest(testCase.body))
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), testCase.want) {
			t.Fatalf("%s: status = %d, body = %s", testCase.name, recorder.Code, recorder.Body.String())
		}
		if len(store.inserts) != 0 {
			t.Fatalf("%s: invalid payload was stored", testCase.name)
		}
	}
}

func TestCreatePhoneReportRejectsNumberTheServiceCannotValidate(t *testing.T) {
	store := &stubStore{}
	s := newReportServer(t, store, "", false)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportRequest(`{"number":"081234567890","category":"penipuan"}`))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_phone") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestCreatePhoneReportRefusesDuplicateFromSameUser(t *testing.T) {
	store := &stubStore{exists: true}
	s := newReportServer(t, store, "+6281234567890", true)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportRequest(`{"number":"081234567890","category":"penipuan"}`))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "duplicate_report") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.inserts) != 0 {
		t.Fatal("duplicate report was stored")
	}
}

func TestCreatePhoneReportKeepsReportWhenNoteCannotBeStored(t *testing.T) {
	// A database without the optional note column rejects the first insert; the retry must
	// still store the report and say so honestly.
	store := &stubStore{insertErr: errNoteColumnMissing{}, failFirst: true}
	s := newReportServer(t, store, "+6281234567890", true)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportRequest(`{"number":"081234567890","category":"penipuan","note":"ada OTP"}`))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.inserts) != 2 {
		t.Fatalf("expected a retry, got %d inserts", len(store.inserts))
	}
	if _, ok := store.inserts[1]["note"]; ok {
		t.Fatal("retry must not send the note column")
	}
	if !strings.Contains(recorder.Body.String(), `"note_saved":false`) {
		t.Fatalf("response must report the unsaved note: %s", recorder.Body.String())
	}
}

func TestCreatePhoneReportRateLimitsPerUser(t *testing.T) {
	t.Setenv("PHONE_REPORT_HOURLY_LIMIT", "2")
	store := &stubStore{}
	s := newReportServer(t, store, "+6281234567890", true)
	codes := make([]int, 0, 3)
	for attempt := 0; attempt < 3; attempt++ {
		recorder := httptest.NewRecorder()
		s.createPhoneReport(recorder, reportRequest(`{"number":"081234567890","category":"penipuan"}`))
		codes = append(codes, recorder.Code)
	}
	if codes[0] != http.StatusAccepted || codes[1] != http.StatusAccepted || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("unexpected status sequence: %v", codes)
	}
}

type errNoteColumnMissing struct{}

func (errNoteColumnMissing) Error() string { return "column phone_reports.note does not exist" }
