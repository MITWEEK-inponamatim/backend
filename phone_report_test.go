package main

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubStore implements dataStore for handler tests; only the phone-report methods matter here.
type stubStore struct {
	exists            bool
	existsAfterInsert bool
	insertErr         error
	inserts           []map[string]any
	failFirst         bool

	// Community rows the handlers under test read back.
	postInserts     []map[string]any
	postErr         error
	postRows        []map[string]any
	postListErr     error
	postRow         map[string]any
	postFound       bool
	postGetErr      error
	postDeleteCalls []map[string]any
	postDeleted     bool
	postDeleteErr   error
	lastFilter      postFilter
	voteCalls       []map[string]any
	voteRow         map[string]any
	voteFound       bool
	voteErr         error
	votes           map[string]int
	commentRows     []map[string]any
	commentInserts  []map[string]any
	commentErr      error
	commentDeletes  []map[string]any
	commentDeleted  bool
	commentDeleteEr error
	parentRow       map[string]any
	parentFound     bool
	dangerousRows   []map[string]any
	dangerousErr    error

	// History list rows, and the filter the handler passed down.
	scanRows      []any
	listScanTypes []string

	// Admin moderation: the role the gate reads, the rows both queues list, and the filter each
	// queue was asked for.
	role           string
	roleErr        error
	adminPostRows  []map[string]any
	adminPostTotal int
	postFilter     queueFilter
	postStatusSet  []map[string]any
	reportRows     []map[string]any
	reportTotal    int
	reportFilter   queueFilter
	reportRow      map[string]any
	reportFound    bool

	// Dashboard aggregate: the range the handler asked for, and the payload the store returns.
	statsRange   string
	statsPayload map[string]any
	statsErr     error
}

func (f *stubStore) InsertScan(context.Context, map[string]any) error { return nil }
func (f *stubStore) PatchScan(context.Context, string, map[string]any) error {
	return nil
}
func (f *stubStore) GetScan(context.Context, string, string) (map[string]any, bool, error) {
	return nil, false, nil
}
func (f *stubStore) ListScans(_ context.Context, _ string, types []string, _, _ int) ([]any, error) {
	f.listScanTypes = types
	if f.scanRows != nil {
		return f.scanRows, nil
	}
	return []any{}, nil
}
func (f *stubStore) InsertFile(context.Context, map[string]any) error { return nil }

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
	return f.exists || (f.existsAfterInsert && len(f.inserts) > 0), nil
}

func (f *stubStore) GetSession(context.Context, string, string) (*sessionInfo, bool, error) {
	return &sessionInfo{ID: "session"}, true, nil
}
func (f *stubStore) TouchSession(context.Context, string, string, time.Time) error { return nil }
func (f *stubStore) RevokeSessionByID(context.Context, string, string) error       { return nil }
func (f *stubStore) RevokeSessionByToken(context.Context, string, string, string) error {
	return nil
}
func (f *stubStore) SessionExists(context.Context, string) (bool, error)                 { return true, nil }
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

func (f *stubStore) InsertCommunityPost(_ context.Context, row map[string]any) error {
	f.postInserts = append(f.postInserts, row)
	return f.postErr
}

func (f *stubStore) ListCommunityPosts(_ context.Context, filter postFilter) ([]map[string]any, error) {
	f.lastFilter = filter
	return f.postRows, f.postListErr
}

func (f *stubStore) GetCommunityPost(context.Context, string) (map[string]any, bool, error) {
	return f.postRow, f.postFound, f.postGetErr
}

func (f *stubStore) DeleteCommunityPost(_ context.Context, postID, userID string) (bool, error) {
	f.postDeleteCalls = append(f.postDeleteCalls, map[string]any{"post_id": postID, "user_id": userID})
	return f.postDeleted, f.postDeleteErr
}

func (f *stubStore) CastCommunityVote(_ context.Context, postID, _ string, value int) (map[string]any, bool, error) {
	f.voteCalls = append(f.voteCalls, map[string]any{"post_id": postID, "value": value})
	return f.voteRow, f.voteFound, f.voteErr
}

func (f *stubStore) CommunityVotesBy(context.Context, string, []string) (map[string]int, error) {
	if f.votes == nil {
		return map[string]int{}, nil
	}
	return f.votes, nil
}

func (f *stubStore) InsertCommunityComment(_ context.Context, row map[string]any) error {
	f.commentInserts = append(f.commentInserts, row)
	return f.commentErr
}

func (f *stubStore) GetCommunityComment(context.Context, string, string) (map[string]any, bool, error) {
	return f.parentRow, f.parentFound, nil
}

func (f *stubStore) ListCommunityComments(context.Context, string, int, int) ([]map[string]any, error) {
	return f.commentRows, nil
}

func (f *stubStore) DeleteCommunityComment(_ context.Context, postID, commentID, userID string) (bool, error) {
	f.commentDeletes = append(f.commentDeletes,
		map[string]any{"post_id": postID, "comment_id": commentID, "user_id": userID})
	return f.commentDeleted, f.commentDeleteEr
}

func (f *stubStore) DangerousNumbers(context.Context, int, int) ([]map[string]any, error) {
	return f.dangerousRows, f.dangerousErr
}

func (f *stubStore) GetUserRole(context.Context, string) (string, error) {
	if f.roleErr != nil {
		return "", f.roleErr
	}
	if f.role == "" {
		return "user", nil
	}
	return f.role, nil
}

func (f *stubStore) ListCommunityPostsAdmin(_ context.Context, filter queueFilter) ([]map[string]any, error) {
	f.postFilter = filter
	return f.adminPostRows, nil
}

func (f *stubStore) UpdateCommunityPostStatus(_ context.Context, postID, status string) (bool, error) {
	f.postStatusSet = append(f.postStatusSet, map[string]any{"post_id": postID, "status": status})
	return len(f.adminPostRows) > 0, nil
}

func (f *stubStore) ListPhoneReportsAdmin(_ context.Context, filter queueFilter) ([]map[string]any, error) {
	f.reportFilter = filter
	return f.reportRows, nil
}

func (f *stubStore) GetPhoneReportAdmin(context.Context, string) (map[string]any, bool, error) {
	return f.reportRow, f.reportFound, nil
}

func (f *stubStore) CountPhoneReportsAdmin(_ context.Context, filter queueFilter) (int, error) {
	f.reportFilter = filter
	return f.reportTotal, nil
}
func (f *stubStore) DeskStats(_ context.Context, rng string) (map[string]any, error) {
	f.statsRange = rng
	return f.statsPayload, f.statsErr
}

func (f *stubStore) CountCommunityPostsAdmin(_ context.Context, filter queueFilter) (int, error) {
	f.postFilter = filter
	return f.adminPostTotal, nil
}

func (f *stubStore) Kind() string { return "stub" }
func (f *stubStore) Close()       {}

const testUserID = "8b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"

// analysisStub stands in for the Python service: it normalises numbers the same way (only the
// +62 shape decides scope, validity never blocks a report) and it keeps or refuses evidence.
type analysisStub struct {
	normalized       string
	refuse           bool
	refuseModeration bool
	stored           []map[string]any
	destroyed        []string
	moderations      []map[string]string
}

// newReportServer wires the handler under test to both internal endpoints it calls.
func newReportServer(t *testing.T, store *stubStore, stub *analysisStub) *server {
	t.Helper()
	analysis := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/internal/v1/phone/normalize":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"e164":     stub.normalized,
				"valid":    stub.normalized != "" && len(stub.normalized) <= 16,
				"domestic": strings.HasPrefix(stub.normalized, "+62"),
			})
		case r.URL.Path == "/internal/v1/phone-reports/evidence" && r.Method == http.MethodPost:
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if stub.refuse {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			publicID := "threatlens/phone-reports/" + testUserID + "/" + body["reference"].(string) + "-rand"
			body["public_id"] = publicID
			stub.stored = append(stub.stored, body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"url": "https://res.cloudinary.com/demo/image/upload/" + publicID, "public_id": publicID,
			})
		case r.URL.Path == "/internal/v1/phone-reports/evidence" && r.Method == http.MethodDelete:
			var body struct {
				PublicID string `json:"public_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			stub.destroyed = append(stub.destroyed, body.PublicID)
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/internal/v1/phone-reports/"):
			var body struct {
				Status string `json:"status"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			reportID := strings.TrimPrefix(r.URL.Path, "/internal/v1/phone-reports/")
			stub.moderations = append(stub.moderations, map[string]string{"id": reportID, "status": body.Status})
			if stub.refuseModeration {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": reportID, "status": body.Status})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
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

// pngEvidence is a byte sequence http.DetectContentType really recognises, because the handler
// trusts the magic bytes and not the filename.
var pngEvidence = append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x00}, 64)...)

func reportForm(t *testing.T, fields map[string]string, filename string, evidence []byte) *http.Request {
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
	request := httptest.NewRequest(http.MethodPost, "/api/v1/phone-reports", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request.WithContext(context.WithValue(request.Context(), identityKey{},
		identity{ID: testUserID, SessionID: "session"}))
}

func reportFields(number, category string) map[string]string {
	return map[string]string{"number": number, "default_region": "ID", "category": category}
}

// newIndoServer is the ordinary happy path: a +62 number and an analysis service that keeps images.
func newIndoServer(t *testing.T, store *stubStore) (*server, *analysisStub) {
	t.Helper()
	stub := &analysisStub{normalized: "+6281234567890"}
	return newReportServer(t, store, stub), stub
}

func TestCreatePhoneReportStoresPendingE164Row(t *testing.T) {
	store := &stubStore{}
	s, stub := newIndoServer(t, store)
	recorder := httptest.NewRecorder()
	fields := reportFields("0812-3456-7890", "Penipuan")
	fields["note"] = "  Ada OTP  "
	s.createPhoneReport(recorder, reportForm(t, fields, "bukti.png", pngEvidence))

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
	if row["evidence_url"] == nil || row["evidence_public_id"] == nil {
		t.Fatalf("report stored without its evidence: %v", row)
	}
	if len(stub.stored) != 1 || stub.stored[0]["user_id"] != testUserID {
		t.Fatalf("evidence not sent to the analysis service: %v", stub.stored)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil || payload["note_saved"] != true {
		t.Fatalf("unexpected response body: %s", recorder.Body.String())
	}
}

func TestCreatePhoneReportRequiresAnEvidenceImage(t *testing.T) {
	store := &stubStore{}
	s, stub := newIndoServer(t, store)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportForm(t, reportFields("081234567890", "penipuan"), "", nil))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "evidence_required") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.inserts) != 0 || len(stub.stored) != 0 {
		t.Fatalf("a report without evidence was stored: inserts=%v evidence=%v", store.inserts, stub.stored)
	}
}

func TestCreatePhoneReportRejectsInvalidPayloads(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]string
		want   string
	}{
		{"unknown category", reportFields("081234567890", "penipuan_berat"), "invalid_category"},
		{"unknown region", map[string]string{"number": "081234567890", "default_region": "ZZ", "category": "penipuan"}, "invalid_phone"},
		{"letters in number", reportFields("0812bca", "penipuan"), "invalid_phone"},
		{"long note", func() map[string]string {
			fields := reportFields("081234567890", "penipuan")
			fields["note"] = strings.Repeat("a", 281)
			return fields
		}(), "invalid_note"},
	}
	for _, testCase := range cases {
		store := &stubStore{}
		s, stub := newIndoServer(t, store)
		recorder := httptest.NewRecorder()
		s.createPhoneReport(recorder, reportForm(t, testCase.fields, "bukti.png", pngEvidence))
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), testCase.want) {
			t.Fatalf("%s: status = %d, body = %s", testCase.name, recorder.Code, recorder.Body.String())
		}
		if len(store.inserts) != 0 || len(stub.stored) != 0 {
			t.Fatalf("%s: invalid payload was stored", testCase.name)
		}
	}
}

// evidenceTypes pairs the bytes a reporter might upload with the type the handler should read.
var evidenceTypes = []struct {
	name     string
	filename string
	data     []byte
	want     string
}{
	{"png", "tangkapan.png", pngEvidence, "image/png"},
	{"jpeg", "chat.jpg", append([]byte("\xff\xd8\xff\xe0"), bytes.Repeat([]byte{0x00}, 64)...), "image/jpeg"},
	{"webp", "bukti.webp", []byte("RIFF\x00\x00\x00\x00WEBPVP8 "), "image/webp"},
	{"heic", "IMG_0001.HEIC", append([]byte("\x00\x00\x00\x18ftypheic"), bytes.Repeat([]byte{0x00}, 64)...), "image/heic"},
	{"renamed php", "bukti.png", []byte("<?php echo 1; ?>"), ""},
	{"animated gif", "bukti.gif", append([]byte("GIF89a"), bytes.Repeat([]byte{0x00}, 64)...), ""},
	{"empty file", "bukti.png", nil, ""},
}

func TestEvidenceMimeFollowsTheBytesNotTheName(t *testing.T) {
	for _, testCase := range evidenceTypes {
		if got := evidenceMime(testCase.data, "image/png"); got != testCase.want {
			t.Errorf("%s: evidenceMime = %q, want %q", testCase.name, got, testCase.want)
		}
	}
}

func TestCreatePhoneReportRefusesANonImageBody(t *testing.T) {
	store := &stubStore{}
	s, stub := newIndoServer(t, store)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportForm(t, reportFields("081234567890", "penipuan"), "bukti.png", []byte("<?php echo 1; ?>")))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "evidence_unsupported_type") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(stub.stored) != 0 {
		t.Fatal("a non-image reached cloud storage")
	}
}

func TestCreatePhoneReportRefusesAnOversizedImage(t *testing.T) {
	t.Setenv("MAX_EVIDENCE_MB", "1")
	store := &stubStore{}
	s, stub := newIndoServer(t, store)
	recorder := httptest.NewRecorder()
	big := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x00}, (1<<20)+64)...)
	s.createPhoneReport(recorder, reportForm(t, reportFields("081234567890", "penipuan"), "besar.png", big))
	if recorder.Code != http.StatusRequestEntityTooLarge || !strings.Contains(recorder.Body.String(), "evidence_too_large") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(stub.stored) != 0 {
		t.Fatal("an oversized image was forwarded to cloud storage")
	}
}

func TestCreatePhoneReportStoresNothingWhenEvidenceCannotBeKept(t *testing.T) {
	store := &stubStore{}
	stub := &analysisStub{normalized: "+6281234567890", refuse: true}
	s := newReportServer(t, store, stub)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportForm(t, reportFields("081234567890", "penipuan"), "bukti.png", pngEvidence))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "evidence_unavailable") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.inserts) != 0 {
		t.Fatalf("a report without evidence was stored: %v", store.inserts)
	}
}

func TestCreatePhoneReportDropsNothingWhenOnlyTheNoteCannotBeStored(t *testing.T) {
	// A database without the optional note column rejects the first insert; the retry must keep
	// the evidence, because "bukti wajib" is not optional the way the note is.
	store := &stubStore{insertErr: errNoteColumnMissing{}, failFirst: true}
	s, _ := newIndoServer(t, store)
	recorder := httptest.NewRecorder()
	fields := reportFields("081234567890", "penipuan")
	fields["note"] = "ada OTP"
	s.createPhoneReport(recorder, reportForm(t, fields, "bukti.png", pngEvidence))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.inserts) != 2 {
		t.Fatalf("expected a retry, got %d inserts", len(store.inserts))
	}
	if _, ok := store.inserts[1]["note"]; ok {
		t.Fatal("retry must not send the note column")
	}
	if store.inserts[1]["evidence_url"] == nil {
		t.Fatal("retry dropped the mandatory evidence")
	}
	if !strings.Contains(recorder.Body.String(), `"note_saved":false`) {
		t.Fatalf("response must report the unsaved note: %s", recorder.Body.String())
	}
}

func TestCreatePhoneReportCleansUpWhenTheEvidenceColumnsAreMissing(t *testing.T) {
	// The migration has not been applied: every insert fails, so the report must not exist and
	// the image that was already uploaded must not stay behind.
	store := &stubStore{insertErr: errEvidenceColumnMissing{}}
	s, stub := newIndoServer(t, store)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportForm(t, reportFields("081234567890", "penipuan"), "bukti.png", pngEvidence))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(stub.destroyed) != 1 || !strings.HasPrefix(stub.destroyed[0], "threatlens/phone-reports/") {
		t.Fatalf("evidence left behind: %v", stub.destroyed)
	}
}

func TestCreatePhoneReportRejectsUnnormalizableNumber(t *testing.T) {
	store := &stubStore{}
	stub := &analysisStub{}
	s := newReportServer(t, store, stub)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportForm(t, reportFields("081234567890", "penipuan"), "bukti.png", pngEvidence))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_phone") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(stub.stored) != 0 {
		t.Fatal("an unusable number got an evidence image uploaded")
	}
}

func TestCreatePhoneReportRejectsNumberOutsideIndonesia(t *testing.T) {
	store := &stubStore{}
	stub := &analysisStub{normalized: "+12025550123"}
	s := newReportServer(t, store, stub)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportForm(t, reportFields("+1 202 555 0123", "penipuan"), "bukti.png", pngEvidence))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "not_indonesian") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.inserts) != 0 {
		t.Fatal("a non-+62 number was stored in the Indonesian community database")
	}
}

func TestCreatePhoneReportKeepsSixTwoNumberThatIsNotARealSubscriber(t *testing.T) {
	// Posting is not gated on validity: the +62 shape is the scope, and the community judges
	// whether the number is real. Blocking here would also hide numbers people were warned about.
	store := &stubStore{}
	stub := &analysisStub{normalized: "+628123456789012345"}
	s := newReportServer(t, store, stub)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportForm(t, reportFields("08123456789012345", "penipuan"), "bukti.png", pngEvidence))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.inserts) != 1 || store.inserts[0]["number_e164"] != "+628123456789012345" {
		t.Fatalf("unexpected inserts: %v", store.inserts)
	}
}

func TestCreatePhoneReportRefusesDuplicateFromSameUser(t *testing.T) {
	store := &stubStore{exists: true}
	s, stub := newIndoServer(t, store)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportForm(t, reportFields("081234567890", "penipuan"), "bukti.png", pngEvidence))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "duplicate_report") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.inserts) != 0 {
		t.Fatal("duplicate report was stored")
	}
	if len(stub.stored) != 0 {
		t.Fatal("a duplicate got its evidence uploaded first")
	}
}

func TestCreatePhoneReportRemovesTheImageWhenTheDuplicateRaces(t *testing.T) {
	// The unique index rejects a second report from the same user for the same number; the image
	// that was already uploaded has to go with it.
	store := &stubStore{existsAfterInsert: true, insertErr: errDuplicateReport{}}
	s, stub := newIndoServer(t, store)
	recorder := httptest.NewRecorder()
	s.createPhoneReport(recorder, reportForm(t, reportFields("081234567890", "penipuan"), "bukti.png", pngEvidence))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "duplicate_report") {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(stub.destroyed) != 1 {
		t.Fatalf("the losing report left its image in the cloud: %v", stub.destroyed)
	}
}

func TestCreatePhoneReportRateLimitsPerUser(t *testing.T) {
	t.Setenv("PHONE_REPORT_HOURLY_LIMIT", "2")
	store := &stubStore{}
	s, _ := newIndoServer(t, store)
	codes := make([]int, 0, 3)
	for attempt := 0; attempt < 3; attempt++ {
		recorder := httptest.NewRecorder()
		s.createPhoneReport(recorder, reportForm(t, reportFields("081234567890", "penipuan"), "bukti.png", pngEvidence))
		codes = append(codes, recorder.Code)
	}
	if codes[0] != http.StatusAccepted || codes[1] != http.StatusAccepted || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("unexpected status sequence: %v", codes)
	}
}

type errNoteColumnMissing struct{}

func (errNoteColumnMissing) Error() string { return "column phone_reports.note does not exist" }

type errEvidenceColumnMissing struct{}

func (errEvidenceColumnMissing) Error() string {
	return `column "evidence_url" of relation "phone_reports" does not exist`
}

type errDuplicateReport struct{}

func (errDuplicateReport) Error() string {
	return `duplicate key value violates unique constraint "phone_reports_reporter_number_key"`
}
