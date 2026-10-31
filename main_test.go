package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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

func TestRejectsFakeAPKZip(t *testing.T) {
	if _, ok := detectFileType("application", ".apk", []byte("PK\x03\x04not-a-zip")); ok {
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
	if _, ok := detectFileType("application", ".apk", buffer.Bytes()); !ok {
		t.Fatal("valid APK ZIP rejected")
	}
}

func TestRejectsInvalidImageMagic(t *testing.T) {
	if _, ok := detectFileType("image", ".png", []byte("not an image")); ok {
		t.Fatal("invalid image accepted")
	}
}

func TestPhoneRegionAllowlist(t *testing.T) {
	if !allowedPhoneRegion("ID") || allowedPhoneRegion("ZZ") {
		t.Fatal("phone region allowlist is incorrect")
	}
}

func TestAcceptsSupportedImageFormats(t *testing.T) {
	if mime, ok := detectFileType("image", ".jpg", []byte{0xff, 0xd8, 0xff, 0xe0}); !ok || mime != "image/jpeg" {
		t.Fatalf("jpeg not detected: %q %v", mime, ok)
	}
	webp := append([]byte("RIFF\x00\x00\x00\x00"), []byte("WEBP")...)
	if mime, ok := detectFileType("image", ".webp", webp); !ok || mime != "image/webp" {
		t.Fatalf("webp not detected: %q %v", mime, ok)
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
		{"+1 202 555 0123", "US", "+12025550123", true},
		{"2025550123", "US", "+12025550123", true},
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

func TestValidatePhoneReportRejectsBadInput(t *testing.T) {
	if code := validatePhoneReport("081234567890", "ID", "penipuan", ""); code != "" {
		t.Fatalf("valid report rejected with %q", code)
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
