package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	port, supabaseURL, publishableKey, secretKey string
	serviceKey, preCookieSecret, analysisURL     string
	jwtSecret, databaseURL                       string
	turnstileSecret, expectedHost, origins       string
	idleSeconds, absoluteSeconds, maxUploadMB    int
	scanPollSeconds, scanTimeoutSeconds          int
	scanAPKTimeoutSeconds                        int
	scanLimitMinute, scanLimitHour               int
	fileScanLimitHour                            int
}

func loadConfig() config {
	return config{
		port: env("PORT", "8080"), supabaseURL: strings.TrimRight(os.Getenv("SUPABASE_URL"), "/"),
		publishableKey: os.Getenv("SUPABASE_PUBLISHABLE_KEY"), secretKey: os.Getenv("SUPABASE_SECRET_KEY"),
		serviceKey: os.Getenv("SERVICE_API_KEY"), preCookieSecret: os.Getenv("PRE_COOKIE_SECRET"),
		jwtSecret:       os.Getenv("SUPABASE_JWT_SECRET"),
		databaseURL:     os.Getenv("DATABASE_URL"),
		analysisURL:     strings.TrimRight(env("ANALYSIS_URL", "http://localhost:8000"), "/"),
		turnstileSecret: os.Getenv("TURNSTILE_SECRET_KEY"), expectedHost: os.Getenv("TURNSTILE_EXPECTED_HOSTNAME"),
		origins: env("ALLOWED_ORIGINS", "http://localhost:3000"), idleSeconds: envInt("IDLE_TIMEOUT_SECONDS", 3600),
		absoluteSeconds: envInt("ABSOLUTE_SESSION_SECONDS", 86400), maxUploadMB: envInt("MAX_UPLOAD_MB", 50),
		scanPollSeconds: envInt("SCAN_POLL_INTERVAL_SECONDS", 2), scanTimeoutSeconds: envInt("SCAN_TIMEOUT_SECONDS", 120),
		scanAPKTimeoutSeconds: envInt("SCAN_APPLICATION_TIMEOUT_SECONDS", 180),
		scanLimitMinute:       envInt("SCAN_LIMIT_PER_MINUTE", 6),
		scanLimitHour:         envInt("SCAN_LIMIT_PER_HOUR", 40),
		fileScanLimitHour:     envInt("FILE_SCAN_LIMIT_PER_HOUR", 12),
	}
}

type server struct {
	cfg         config
	db          dataStore
	client      *http.Client
	metricsMu   sync.Mutex
	metrics     map[string]int64
	limitsMu    sync.Mutex
	limits      map[string][]time.Time
	activityMu  sync.Mutex
	activity    map[string]time.Time
	jwksMu      sync.Mutex
	jwks        map[string]jwk
	jwksFetched time.Time
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

type identity struct {
	ID, Email, SessionID string
	Token                string
}

type jwtClaims struct {
	Sub       string          `json:"sub"`
	SessionID string          `json:"session_id"`
	Issuer    string          `json:"iss"`
	Audience  json.RawMessage `json:"aud"`
	Expires   int64           `json:"exp"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type supabaseUser struct {
	ID               string         `json:"id"`
	Email            string         `json:"email"`
	EmailConfirmedAt string         `json:"email_confirmed_at"`
	UserMetadata     map[string]any `json:"user_metadata"`
}

type scanReport struct {
	ScanID             string         `json:"scan_id"`
	Type               string         `json:"type"`
	Outcome            string         `json:"outcome"`
	Risk               map[string]any `json:"risk"`
	Findings           []any          `json:"findings"`
	EvidenceSummary    string         `json:"evidence_summary"`
	RecommendedActions []string       `json:"recommended_actions"`
	Limitations        []string       `json:"limitations"`
	Artifacts          map[string]any `json:"artifacts"`
	LLMUsage           map[string]any `json:"llm_usage"`
	Error              any            `json:"error"`
}

func main() {
	loadDotEnv(".env")
	cfg := loadConfig()
	if cfg.supabaseURL == "" || cfg.publishableKey == "" || cfg.secretKey == "" || cfg.serviceKey == "" || cfg.preCookieSecret == "" {
		log.Fatal("required configuration missing: SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, SUPABASE_SECRET_KEY, SERVICE_API_KEY, PRE_COOKIE_SECRET")
	}
	s := &server{cfg: cfg, client: &http.Client{Timeout: 12 * time.Second}, metrics: map[string]int64{}, limits: map[string][]time.Time{}, activity: map[string]time.Time{}}
	s.db = newStore(s)
	defer s.db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.Handle("POST /api/v1/auth/turnstile/verify", s.rateLimit(10, time.Minute, http.HandlerFunc(s.verifyTurnstile)))
	mux.HandleFunc("POST /api/v1/auth/session/finalize", s.finalizeSession)
	mux.Handle("POST /api/v1/auth/session/heartbeat", s.authenticated(http.HandlerFunc(s.heartbeat)))
	mux.Handle("POST /api/v1/auth/logout", s.authenticated(http.HandlerFunc(s.logout)))
	mux.Handle("GET /api/v1/me", s.authenticated(http.HandlerFunc(s.me)))
	mux.Handle("POST /api/v1/scans/url", s.authenticated(s.scanRateLimit(false, http.HandlerFunc(s.createTextScan("url")))))
	mux.Handle("POST /api/v1/scans/phone", s.authenticated(s.scanRateLimit(false, http.HandlerFunc(s.createTextScan("phone")))))
	mux.Handle("POST /api/v1/scans/application", s.authenticated(s.scanRateLimit(true, http.HandlerFunc(s.createFileScan("application")))))
	mux.Handle("GET /api/v1/scans", s.authenticated(http.HandlerFunc(s.listScans)))
	mux.Handle("GET /api/v1/scans/{scanID}", s.authenticated(http.HandlerFunc(s.getScan)))
	mux.Handle("POST /api/v1/phone-reports", s.authenticated(http.HandlerFunc(s.createPhoneReport)))
	mux.Handle("POST /api/v1/community/posts", s.authenticated(http.HandlerFunc(s.createCommunityPost)))
	mux.Handle("GET /api/v1/community/posts", s.authenticated(http.HandlerFunc(s.listCommunityPosts)))
	mux.Handle("GET /api/v1/community/posts/{postID}", s.authenticated(http.HandlerFunc(s.getCommunityPost)))
	mux.Handle("POST /api/v1/community/posts/{postID}/vote", s.authenticated(http.HandlerFunc(s.castCommunityVote)))
	mux.Handle("POST /api/v1/community/posts/{postID}/comments", s.authenticated(http.HandlerFunc(s.createCommunityComment)))
	mux.Handle("GET /api/v1/community/dangerous-numbers", s.authenticated(http.HandlerFunc(s.listDangerousNumbers)))
	mux.Handle("GET /internal/v1/health", s.internalAuthenticated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })))
	mux.Handle("GET /internal/v1/metrics", s.internalAuthenticated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"counters": s.metricsSnapshot(), "data_store": s.db.Kind()})
	})))
	handler := s.corsAndSecurity(mux)
	log.Printf("Go API listening on :%s", cfg.port)
	log.Fatal(http.ListenAndServe(":"+cfg.port, handler))
}

func loadDotEnv(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), "\"'")
		if key != "" && os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	}
}

func (s *server) corsAndSecurity(next http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, origin := range strings.Split(s.cfg.origins, ",") {
		allowed[strings.TrimSpace(origin)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := randomID()
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		if origin := r.Header.Get("Origin"); origin != "" {
			if !allowed[origin] {
				writeError(w, 403, "origin_denied")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Activity, X-Request-ID")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Expose-Headers", "Retry-After, X-Request-ID")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if (r.Method == http.MethodPost) && strings.HasPrefix(r.URL.Path, "/api/v1/") {
			origin := r.Header.Get("Origin")
			if origin != "" && !allowed[origin] {
				writeError(w, 403, "origin_denied")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) rateLimit(max int, window time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allow(clientIP(r), max, window) {
			writeError(w, 429, "rate_limited")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow applies an in-memory sliding window limit for an arbitrary key (client IP or user ID).
// It is deliberately process-local: a single API instance enforces it, and the database unique
// index remains the authoritative duplicate guard when several instances run.
func (s *server) allow(key string, max int, window time.Duration) bool {
	if max < 1 {
		return true
	}
	now := time.Now()
	s.limitsMu.Lock()
	defer s.limitsMu.Unlock()
	recent := s.limits[key][:0]
	for _, seen := range s.limits[key] {
		if now.Sub(seen) < window {
			recent = append(recent, seen)
		}
	}
	if len(recent) >= max {
		s.limits[key] = recent
		return false
	}
	s.limits[key] = append(recent, now)
	return true
}

// scanRateLimit throttles scan creation per authenticated user, keyed by user ID rather than
// IP so a shared NAT cannot starve a household. File scans draw from their own, much smaller
// hourly budget: each one occupies the isolated extraction worker and, once the vision pass is
// enabled, spends a paid model call. Polling routes stay unthrottled on purpose, because
// following a queued scan to its result must never be what runs out of quota.
func (s *server) scanRateLimit(fileScan bool, next http.Handler) http.Handler {
	hourKey, hourMax := "scan_hour:", s.cfg.scanLimitHour
	if fileScan {
		hourKey, hourMax = "scan_file_hour:", s.cfg.fileScanLimitHour
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid := requestIdentity(r).ID
		minuteKey := "scan_min:" + uid
		hourBucket := hourKey + uid
		if !s.allow(minuteKey, s.cfg.scanLimitMinute, time.Minute) {
			s.denyScan(w, minuteKey, time.Minute)
			return
		}
		if !s.allow(hourBucket, hourMax, time.Hour) {
			s.denyScan(w, hourBucket, time.Hour)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) denyScan(w http.ResponseWriter, key string, window time.Duration) {
	s.count("scans_rate_limited")
	w.Header().Set("Retry-After", strconv.Itoa(s.retryAfterSeconds(key, window)))
	writeError(w, http.StatusTooManyRequests, "rate_limited")
}

// retryAfterSeconds reports how long until the oldest request inside the window ages out of it.
func (s *server) retryAfterSeconds(key string, window time.Duration) int {
	now := time.Now()
	s.limitsMu.Lock()
	defer s.limitsMu.Unlock()
	var oldest time.Time
	for _, seen := range s.limits[key] {
		if now.Sub(seen) < window && (oldest.IsZero() || seen.Before(oldest)) {
			oldest = seen
		}
	}
	if oldest.IsZero() {
		return 1
	}
	if seconds := int((window - now.Sub(oldest)) / time.Second); seconds > 0 {
		return seconds + 1
	}
	return 1
}

type identityKey struct{}

func (s *server) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.verifyBearer(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			s.count("auth_failures")
			writeError(w, 401, "unauthenticated")
			return
		}
		if err := s.requireActiveSession(r.Context(), id); err != nil {
			var expired *sessionExpired
			if errors.As(err, &expired) {
				writeError(w, 401, expired.code)
			} else {
				writeError(w, 403, "session_required")
			}
			return
		}
		if r.Header.Get("X-Activity") != "passive" {
			s.touchSession(r.Context(), id)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	})
}

func (s *server) internalAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.serviceKey == "" || !hmac.Equal([]byte(r.Header.Get("X-Service-Key")), []byte(s.cfg.serviceKey)) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type sessionExpired struct{ code string }

func (e *sessionExpired) Error() string { return e.code }

func (s *server) verifyBearer(ctx context.Context, authorization string) (identity, error) {
	if !strings.HasPrefix(authorization, "Bearer ") {
		return identity{}, errors.New("missing bearer")
	}
	token := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return identity{}, errors.New("malformed token")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil || json.Unmarshal(headerBytes, &header) != nil || (header.Alg != "RS256" && header.Alg != "ES256" && header.Alg != "HS256") || (header.Alg != "HS256" && header.Kid == "") {
		return identity{}, errors.New("invalid JWT header")
	}
	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return identity{}, err
	}
	var claims jwtClaims
	if json.Unmarshal(payload, &claims) != nil || claims.Sub == "" || claims.SessionID == "" || claims.Expires <= time.Now().Unix() || claims.Issuer != s.cfg.supabaseURL+"/auth/v1" || !audienceAuthenticated(claims.Audience) {
		return identity{}, errors.New("invalid claims")
	}
	if header.Alg == "HS256" {
		if s.cfg.jwtSecret == "" {
			return identity{}, errors.New("legacy JWT secret missing")
		}
		signature, err := decodeBase64URL(parts[2])
		if err != nil {
			return identity{}, err
		}
		mac := hmac.New(sha256.New, []byte(s.cfg.jwtSecret))
		_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
		if !hmac.Equal(signature, mac.Sum(nil)) {
			return identity{}, errors.New("invalid JWT signature")
		}
	} else {
		if err := s.verifyJWTSignature(ctx, header.Alg, header.Kid, parts[0]+"."+parts[1], parts[2]); err != nil {
			return identity{}, err
		}
	}
	var user supabaseUser
	if err := s.supabase(ctx, http.MethodGet, "/auth/v1/user", nil, token, &user); err != nil {
		return identity{}, err
	}
	if user.ID != claims.Sub || user.EmailConfirmedAt == "" {
		return identity{}, errors.New("unverified account")
	}
	return identity{ID: user.ID, Email: user.Email, SessionID: claims.SessionID, Token: token}, nil
}

func decodeJWTPart(part string) ([]byte, error) {
	return decodeBase64URL(part)
}

func decodeBase64URL(part string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(part)
}

func (s *server) verifyJWTSignature(ctx context.Context, alg, kid, signingInput, encodedSignature string) error {
	key, err := s.getJWK(ctx, kid)
	if err != nil {
		return err
	}
	if key.Alg != "" && key.Alg != alg {
		return errors.New("JWT algorithm mismatch")
	}
	signature, err := decodeBase64URL(encodedSignature)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(signingInput))
	switch alg {
	case "RS256":
		if key.Kty != "RSA" {
			return errors.New("invalid RSA key")
		}
		modulus, err := decodeBase64URL(key.N)
		if err != nil {
			return err
		}
		exponent, err := decodeBase64URL(key.E)
		if err != nil {
			return err
		}
		e := 0
		for _, b := range exponent {
			e = (e << 8) | int(b)
		}
		if e < 3 {
			return errors.New("invalid RSA exponent")
		}
		return rsa.VerifyPKCS1v15(&rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}, crypto.SHA256, digest[:], signature)
	case "ES256":
		if key.Kty != "EC" || len(signature) != 64 {
			return errors.New("invalid EC key")
		}
		x, err := decodeBase64URL(key.X)
		if err != nil {
			return err
		}
		y, err := decodeBase64URL(key.Y)
		if err != nil {
			return err
		}
		public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
			return errors.New("invalid JWT signature")
		}
		return nil
	default:
		return errors.New("unsupported JWT algorithm")
	}
}

func (s *server) getJWK(ctx context.Context, kid string) (jwk, error) {
	s.jwksMu.Lock()
	defer s.jwksMu.Unlock()
	if time.Since(s.jwksFetched) > 5*time.Minute || s.jwks[kid].Kid == "" {
		var payload struct {
			Keys []jwk `json:"keys"`
		}
		if err := s.supabase(ctx, http.MethodGet, "/auth/v1/.well-known/jwks.json", nil, "", &payload); err != nil {
			return jwk{}, err
		}
		keys := make(map[string]jwk, len(payload.Keys))
		for _, key := range payload.Keys {
			if key.Kid != "" {
				keys[key.Kid] = key
			}
		}
		s.jwks, s.jwksFetched = keys, time.Now()
	}
	key := s.jwks[kid]
	if key.Kid == "" {
		return jwk{}, errors.New("JWT signing key not found")
	}
	return key, nil
}

func audienceAuthenticated(raw json.RawMessage) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == "authenticated"
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, v := range many {
			if v == "authenticated" {
				return true
			}
		}
	}
	return false
}

func (s *server) count(name string) {
	s.metricsMu.Lock()
	if s.metrics == nil {
		s.metrics = map[string]int64{}
	}
	s.metrics[name]++
	s.metricsMu.Unlock()
}

func (s *server) metricsSnapshot() map[string]int64 {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	snapshot := make(map[string]int64, len(s.metrics))
	for key, value := range s.metrics {
		snapshot[key] = value
	}
	return snapshot
}

func (s *server) requireActiveSession(ctx context.Context, id identity) error {
	row, found, err := s.db.GetSession(ctx, id.ID, id.SessionID)
	if err != nil || !found {
		return errors.New("session missing")
	}
	if row.RevokedAt != nil {
		return errors.New("session revoked")
	}
	now := time.Now()
	if now.Sub(row.CreatedAt) > time.Duration(s.cfg.absoluteSeconds)*time.Second {
		s.revokeSession(ctx, row.ID, "absolute")
		return &sessionExpired{code: "session_expired_absolute"}
	}
	if now.Sub(row.LastActivityAt) > time.Duration(s.cfg.idleSeconds)*time.Second {
		s.revokeSession(ctx, row.ID, "idle")
		s.authEvent(ctx, id.ID, "idle_logout", "")
		return &sessionExpired{code: "session_expired_idle"}
	}
	return nil
}

func (s *server) touchSession(ctx context.Context, id identity) {
	key := id.ID + ":" + id.SessionID
	now := time.Now()
	s.activityMu.Lock()
	if now.Sub(s.activity[key]) < time.Minute {
		s.activityMu.Unlock()
		return
	}
	s.activity[key] = now
	s.activityMu.Unlock()
	_ = s.db.TouchSession(ctx, id.ID, id.SessionID, now)
}

func (s *server) revokeSession(ctx context.Context, sessionID, reason string) {
	_ = s.db.RevokeSessionByID(ctx, sessionID, reason)
}

func (s *server) verifyTurnstile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body) != nil || body.Token == "" {
		writeError(w, 400, "invalid_request")
		return
	}
	if s.cfg.turnstileSecret == "" {
		writeError(w, 503, "captcha_unavailable")
		return
	}
	ip := clientIP(r)
	form := url.Values{"secret": {s.cfg.turnstileSecret}, "response": {body.Token}, "remoteip": {ip}, "idempotency_key": {randomID()}}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var result struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
		Action   string `json:"action"`
	}
	resp, err := s.client.Do(req)
	if err != nil {
		writeError(w, 502, "captcha_unavailable")
		return
	}
	defer resp.Body.Close()
	if json.NewDecoder(io.LimitReader(resp.Body, 32<<10)).Decode(&result) != nil || !result.Success || result.Action != "login" || (s.cfg.expectedHost != "" && result.Hostname != s.cfg.expectedHost) {
		s.authEvent(r.Context(), "", "turnstile_fail", ip)
		writeError(w, 403, "captcha_failed")
		return
	}
	nonce := randomID()
	now := time.Now().UTC()
	if err := s.db.InsertPreflight(r.Context(), nonce, now, now.Add(10*time.Minute), ip); err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	value := nonce + "." + s.sign(nonce)
	http.SetCookie(w, &http.Cookie{Name: "tl_pre", Value: value, Path: "/", HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) finalizeSession(w http.ResponseWriter, r *http.Request) {
	id, err := s.verifyBearer(r.Context(), r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, 401, "unauthenticated")
		return
	}
	if !s.validOrigin(r) {
		writeError(w, 403, "origin_denied")
		return
	}
	cookie, err := r.Cookie("tl_pre")
	if err != nil {
		writeError(w, 403, "session_required")
		return
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(s.sign(parts[0]))) {
		writeError(w, 403, "session_required")
		return
	}
	preflight, found, err := s.db.GetPreflight(r.Context(), parts[0])
	if err != nil || !found || preflight.UsedAt != nil || time.Now().After(preflight.ExpiresAt) {
		writeError(w, 403, "session_required")
		return
	}
	used := time.Now().UTC()
	if consumed, err := s.db.ConsumePreflight(r.Context(), parts[0], used); err != nil || !consumed {
		writeError(w, 403, "session_required")
		return
	}
	active, err := s.db.SessionExists(r.Context(), id.SessionID)
	if err != nil {
		active = true
	}
	if !active {
		if err := s.db.InsertSession(r.Context(), id.ID, id.SessionID, clientIP(r), r.UserAgent()); err != nil {
			writeError(w, 503, "service_unavailable")
			return
		}
	}
	s.authEvent(r.Context(), id.ID, "login", clientIP(r))
	http.SetCookie(w, &http.Cookie{Name: "tl_pre", Value: "", Path: "/", HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) heartbeat(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	_ = s.db.RevokeSessionByToken(r.Context(), id.ID, id.SessionID, "logout")
	s.authEvent(r.Context(), id.ID, "logout", clientIP(r))
	_ = s.supabase(r.Context(), http.MethodPost, "/auth/v1/logout?scope=global", nil, id.Token, nil)
	http.SetCookie(w, &http.Cookie{Name: "tl_pre", Value: "", Path: "/", HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	writeJSON(w, 200, map[string]string{"id": id.ID, "email": id.Email})
}

func (s *server) createTextScan(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := requestIdentity(r)
		var input map[string]any
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&input) != nil {
			writeError(w, 400, "invalid_request")
			return
		}
		field := "url"
		if kind == "phone" {
			field = "number"
		}
		value, _ := input[field].(string)
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 20000 {
			writeError(w, 400, "invalid_input")
			return
		}
		if kind == "url" {
			u, err := url.ParseRequestURI(value)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || len(value) > 2048 {
				writeError(w, 400, "invalid_url")
				return
			}
		}
		if kind == "phone" {
			number, _ := input["number"].(string)
			region, _ := input["default_region"].(string)
			if len(number) < 5 || len(number) > 32 || !allowedPhoneRegion(region) || !validPhoneChars(number) {
				writeError(w, 400, "invalid_phone")
				return
			}
			input = map[string]any{"number": number, "default_region": strings.ToUpper(region)}
			value = number
		}
		scanID := randomID()
		scan := map[string]any{"id": scanID, "user_id": id.ID, "type": kind, "input_ref": value, "status": "queued"}
		if err := s.db.InsertScan(r.Context(), scan); err != nil {
			writeError(w, 503, "service_unavailable")
			return
		}
		payload := map[string]any{field: value}
		if kind == "phone" {
			payload = input
		}
		go s.processScan(scanID, id.ID, kind, payload, map[string]any{})
		s.count("scans_created")
		writeJSON(w, http.StatusAccepted, map[string]string{"scan_id": scanID, "status": "queued"})
	}
}

func (s *server) createFileScan(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := requestIdentity(r)
		limit := int64(s.cfg.maxUploadMB) << 20
		r.Body = http.MaxBytesReader(w, r.Body, limit+(1<<20))
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			writeError(w, 413, "file_too_large")
			return
		}
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			writeError(w, 400, "file_required")
			return
		}
		defer file.Close()
		if header.Size > limit {
			writeError(w, 413, "file_too_large")
			return
		}
		data, err := io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil || int64(len(data)) > limit {
			writeError(w, 413, "file_too_large")
			return
		}
		mimeType, valid := detectApkType(filepath.Ext(header.Filename), data)
		if !valid {
			writeError(w, 400, "unsupported_file_type")
			return
		}
		consent := r.FormValue("consent_external_upload") == "true"
		scanID := randomID()
		name := safeFilename(header.Filename)
		storagePath := id.ID + "/" + scanID + "/" + name
		hash := sha256.Sum256(data)
		if err := s.upload(r.Context(), "uploads", storagePath, mimeType, data); err != nil {
			writeError(w, 503, "storage_unavailable")
			return
		}
		if err := s.db.InsertScan(r.Context(), map[string]any{"id": scanID, "user_id": id.ID, "type": kind, "input_ref": storagePath, "status": "queued"}); err != nil {
			writeError(w, 503, "service_unavailable")
			return
		}
		digest := hex.EncodeToString(hash[:])
		fileRecord := map[string]any{"user_id": id.ID, "scan_id": scanID, "bucket": "uploads", "storage_path": storagePath, "sha256": digest, "size_bytes": len(data), "mime": mimeType, "expires_at": time.Now().Add(time.Duration(envInt("FILE_RETENTION_DAYS", 7)) * 24 * time.Hour).UTC()}
		if err := s.db.InsertFile(r.Context(), fileRecord); err != nil {
			writeError(w, 503, "service_unavailable")
			return
		}
		// The analysis service re-verifies this path before reading the object, and only
		// forwards the sample to third parties when the user ticked the consent box.
		input := map[string]any{"bucket": "uploads", "storage_path": storagePath, "sha256": digest, "size_bytes": len(data), "mime": mimeType, "filename": name}
		options := map[string]any{"consent_external_upload": consent}
		go s.processScan(scanID, id.ID, kind, input, options)
		s.count("scans_created")
		writeJSON(w, http.StatusAccepted, map[string]string{"scan_id": scanID, "status": "queued"})
	}
}

func (s *server) scanDeadline(kind string) time.Duration {
	seconds := s.cfg.scanTimeoutSeconds
	// APK static analysis is slower than the text scanners and gets its own budget.
	if kind == "application" && s.cfg.scanAPKTimeoutSeconds > seconds {
		seconds = s.cfg.scanAPKTimeoutSeconds
	}
	return time.Duration(seconds) * time.Second
}

func (s *server) processScan(scanID, userID, kind string, input, options map[string]any) {
	budget := s.scanDeadline(kind)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if s.cfg.serviceKey == "" {
		s.failScan(scanID, kind, "service_unavailable", "Analysis service is unavailable.")
		return
	}
	var created struct {
		JobID string `json:"job_id"`
	}
	body := map[string]any{"scan_id": scanID, "user_id": userID, "type": kind, "input": input, "options": options}
	if err := s.analysisRequest(ctx, http.MethodPost, "/internal/v1/jobs", body, &created); err != nil || created.JobID == "" {
		s.failScan(scanID, kind, "analysis_unavailable", "Analysis service could not accept this scan.")
		return
	}
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		var job map[string]any
		if err := s.analysisRequest(ctx, http.MethodGet, "/internal/v1/jobs/"+url.PathEscape(created.JobID), nil, &job); err == nil {
			status, _ := job["status"].(string)
			if status == "completed" || status == "failed" {
				report, _ := job["report"].(map[string]any)
				if report == nil {
					s.failScan(scanID, kind, "invalid_analysis_response", "Analysis service returned no report.")
					return
				}
				if status == "completed" {
					s.count("jobs_completed")
				} else {
					s.count("jobs_failed")
				}
				_ = s.db.PatchScan(context.Background(), scanID, map[string]any{"status": status, "outcome": report["outcome"], "risk_level": nested(report, "risk", "level"), "report": report, "error": errorCode(report), "finished_at": time.Now().UTC()})
				if usage, ok := report["llm_usage"].(map[string]any); ok {
					if model, _ := usage["model"].(string); model != "" {
						_ = s.db.InsertLLMUsage(context.Background(), map[string]any{"scan_id": scanID, "model": model, "prompt_tokens": usage["prompt_tokens"], "completion_tokens": usage["completion_tokens"], "latency_ms": usage["latency_ms"], "status": usage["status"]})
					}
				}
				return
			}
		}
		time.Sleep(time.Duration(s.cfg.scanPollSeconds) * time.Second)
	}
	s.count("scan_timeouts")
	s.failScan(scanID, kind, "timeout", "Scan exceeded the configured time limit.")
}

func (s *server) failScan(scanID, kind, code, message string) {
	s.count("scans_failed")
	report := scanReport{ScanID: scanID, Type: kind, Outcome: "scan_failed", Risk: map[string]any{"level": "unknown", "score": nil, "confidence": "low", "coverage": map[string]any{"checks_run": []string{}, "checks_unavailable": []string{}, "summary": "No completed analysis."}}, Findings: []any{}, EvidenceSummary: "", RecommendedActions: []string{"Coba pindai lagi nanti."}, Limitations: []string{}, Artifacts: map[string]any{"screenshot_path": nil, "redirect_chain": []string{}}, LLMUsage: map[string]any{"model": env("OPENAI_MODEL", "gpt-6-luna"), "prompt_tokens": 0, "completion_tokens": 0, "latency_ms": 0, "status": "not_used"}, Error: map[string]string{"code": code, "message": message}}
	_ = s.db.PatchScan(context.Background(), scanID, map[string]any{"status": "failed", "outcome": "scan_failed", "risk_level": "unknown", "report": report, "error": code, "finished_at": time.Now().UTC()})
}

func (s *server) listScans(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.ListScans(r.Context(), id.ID, limit, offset)
	if err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"scans": rows, "limit": limit, "offset": offset})
}

func (s *server) getScan(w http.ResponseWriter, r *http.Request) {
	id := requestIdentity(r)
	scanID := r.PathValue("scanID")
	if len(scanID) != 36 {
		writeError(w, 404, "not_found")
		return
	}
	row, found, err := s.db.GetScan(r.Context(), id.ID, scanID)
	if err != nil {
		writeError(w, 503, "service_unavailable")
		return
	}
	if !found {
		writeError(w, 404, "not_found")
		return
	}
	writeJSON(w, 200, row)
}

// ---------------------------------------------------------------- community phone reports

// phoneReportCategories is the canonical storage vocabulary and mirrors
// app/phone_reports.py::REPORT_CATEGORIES; free text is never stored as a category.
// phishing and pharming are the two board categories this endpoint did not know before the
// community report form moved onto /community/phone: a reporter picking "Phishing" there must not
// be sent back an invalid_category, and the three older values stay because /recognize still offers
// them.
var phoneReportCategories = map[string]bool{
	"penipuan": true, "spam": true, "telemarketing": true,
	"penagih_utang": true, "peniruan_identitas": true, "lainnya": true,
	"phishing": true, "pharming": true,
}

var callingCodes = map[string]string{"ID": "62"}

// validatePhoneReport returns "" when the payload is acceptable, otherwise the error code.
func validatePhoneReport(number, region, category, note string) string {
	if len(number) < 5 || len(number) > 32 || !validPhoneChars(number) || !allowedPhoneRegion(region) {
		return "invalid_phone"
	}
	if !phoneReportCategories[category] {
		return "invalid_category"
	}
	if len([]rune(note)) > 280 {
		return "invalid_note"
	}
	return ""
}

// canonicalPhoneDigits mirrors phone_scanner.canonical_digits: 0812…, 62812… and +62 0812… are
// the same subscriber, and the trunk 0 left over after the country code would store one number
// under two keys. Indonesian subscriber numbers never start with 0 once +62 is present.
func canonicalPhoneDigits(number string) string {
	digits := make([]rune, 0, len(number))
	for _, r := range number {
		if r >= '0' && r <= '9' {
			digits = append(digits, r)
		}
	}
	body := string(digits)
	if !strings.HasPrefix(body, "62") {
		return body
	}
	subscriber := body[2:]
	if strings.HasPrefix(subscriber, "0") {
		subscriber = subscriber[1:]
	}
	return "62" + subscriber
}

// fallbackE164 mirrors app/phone_scanner.py::_fallback_normalize so reporting stays usable
// when the analysis service is briefly unreachable. It never claims validity, it only shapes
// the digits; the analysis service remains the authority for the stored value.
func fallbackE164(number, region string) (string, bool) {
	digits := canonicalPhoneDigits(number)
	if digits == "" {
		return "", false
	}
	code := callingCodes[strings.ToUpper(region)]
	var body string
	switch {
	case code != "" && strings.HasPrefix(digits, code):
		body = digits
	case strings.HasPrefix(strings.TrimSpace(number), "+"):
		body = digits
	case digits[0] == '0':
		body = code + digits[1:]
	default:
		body = code + digits
	}
	if len(body) < 8 || len(body) > 15 {
		return "", false
	}
	return "+" + body, true
}

// normalizePhone delegates to the single Python implementation and falls back locally only
// when that service cannot be reached. When it answers, its verdict is final: an empty E.164
// means the number could not be normalised, and the local guess must not override it.
//
// The bool reports whether the number is a usable +62 key, not whether it is a real subscriber
// number: a +62 number with the wrong digit count is still stored, because validity is judged
// by the community (and shown as a finding), while +62 itself is the product scope.
func (s *server) normalizePhone(ctx context.Context, number, region string) (string, bool) {
	var normalized struct {
		E164     string `json:"e164"`
		Domestic bool   `json:"domestic"`
	}
	body := map[string]any{"number": number, "default_region": region}
	if err := s.analysisRequest(ctx, http.MethodPost, "/internal/v1/phone/normalize", body, &normalized); err == nil {
		return normalized.E164, normalized.E164 != "" && normalized.Domestic
	}
	e164, shaped := fallbackE164(number, region)
	return e164, shaped && indonesianE164(e164)
}

// evidenceMime decides the type of an uploaded proof image from its bytes, not from whatever
// the browser claimed. It mirrors app/phone_evidence.py::ALLOWED_EVIDENCE_MIME; anything the two
// lists disagree on is refused here rather than repaired later, so a report never carries an
// image nobody can open. GIF is left out on purpose: an animated proof is not a proof.
func evidenceMime(data []byte, declared string) string {
	switch detected := http.DetectContentType(data); detected {
	case "image/png", "image/jpeg", "image/webp":
		return detected
	}
	// http.DetectContentType has no signature for HEIC, and iPhone cameras produce nothing else.
	// The ISO base-media brand at offset 8 is the magic check, so a renamed .php never passes.
	if len(data) >= 12 && string(data[4:8]) == "ftyp" {
		switch strings.ToLower(string(data[8:12])) {
		case "heic", "heix", "hevc", "hevx", "mif1", "msf1":
			if strings.ToLower(declared) == "image/heif" {
				return "image/heif"
			}
			return "image/heic"
		}
	}
	return ""
}

type storedEvidence struct {
	URL      string `json:"url"`
	PublicID string `json:"public_id"`
	Mime     string `json:"mime"`
}

// storePhoneEvidence hands the bytes to the analysis service, which owns the Cloudinary
// credentials. The image is passed as base64 JSON on purpose: this service has no multipart
// client for it and the Python side has no multipart parser installed.
func (s *server) storePhoneEvidence(ctx context.Context, userID, reference, mime string, data []byte) (*storedEvidence, bool) {
	var stored storedEvidence
	body := map[string]any{
		"user_id":     userID,
		"reference":   reference,
		"mime":        mime,
		"data_base64": base64.StdEncoding.EncodeToString(data),
	}
	// A 503 here is the service saying "this image cannot be kept", which is the same answer as
	// a transport failure: either way the report has to be refused.
	if err := s.analysisRequest(ctx, http.MethodPost, "/internal/v1/phone-reports/evidence", body, &stored); err != nil {
		return nil, false
	}
	if stored.URL == "" || stored.PublicID == "" {
		return nil, false
	}
	return &stored, true
}

// discardPhoneEvidence is cleanup, not a decision: the report is already refused, so whether the
// asset vanished only feeds the metrics.
func (s *server) discardPhoneEvidence(ctx context.Context, publicID string) {
	if publicID == "" {
		return
	}
	_ = s.analysisRequest(ctx, http.MethodDelete, "/internal/v1/phone-reports/evidence",
		map[string]any{"public_id": publicID}, nil)
}

// createPhoneReport stores one pending community report. Reports never raise risk by
// themselves: only a moderator turning them into "verified" does that (app/phone_reports.py).
//
// The evidence image is mandatory and stored first: "bukti wajib" only means something if a
// report without its proof cannot exist, so every failure path here leaves nothing behind.
func (s *server) createPhoneReport(w http.ResponseWriter, r *http.Request) {
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
	region := strings.ToUpper(strings.TrimSpace(r.FormValue("default_region")))
	if region == "" {
		region = "ID"
	}
	category := strings.ToLower(strings.TrimSpace(r.FormValue("category")))
	note := strings.TrimSpace(r.FormValue("note"))
	if code := validatePhoneReport(number, region, category, note); code != "" {
		writeError(w, 400, code)
		return
	}
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
	if !s.allow("phone_report:"+id.ID, envInt("PHONE_REPORT_HOURLY_LIMIT", 10), time.Hour) {
		writeError(w, 429, "rate_limited")
		return
	}
	e164, domestic := s.normalizePhone(r.Context(), number, region)
	if e164 == "" {
		writeError(w, 400, "invalid_phone")
		return
	}
	if !domestic {
		writeError(w, 400, "not_indonesian")
		return
	}
	if exists, err := s.db.PhoneReportExists(r.Context(), id.ID, e164); err == nil && exists {
		writeError(w, 409, "duplicate_report")
		return
	}
	stored, ok := s.storePhoneEvidence(r.Context(), id.ID, randomID(), mimeType, data)
	if !ok {
		writeError(w, 503, "evidence_unavailable")
		return
	}
	row := map[string]any{
		"number_e164":        e164,
		"category":           category,
		"source":             "user_report",
		"reported_by":        id.ID,
		"status":             "pending",
		"evidence_url":       stored.URL,
		"evidence_public_id": stored.PublicID,
	}
	if note != "" {
		row["note"] = note
	}
	noteSaved := note != ""
	if err := s.db.InsertPhoneReport(r.Context(), row); err != nil {
		if exists, checkErr := s.db.PhoneReportExists(r.Context(), id.ID, e164); checkErr == nil && exists {
			s.discardPhoneEvidence(r.Context(), stored.PublicID)
			writeError(w, 409, "duplicate_report")
			return
		}
		if note != "" {
			// A database without the optional note column still stores the report itself.
			delete(row, "note")
			noteSaved = false
			err = s.db.InsertPhoneReport(r.Context(), row)
		}
		if err != nil {
			// The evidence columns are additive too, but unlike the note they cannot be dropped:
			// the migration has to be applied before reports can be accepted.
			s.discardPhoneEvidence(r.Context(), stored.PublicID)
			writeError(w, 503, "service_unavailable")
			return
		}
	}
	s.count("phone_reports_created")
	writeJSON(w, http.StatusAccepted, map[string]any{"number_e164": e164, "category": category, "status": "pending", "note_saved": noteSaved})
}

func (s *server) supabase(ctx context.Context, method, path string, body any, bearer string, out any) error {
	if s.cfg.supabaseURL == "" {
		return errors.New("supabase URL missing")
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.cfg.supabaseURL+path, reader)
	if err != nil {
		return err
	}
	key := s.cfg.secretKey
	if bearer != "" {
		key = s.cfg.publishableKey
		req.Header.Set("Authorization", "Bearer "+bearer)
	} else {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("apikey", key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.HasPrefix(path, "/rest/v1/") && method == http.MethodPatch {
		req.Header.Set("Prefer", "return=representation")
	} else if strings.HasPrefix(path, "/rest/v1/") && method == http.MethodPost {
		req.Header.Set("Prefer", "return=minimal")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("supabase returned status %d", resp.StatusCode)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (s *server) upload(ctx context.Context, bucket, object string, mimeType string, data []byte) error {
	path := "/storage/v1/object/" + bucket + "/" + escapeObjectPath(object)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.supabaseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("apikey", s.cfg.secretKey)
	req.Header.Set("Authorization", "Bearer "+s.cfg.secretKey)
	req.Header.Set("Content-Type", mimeType)
	req.Header.Set("x-upsert", "false")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("storage returned status %d", resp.StatusCode)
	}
	return nil
}

func (s *server) analysisRequest(ctx context.Context, method, path string, body any, out any) error {
	var data io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		data = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.cfg.analysisURL+path, data)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Service-Key", s.cfg.serviceKey)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("analysis returned status %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(content, out)
	}
	return nil
}

func (s *server) authEvent(ctx context.Context, userID, event, ip string) {
	_ = s.db.InsertAuthEvent(ctx, userID, event, ip)
}

func (s *server) sign(value string) string {
	h := hmac.New(sha256.New, []byte(s.cfg.preCookieSecret))
	_, _ = h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *server) validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	for _, allowed := range strings.Split(s.cfg.origins, ",") {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	return false
}

func requestIdentity(r *http.Request) identity {
	v, _ := r.Context().Value(identityKey{}).(identity)
	return v
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil || value < 1 {
		return fallback
	}
	return value
}
func validPhoneChars(value string) bool {
	for _, r := range value {
		if !(r >= '0' && r <= '9') && r != '+' && r != '-' && r != '(' && r != ')' && r != ' ' {
			return false
		}
	}
	return true
}

// allowedPhoneRegion keeps the product scope honest: only Indonesian numbers are accepted,
// so no other country's subscribers can be entered into the community database.
func allowedPhoneRegion(region string) bool {
	return strings.EqualFold(region, "ID")
}

// indonesianE164 reports whether a normalised number actually carries the +62 country code.
// The region field alone is not enough: "+1 202 555 0123" submitted with region ID normalises
// to a US number, and that must not reach storage or the checker.
func indonesianE164(e164 string) bool {
	return strings.HasPrefix(e164, "+62")
}

func nested(value map[string]any, outer, inner string) any {
	if m, ok := value[outer].(map[string]any); ok {
		return m[inner]
	}
	return nil
}

func errorCode(report map[string]any) any {
	if problem, ok := report["error"].(map[string]any); ok {
		if code, ok := problem["code"].(string); ok {
			return code
		}
	}
	return nil
}
func safeFilename(name string) string {
	name = filepath.Base(name)
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "upload"
	}
	return b.String()
}
func escapeObjectPath(path string) string {
	parts := strings.Split(path, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
func detectApkType(ext string, data []byte) (string, bool) {
	if !strings.EqualFold(ext, ".apk") || len(data) < 4 || !bytes.Equal(data[:4], []byte{'P', 'K', 3, 4}) {
		return "", false
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	return "application/vnd.android.package-archive", err == nil && len(archive.File) > 0
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, apiError{Code: code})
}
