package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	testAccessIssuer = "https://example-team.cloudflareaccess.com"
	testAccessAUD    = "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2"
	testEmail        = "alex@example.com"
)

// accessFixture is a fake Cloudflare Access: a signing key, the certs
// endpoint that publishes it, and a matching accessConfig.
type accessFixture struct {
	key    *rsa.PrivateKey
	kid    string
	certs  *httptest.Server
	config accessConfig
}

func newAccessFixture(t *testing.T) *accessFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &accessFixture{key: key, kid: "test-key-1"}
	f.certs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(f.certs.Close)
	f.config = accessConfig{
		Issuer:        testAccessIssuer,
		CertsURL:      f.certs.URL + "/cdn-cgi/access/certs",
		AUD:           testAccessAUD,
		AllowedEmails: map[string]bool{testEmail: true},
	}
	return f
}

// claims returns valid Access claims for email; tests change single fields.
func (f *accessFixture) claims(email string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   testAccessIssuer,
		"aud":   []string{testAccessAUD},
		"sub":   "8a5b1c2d",
		"email": email,
		"iat":   now.Add(-time.Minute).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
		"type":  "app",
	}
}

// sign signs claims with key under kid (RS256).
func sign(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *accessFixture) token(t *testing.T, change func(map[string]any)) string {
	t.Helper()
	c := f.claims(testEmail)
	if change != nil {
		change(c)
	}
	return sign(t, f.key, f.kid, c)
}

// lockedBuffer is a bytes.Buffer safe for concurrent log writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestAccessVerifier(t *testing.T) {
	f := newAccessFixture(t)
	v := newAccessVerifier(context.Background(), f.config)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		token   func() string
		wantErr string // empty: valid
	}{
		{"valid", func() string { return f.token(t, nil) }, ""},
		{"email case does not matter", func() string {
			return f.token(t, func(c map[string]any) { c["email"] = "Alex@Example.COM" })
		}, ""},
		{"expired", func() string {
			return f.token(t, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() })
		}, "expired"},
		{"wrong aud", func() string {
			return f.token(t, func(c map[string]any) { c["aud"] = []string{"another-application"} })
		}, "expected audience"},
		{"wrong iss", func() string {
			return f.token(t, func(c map[string]any) { c["iss"] = "https://evil.cloudflareaccess.com" })
		}, "issued by a different provider"},
		{"unlisted email", func() string {
			return f.token(t, func(c map[string]any) { c["email"] = "mallory@example.com" })
		}, "is not in PAPERLESS_MCP_ALLOWED_EMAILS"},
		{"no email (service token)", func() string {
			return f.token(t, func(c map[string]any) { delete(c, "email"); c["common_name"] = "svc.access" })
		}, "no email claim"},
		{"signed by another key", func() string { return sign(t, otherKey, f.kid, f.claims(testEmail)) }, "verify"},
		{"unknown key id", func() string { return sign(t, otherKey, "unknown-kid", f.claims(testEmail)) }, "verify"},
		{"tampered payload", func() string {
			parts := strings.Split(f.token(t, nil), ".")
			other := strings.Split(f.token(t, func(c map[string]any) { c["email"] = "mallory@example.com" }), ".")
			return parts[0] + "." + other[1] + "." + parts[2]
		}, "verify"},
		{"not a JWT", func() string { return "oauth:CvNooOpaque" }, "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email, err := v.verify(context.Background(), tc.token())
			if tc.wantErr == "" {
				if err != nil || email != testEmail {
					t.Fatalf("verify = %q, %v; want %q", email, err, testEmail)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("verify error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestRequireAccess(t *testing.T) {
	f := newAccessFixture(t)
	var logs lockedBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	var gotEmail string
	handler := requireAccess(newAccessVerifier(context.Background(), f.config), logger,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotEmail = identityFrom(r.Context())
			w.WriteHeader(http.StatusNoContent)
		}))

	do := func(token string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
		if token != "" {
			req.Header.Set(accessJWTHeader, token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		return rec.Code, string(body)
	}

	status, _ := do(f.token(t, nil))
	if status != http.StatusNoContent || gotEmail != testEmail {
		t.Fatalf("valid token: status %d, email %q", status, gotEmail)
	}

	expired := f.token(t, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
	for name, token := range map[string]string{"missing header": "", "expired": expired, "garbage": "a.b.c"} {
		gotEmail = ""
		status, body := do(token)
		if status != http.StatusUnauthorized || body != "unauthorized\n" {
			t.Errorf("%s: %d %q, want 401 without detail", name, status, body)
		}
		if gotEmail != "" {
			t.Errorf("%s: request reached the handler", name)
		}
	}
	if !strings.Contains(logs.String(), "missing Cf-Access-Jwt-Assertion header") || !strings.Contains(logs.String(), "expired") {
		t.Errorf("log lacks the refusal reasons:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), expired) {
		t.Error("log contains a raw token")
	}
}

func TestAccessCertsUnreachableFailsClosed(t *testing.T) {
	f := newAccessFixture(t)
	f.certs.Close()
	v := newAccessVerifier(context.Background(), f.config)
	if _, err := v.verify(context.Background(), f.token(t, nil)); err == nil {
		t.Fatal("verify succeeded without signing keys")
	}
}

func TestLoadAccessConfig(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := map[string]string{
			envAccessTeamDomain: "example-team.cloudflareaccess.com",
			envAccessAUD:        testAccessAUD,
			envAllowedEmails:    " Alex@Example.com , second@example.com ",
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}

	cfg, err := loadAccessConfig(env())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != testAccessIssuer || cfg.CertsURL != testAccessIssuer+"/cdn-cgi/access/certs" {
		t.Errorf("issuer %q, certs %q", cfg.Issuer, cfg.CertsURL)
	}
	if !cfg.AllowedEmails["alex@example.com"] || !cfg.AllowedEmails["second@example.com"] || len(cfg.AllowedEmails) != 2 {
		t.Errorf("allowed emails = %v", cfg.AllowedEmails)
	}
	if cfg, err := loadAccessConfig(env(envAccessTeamDomain, "https://example-team.cloudflareaccess.com/")); err != nil || cfg.Issuer != testAccessIssuer {
		t.Errorf("with scheme and slash: %q, %v", cfg.Issuer, err)
	}

	for _, tc := range []struct {
		name    string
		env     func(string) string
		wantErr string
	}{
		{"no team domain", env(envAccessTeamDomain, ""), "serve requires PAPERLESS_MCP_ACCESS_TEAM_DOMAIN"},
		{"template team domain", env(envAccessTeamDomain, "${user_config.team}"), "serve requires PAPERLESS_MCP_ACCESS_TEAM_DOMAIN"},
		{"http team domain", env(envAccessTeamDomain, "http://example-team.cloudflareaccess.com"), "must be an https origin"},
		{"team domain with path", env(envAccessTeamDomain, "https://example-team.cloudflareaccess.com/cdn-cgi"), "must be an https origin"},
		{"no aud", env(envAccessAUD, " "), "serve requires PAPERLESS_MCP_ACCESS_AUD"},
		{"no emails", env(envAllowedEmails, " , "), "serve requires PAPERLESS_MCP_ALLOWED_EMAILS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadAccessConfig(tc.env); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
