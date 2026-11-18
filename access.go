package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Environment variables that configure Cloudflare Access checks in serve mode.
const (
	envAccessTeamDomain = "PAPERLESS_MCP_ACCESS_TEAM_DOMAIN"
	envAccessAUD        = "PAPERLESS_MCP_ACCESS_AUD"
	envAllowedEmails    = "PAPERLESS_MCP_ALLOWED_EMAILS"
)

// accessJWTHeader is the header in which Cloudflare Access passes its signed
// assertion of the user's identity to the origin.
const accessJWTHeader = "Cf-Access-Jwt-Assertion"

// accessCertsTimeout bounds each fetch of the Access signing keys.
const accessCertsTimeout = 10 * time.Second

// accessConfig is the Cloudflare Access configuration for serve mode.
type accessConfig struct {
	Issuer        string          // https://<team>.cloudflareaccess.com, the JWT's iss
	CertsURL      string          // <Issuer>/cdn-cgi/access/certs
	AUD           string          // the Access application's AUD tag
	AllowedEmails map[string]bool // lower-cased
}

// loadAccessConfig reads the Access settings. All three are required: serve
// refuses to start without them, so the HTTP endpoint is never unprotected.
func loadAccessConfig(getenv func(string) string) (accessConfig, error) {
	var cfg accessConfig

	team := strings.TrimSpace(getenv(envAccessTeamDomain))
	if team == "" || strings.Contains(team, "${") {
		return cfg, fmt.Errorf("serve requires %s (e.g. https://<team>.cloudflareaccess.com)", envAccessTeamDomain)
	}
	if !strings.Contains(team, "://") {
		team = "https://" + team
	}
	u, err := url.Parse(strings.TrimRight(team, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return cfg, fmt.Errorf("%s must be an https origin such as https://<team>.cloudflareaccess.com", envAccessTeamDomain)
	}
	cfg.Issuer = "https://" + u.Host
	cfg.CertsURL = cfg.Issuer + "/cdn-cgi/access/certs"

	cfg.AUD = strings.TrimSpace(getenv(envAccessAUD))
	if cfg.AUD == "" || strings.Contains(cfg.AUD, "${") {
		return cfg, fmt.Errorf("serve requires %s (the Access application's AUD tag)", envAccessAUD)
	}

	cfg.AllowedEmails = map[string]bool{}
	for _, email := range splitPolicyNames(getenv(envAllowedEmails)) {
		cfg.AllowedEmails[strings.ToLower(email)] = true
	}
	if len(cfg.AllowedEmails) == 0 {
		return cfg, fmt.Errorf("serve requires %s (comma-separated email addresses)", envAllowedEmails)
	}
	return cfg, nil
}

// accessVerifier checks Cloudflare Access JWTs: the RS256 signature against
// the team's published keys (matched by kid, rotation handled by go-oidc),
// the issuer, the audience, the expiry, and the email against the allowlist.
type accessVerifier struct {
	verifier *oidc.IDTokenVerifier
	allowed  map[string]bool
}

// newAccessVerifier builds the verifier. Signing keys are fetched lazily, on
// the first token and again when an unknown kid appears.
func newAccessVerifier(ctx context.Context, cfg accessConfig) *accessVerifier {
	// This client only ever fetches the Access signing keys from Cloudflare.
	// It never talks to Paperless; Paperless traffic goes through Client.
	certsClient := &http.Client{Timeout: accessCertsTimeout}
	keySet := oidc.NewRemoteKeySet(oidc.ClientContext(ctx, certsClient), cfg.CertsURL)
	return &accessVerifier{
		verifier: oidc.NewVerifier(cfg.Issuer, keySet, &oidc.Config{
			ClientID:             cfg.AUD,
			SupportedSigningAlgs: []string{oidc.RS256},
		}),
		allowed: cfg.AllowedEmails,
	}
}

// verify checks a raw Access JWT and returns the email it asserts.
func (a *accessVerifier) verify(ctx context.Context, raw string) (string, error) {
	token, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		return "", err
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := token.Claims(&claims); err != nil {
		return "", fmt.Errorf("read claims: %w", err)
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return "", fmt.Errorf("token has no email claim (service tokens are not accepted)")
	}
	if !a.allowed[email] {
		return email, fmt.Errorf("email %s is not in %s", email, envAllowedEmails)
	}
	return email, nil
}

// identityKey carries the verified email in a request's context.
type identityKey struct{}

// identityFrom returns the verified email in ctx, or "".
func identityFrom(ctx context.Context) string {
	email, _ := ctx.Value(identityKey{}).(string)
	return email
}

// requireAccess wraps next so that only requests with a valid Access JWT for
// an allowed email reach it. Any failure answers 401 with no detail; the
// reason goes to the log. It fails closed: no header, a bad token, a key
// fetch error all end in 401.
func requireAccess(v *accessVerifier, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get(accessJWTHeader)
		if raw == "" {
			logger.Warn("auth refused", "reason", "missing "+accessJWTHeader+" header", "remote", r.RemoteAddr)
			unauthorized(w)
			return
		}
		email, err := v.verify(r.Context(), raw)
		if err != nil {
			logger.Warn("auth refused", "reason", err.Error(), "email", email, "remote", r.RemoteAddr)
			unauthorized(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, email)))
	})
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte("unauthorized\n"))
}
