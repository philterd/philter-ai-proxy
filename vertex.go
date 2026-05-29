package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// vertexAuthScope is the OAuth scope for Vertex AI when authenticating with
// a Google OAuth2 / ADC token. cloud-platform is the documented scope for
// Vertex AI Generative Language APIs.
const vertexAuthScope = "https://www.googleapis.com/auth/cloud-platform"

// isVertexPath reports whether a request path targets Vertex AI's
// resource-style generation endpoints:
//
//	/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent
//	/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:streamGenerateContent
//
// Differentiated from the public Gemini API (which uses /v1/models/... or
// /v1beta/models/...) by the /projects/ prefix.
func isVertexPath(path string) bool {
	if !strings.HasPrefix(path, "/v1/projects/") {
		return false
	}
	lp := strings.ToLower(path)
	return strings.Contains(lp, ":generatecontent") || strings.Contains(lp, ":streamgeneratecontent")
}

// vertexModelFromPath extracts {model} from a Vertex resource-style path. The
// model is the URL-level identifier (e.g. `gemini-1.5-pro`); requests don't
// carry a body-level `model` field. Returns "" if the path does not match.
func vertexModelFromPath(path string) string {
	const marker = "/models/"
	idx := strings.Index(path, marker)
	if idx == -1 {
		return ""
	}
	rest := path[idx+len(marker):]
	// Trim the trailing `:generateContent` / `:streamGenerateContent` suffix
	// and anything after it.
	if colon := strings.Index(rest, ":"); colon != -1 {
		rest = rest[:colon]
	}
	if slash := strings.Index(rest, "/"); slash != -1 {
		rest = rest[:slash]
	}
	return rest
}

// vertexDefaultEndpoint returns the regional default endpoint for the given
// location, e.g. "us-central1" -> "https://us-central1-aiplatform.googleapis.com".
func vertexDefaultEndpoint(location string) string {
	return fmt.Sprintf("https://%s-aiplatform.googleapis.com", location)
}

// vertexTokenProvider acquires and caches a Google OAuth2 access token via
// Application Default Credentials (workload identity, service-account file,
// metadata server, gcloud creds, etc.). Tokens are refreshed shortly before
// expiry.
//
// Implements the tokenSource interface declared in azure.go so the Vertex
// handler can be tested with an injected fake.
type vertexTokenProvider struct {
	ts oauth2.TokenSource

	mu     sync.Mutex
	cached *oauth2.Token
}

func newVertexTokenProvider(ctx context.Context) (*vertexTokenProvider, error) {
	ts, err := google.DefaultTokenSource(ctx, vertexAuthScope)
	if err != nil {
		return nil, fmt.Errorf("vertex: %w", err)
	}
	return &vertexTokenProvider{ts: ts}, nil
}

func (v *vertexTokenProvider) token(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cached != nil && v.cached.AccessToken != "" && time.Until(v.cached.Expiry) > 5*time.Minute {
		return v.cached.AccessToken, nil
	}
	tok, err := v.ts.Token()
	if err != nil {
		return "", err
	}
	v.cached = tok
	return tok.AccessToken, nil
}

// staticTokenSource is a tokenSource that returns a fixed token, used in
// tests and other places where ADC isn't available.
type staticTokenSource struct {
	value string
}

func (s staticTokenSource) token(_ context.Context) (string, error) {
	if s.value == "" {
		return "", fmt.Errorf("static token source: empty token")
	}
	return s.value, nil
}

// handleVertex proxies a Vertex AI request. Request and response bodies are
// the Gemini schema, so redaction and outbound scanning are delegated to the
// shared handleGeminiShaped path; the Vertex-specific work is acquiring an
// OAuth2 bearer token and setting it as the Authorization header. The
// URL-level model identifier is recorded in the audit entry.
func (p *Proxy) handleVertex(w http.ResponseWriter, r *http.Request, bodyBytes []byte, philterCtx, documentID, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	audit.Model = vertexModelFromPath(r.URL.Path)

	if p.vertexTokenSource == nil {
		slog.Error("Vertex token source not configured", "request_id", audit.RequestID)
		writeError(w, audit, http.StatusBadGateway, "provider_error", "vertex_auth_failed", "vertex token source not configured")
		return
	}
	tok, err := p.vertexTokenSource.token(r.Context())
	if err != nil {
		slog.Error("Vertex token acquisition failed", "error", err, "request_id", audit.RequestID)
		writeError(w, audit, http.StatusBadGateway, "provider_error", "vertex_auth_failed", "failed to acquire vertex auth token")
		return
	}
	r.Header.Set("Authorization", "Bearer "+tok)

	p.handleGeminiShaped(w, r, bodyBytes, philterCtx, documentID, policyName, audit, outbound, p.vertexTarget, p.vertexClient, "vertex")
}

// vertexTargetURL builds the Vertex AI target URL from the configured project,
// location, and optional endpoint override. The returned URL is the host the
// proxy forwards to; the request's resource path is preserved verbatim so
// {project}/{location} need not match the configured values (operators may
// proxy multiple projects from one deployment if they configure ADC to permit
// it).
func vertexTargetURL(cfg VertexConfig) (*url.URL, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		if cfg.Location == "" {
			return nil, fmt.Errorf("vertex: location or endpoint required")
		}
		endpoint = vertexDefaultEndpoint(cfg.Location)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("vertex: invalid endpoint %q: %w", endpoint, err)
	}
	return u, nil
}
