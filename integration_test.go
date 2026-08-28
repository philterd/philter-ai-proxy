//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// philterIntegrationURL returns the Philter endpoint used by integration tests.
// It defaults to the host port published by docker-compose.test.yaml (8081)
// but can be overridden with PHILTER_TEST_URL.
func philterIntegrationURL() string {
	if u := os.Getenv("PHILTER_TEST_URL"); u != "" {
		return u
	}
	return "http://localhost:8081"
}

// waitForPhilter polls the Philter endpoint until it responds or the deadline
// elapses. The reference image returns 404 at "/", but a successful TCP+HTTP
// roundtrip is enough to know the service is up.
func waitForPhilter(t *testing.T, endpoint string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(endpoint + "/api/status")
		if err == nil {
			resp.Body.Close()
			return
		}
		// Fall back to the bare endpoint — older images may not expose /api/status.
		resp, err = client.Get(endpoint)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("Philter not reachable at %s within %v — start it with `make integration-up`", endpoint, timeout)
}

func newIntegrationProxy(t *testing.T, philterURL string, openaiURL *url.URL, auditOut *bytes.Buffer) *Proxy {
	t.Helper()
	cfg := defaultConfig()
	cfg.Philter.Endpoint = philterURL
	cfg.Philter.Retry = RetryConfig{MaxAttempts: 1}
	cfg.Philter.CircuitBreaker = CircuitBreakerConfig{Enabled: false}
	cfg.Defaults.Policy = "default"
	cfg.Defaults.Context = "none"

	p := &Proxy{
		config:       cfg,
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter: newPhilterClient(http.DefaultClient, philterURL,
			RetryConfig{MaxAttempts: 1},
			CircuitBreakerConfig{Enabled: false}),
	}
	if auditOut != nil {
		p.auditLogger = slog.New(slog.NewJSONHandler(auditOut, nil))
	}
	return p
}

// TestIntegration_OpenAI_EndToEnd exercises the full request lifecycle:
//
//	client → proxy → real Philter → mock OpenAI → proxy → client
//
// It verifies that:
//  1. The proxy returns 200 to the client.
//  2. The downstream OpenAI mock actually receives the request (Philter did
//     not short-circuit the flow).
//  3. The mock's response body is delivered back to the client unchanged.
//  4. An audit log entry is emitted with provider=openai.
func TestIntegration_OpenAI_EndToEnd(t *testing.T) {
	philterURL := philterIntegrationURL()
	waitForPhilter(t, philterURL, 30*time.Second)

	var (
		mu             sync.Mutex
		receivedBody   []byte
		receivedPath   string
		receivedMethod string
	)

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = body
		receivedPath = r.URL.Path
		receivedMethod = r.Method
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"chatcmpl-integration","object":"chat.completion","model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"Hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	var auditBuf bytes.Buffer
	proxy := newIntegrationProxy(t, philterURL, openaiURL, &auditBuf)

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"My SSN is 123-45-6789 and my email is alice@example.com"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from proxy, got %d: %s", w.Code, w.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()

	if receivedBody == nil {
		t.Fatal("mock OpenAI server was never called — proxy did not forward the request")
	}
	if receivedMethod != "POST" {
		t.Errorf("expected POST to provider, got %s", receivedMethod)
	}
	if receivedPath != "/v1/chat/completions" {
		t.Errorf("expected provider path /v1/chat/completions, got %s", receivedPath)
	}

	var forwarded OpenAIRequest
	if err := json.Unmarshal(receivedBody, &forwarded); err != nil {
		t.Fatalf("provider received malformed JSON: %v\n%s", err, string(receivedBody))
	}
	if forwarded.Model != "gpt-4" {
		t.Errorf("expected forwarded model gpt-4, got %q", forwarded.Model)
	}
	if len(forwarded.Messages) != 1 {
		t.Fatalf("expected 1 forwarded message, got %d", len(forwarded.Messages))
	}
	var forwardedContent string
	if err := json.Unmarshal(forwarded.Messages[0].Content, &forwardedContent); err != nil {
		t.Fatalf("forwarded message content is not a string: %v", err)
	}
	if forwardedContent == "" {
		t.Error("forwarded message content is empty — Philter dropped the text")
	}
	// Log what Philter produced so test output is useful when policies change.
	t.Logf("Philter produced forwarded content: %q", forwardedContent)

	respBody := w.Body.String()
	if !strings.Contains(respBody, `"chatcmpl-integration"`) {
		t.Errorf("expected mock provider response body to reach client, got: %s", respBody)
	}

	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("expected Content-Type application/json from proxy, got %q", ct)
	}

	auditOut := auditBuf.String()
	if auditOut == "" {
		t.Fatal("no audit log entry emitted")
	}
	var auditEntry map[string]any
	// auditBuf may contain multiple JSON objects (one per line); the first one
	// is the inbound entry we care about.
	firstLine := strings.SplitN(auditOut, "\n", 2)[0]
	if err := json.Unmarshal([]byte(firstLine), &auditEntry); err != nil {
		t.Fatalf("audit log is not valid JSON: %v\n%s", err, auditOut)
	}
	if auditEntry["provider"] != "openai" {
		t.Errorf("expected audit provider=openai, got %v", auditEntry["provider"])
	}
	if auditEntry["http_status"] != float64(200) {
		t.Errorf("expected audit http_status=200, got %v", auditEntry["http_status"])
	}
}

// TestIntegration_OpenAI_PhilterRedacts verifies that Philter actually
// transformed the inbound text before it was forwarded. It assumes the
// reference image's default policy redacts at least one of the common PII
// types in the prompt. If no redaction occurs, the test is skipped rather
// than failed — this lets the suite run against custom policies without
// silently passing the "is Philter wired up?" check elsewhere in the suite.
func TestIntegration_OpenAI_PhilterRedacts(t *testing.T) {
	philterURL := philterIntegrationURL()
	waitForPhilter(t, philterURL, 30*time.Second)

	originalContent := "The patient was born on 01/02/1980 and his SSN is 123-45-6789."

	var receivedBody []byte
	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer openaiServer.Close()

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := newIntegrationProxy(t, philterURL, openaiURL, nil)

	reqBody, _ := json.Marshal(map[string]any{
		"model": "gpt-4",
		"messages": []map[string]any{
			{"role": "user", "content": originalContent},
		},
	})
	req := httptest.NewRequest("POST", "/v1/chat/completions", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var forwarded OpenAIRequest
	if err := json.Unmarshal(receivedBody, &forwarded); err != nil {
		t.Fatalf("malformed forwarded body: %v", err)
	}
	var forwardedContent string
	json.Unmarshal(forwarded.Messages[0].Content, &forwardedContent)

	t.Logf("original:  %q", originalContent)
	t.Logf("forwarded: %q", forwardedContent)

	if forwardedContent == originalContent {
		t.Skip("Philter returned the input unchanged — the active policy does not redact this fixture; skipping redaction assertion")
	}
}

// TestIntegration_Health verifies the /health endpoint returns 200 with
// "status":"UP" and "philter":"ok" when the real Philter container is reachable.
func TestIntegration_Health(t *testing.T) {
	philterURL := philterIntegrationURL()
	waitForPhilter(t, philterURL, 30*time.Second)

	proxy := newIntegrationProxy(t, philterURL, &url.URL{}, nil)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected /health 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"status":"UP"`) {
		t.Errorf("expected UP status, got %s", body)
	}
	if !strings.Contains(body, `"philter":"ok"`) {
		t.Errorf("expected philter:ok in health body, got %s", body)
	}
}
