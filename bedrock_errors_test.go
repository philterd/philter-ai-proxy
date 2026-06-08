package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// failingCreds is an aws.CredentialsProvider that always errors, to exercise
// the Bedrock request-signing failure path.
type failingCreds struct{}

func (failingCreds) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, errors.New("credentials unavailable")
}

// bedrockJSONServer returns a Bedrock stub that replies with a Converse response
// carrying the given assistant text.
func bedrockJSONServer(t *testing.T, text string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BedrockConverseResponse{
			Output: BedrockConverseOutput{
				Message: BedrockMessage{Role: "assistant", Content: []BedrockContentBlock{{Text: text}}},
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func bedrockReq() *http.Request {
	return httptest.NewRequest("POST", "/model/amazon.titan-text-v1/converse",
		strings.NewReader(`{"messages":[{"role":"user","content":[{"text":"hello"}]}]}`))
}

// TestBedrock_SignError covers the signing-failure branch: a creds provider that
// errors yields HTTP 500 with the bedrock_sign_failed code.
func TestBedrock_SignError(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()
	bedrockSrv := bedrockJSONServer(t, "ok")

	proxy := newBedrockProxy(philterSrv.URL, bedrockSrv.URL)
	proxy.bedrockCreds = failingCreds{}

	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, bedrockReq())

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "bedrock_sign_failed") {
		t.Errorf("expected bedrock_sign_failed, got: %s", w.Body.String())
	}
}

// TestBedrock_OutboundScan_SignError covers the signing-failure branch inside
// the capture path (outbound-scan enabled): it surfaces as HTTP 502.
func TestBedrock_OutboundScan_SignError(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()
	bedrockSrv := bedrockJSONServer(t, "ok")

	proxy := newBedrockProxy(philterSrv.URL, bedrockSrv.URL)
	proxy.bedrockCreds = failingCreds{}
	proxy.config.Defaults.Outbound = OutboundConfig{Enabled: true, Action: "redact"}

	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, bedrockReq())

	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502 on signing failure in the capture path, got %d: %s", w.Code, w.Body.String())
	}
}

// TestBedrock_OutboundScan_ProviderUnreachable covers the capture-error branch
// of the outbound-scan path: an unreachable Bedrock endpoint yields HTTP 502.
func TestBedrock_OutboundScan_ProviderUnreachable(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	proxy := newBedrockProxy(philterSrv.URL, "http://127.0.0.1:1") // nothing listening
	proxy.config.Defaults.Outbound = OutboundConfig{Enabled: true, Action: "redact"}

	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, bedrockReq())

	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d: %s", w.Code, w.Body.String())
	}
}

// TestBedrock_OutboundScan_PhilterError covers the scan-error branch: Philter is
// reachable for the inbound redaction but fails on the outbound scan, yielding
// HTTP 502 with philter_error.
func TestBedrock_OutboundScan_PhilterError(t *testing.T) {
	var calls int
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 { // inbound redaction succeeds
			w.Write(explainJSON("hi", "doc-id", nil))
			return
		}
		w.WriteHeader(http.StatusInternalServerError) // outbound scan fails
		w.Write([]byte("boom"))
	}))
	defer philterSrv.Close()
	bedrockSrv := bedrockJSONServer(t, "John Smith")

	proxy := newBedrockProxy(philterSrv.URL, bedrockSrv.URL)
	proxy.config.Defaults.Outbound = OutboundConfig{Enabled: true, Action: "redact"}

	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, bedrockReq())

	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502 on outbound Philter failure, got %d: %s", w.Code, w.Body.String())
	}
}

// TestBedrock_OutboundScan_Block covers the blocked branch: action "block" with
// PII detected yields HTTP 403 with outbound_blocked.
func TestBedrock_OutboundScan_Block(t *testing.T) {
	philter := philterRedact("[REDACTED]") // reports PII (entity count > 0)
	defer philter.Close()
	bedrockSrv := bedrockJSONServer(t, "SSN 123-45-6789")

	proxy := newBedrockProxy(philter.URL, bedrockSrv.URL)
	proxy.config.Defaults.Outbound = OutboundConfig{Enabled: true, Action: "block"}

	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, bedrockReq())

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "outbound_blocked") {
		t.Errorf("expected outbound_blocked, got: %s", w.Body.String())
	}
}

// TestBedrock_OutboundScan_StreamingSkipped covers the streaming-skip branch of
// the outbound-scan path: a streaming Content-Type is passed through unscanned.
func TestBedrock_OutboundScan_StreamingSkipped(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()
	bedrockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("SSN 123-45-6789 (binary frames would be here)"))
	}))
	defer bedrockSrv.Close()

	proxy := newBedrockProxy(philter.URL, bedrockSrv.URL)
	proxy.config.Defaults.Outbound = OutboundConfig{Enabled: true, Action: "redact"}

	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, bedrockReq())

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "123-45-6789") {
		t.Errorf("streaming Bedrock response must pass through unscanned, got: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "[REDACTED]") {
		t.Errorf("streaming response must not be scanned/redacted, got: %s", w.Body.String())
	}
}

// --- Close() methods -----------------------------------------------------

func TestResponseCache_Close(t *testing.T) {
	c, err := newResponseCache(CacheConfig{}) // memory backend
	if err != nil {
		t.Fatalf("newResponseCache: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("memory cache Close() = %v, want nil", err)
	}
}

func TestUsageStore_Close(t *testing.T) {
	if err := newMemUsageStore().Close(); err != nil {
		t.Errorf("memory usage store Close() = %v, want nil", err)
	}
}
