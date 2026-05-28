package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fuzzHarness wires a Proxy against in-process mocks for Philter, the four
// HTTP providers, and Bedrock. Each fuzz iteration reuses the same harness;
// the mocks are deliberately stateless so iterations don't interfere with
// each other.
type fuzzHarness struct {
	proxy   *Proxy
	cleanup func()
}

func newFuzzHarness(tb testing.TB) *fuzzHarness {
	tb.Helper()

	// Philter mock: echo whatever was sent as the filtered text. This keeps
	// the proxy moving through redaction without imposing real PII rules,
	// which is what we want when fuzzing the *parser* paths.
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(explainJSON(string(body), "doc-id", nil))
	}))

	// Provider mock: return a canned 200. We don't validate the forwarded
	// body — that's the proxy's job and the fuzz iteration's invariant is
	// "no panic", not "produces a correct upstream call".
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"fuzz","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))

	u, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:          testConfig(philterSrv.URL),
		philter:         testPhilterClient(philterSrv.URL),
		openaiTarget:    u,
		anthropicTarget: u,
		geminiTarget:    u,
		ollamaTarget:    u,
		openaiClient:    http.DefaultClient,
		anthropicClient: http.DefaultClient,
		geminiClient:    http.DefaultClient,
		ollamaClient:    http.DefaultClient,
		bedrockRegion:   "us-east-1",
		bedrockCreds:    staticCreds("AKIAFUZZ", "secretfuzz"),
		bedrockClient:   &http.Client{Transport: &mockBedrockTransport{bedrockURL: providerSrv.URL}},
	}

	return &fuzzHarness{
		proxy: proxy,
		cleanup: func() {
			philterSrv.Close()
			providerSrv.Close()
		},
	}
}

// driveFuzz sends body through ServeHTTP and asserts the AC invariants from
// philterd-website#117:
//
//   - No panic escapes ServeHTTP (Go's fuzz runtime turns a panic into a
//     reported crash automatically; this function also recovers explicitly so
//     the failure message includes the offending input).
//   - The proxy writes *some* response — a missing status code would mean
//     ServeHTTP returned without calling WriteHeader.
//   - For any input, the status is never 5xx. In this harness Philter and the
//     provider mocks always succeed, so any 5xx would mean the proxy treated
//     malformed input as an internal error (the issue's exact failure mode).
//   - When the status is 4xx, the response body is structured JSON of the
//     shape {"error":{"message":"...","type":"..."}}.
func driveFuzz(t *testing.T, proxy *Proxy, path string, body []byte) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ServeHTTP panicked on path=%s body=%q: %v", path, body, r)
		}
	}()

	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code == 0 {
		t.Errorf("ServeHTTP wrote no status for path=%s body=%q", path, body)
		return
	}
	if w.Code >= 500 {
		t.Errorf("ServeHTTP returned 5xx status %d for path=%s body=%q (mocks always succeed in fuzz harness, so any 5xx is a proxy bug)", w.Code, path, body)
		return
	}
	if w.Code < 200 || w.Code >= 600 {
		t.Errorf("ServeHTTP produced an out-of-range status %d for path=%s body=%q", w.Code, path, body)
		return
	}

	if w.Code >= 400 {
		ct := w.Header().Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			t.Errorf("ServeHTTP returned %d with non-JSON Content-Type %q for path=%s body=%q", w.Code, ct, path, body)
			return
		}
		var parsed struct {
			Error struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
			t.Errorf("ServeHTTP returned %d with non-JSON body for path=%s body=%q: %v\nresponse: %s", w.Code, path, body, err, w.Body.String())
			return
		}
		if parsed.Error.Type == "" {
			t.Errorf("ServeHTTP returned %d with missing error.type for path=%s body=%q\nresponse: %s", w.Code, path, body, w.Body.String())
		}
	}
}

// TestParser_MalformedBody_StructuredError is the deterministic counterpart
// to the fuzz targets: it pins the structured-error contract for each parser
// path with a fixed input rather than relying on millions of random tries.
// If this test breaks, anything downstream that catches 4xx by JSON shape
// (clients, dashboards, the in-progress #115 work) will break too.
func TestParser_MalformedBody_StructuredError(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
	}{
		{"openai", "/v1/chat/completions", `{not json`},
		{"anthropic", "/v1/messages", `{not json`},
		{"gemini", "/v1beta/models/gemini-pro:generateContent", `{not json`},
		{"ollama-generate", "/api/generate", `{not json`},
		{"ollama-chat", "/api/chat", `{not json`},
		{"bedrock", "/model/anthropic.claude-3-sonnet/converse", `{not json`},
	}

	h := newFuzzHarness(t)
	defer h.cleanup()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.proxy.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for malformed body, got %d: %s", w.Code, w.Body.String())
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("expected JSON Content-Type, got %q", ct)
			}
			var resp struct {
				Error struct {
					Message string `json:"message"`
					Type    string `json:"type"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("response is not valid JSON: %v\nbody: %s", err, w.Body.String())
			}
			if resp.Error.Type != "invalid_request" {
				t.Errorf("expected error.type=invalid_request, got %q", resp.Error.Type)
			}
			if resp.Error.Message == "" {
				t.Error("expected non-empty error.message")
			}
		})
	}
}

// --- FuzzAnthropicRequest ---------------------------------------------------
//
// Anthropic's content field is the most polymorphic in the codebase: it can
// be a string, an array of typed blocks, and tool_result blocks themselves
// can carry either a string or an array of sub-blocks. Each level is parsed
// with a hand-rolled type switch in handleAnthropic — exactly the shape that
// fuzzing is good at probing.

func FuzzAnthropicRequest(f *testing.F) {
	h := newFuzzHarness(f)
	f.Cleanup(h.cleanup)

	f.Add([]byte(`{"model":"claude-3","messages":[{"role":"user","content":"hello"}]}`))
	f.Add([]byte(`{"model":"claude-3","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"system":"sys"}`))
	f.Add([]byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","content":"x"}]}]}`))
	f.Add([]byte(`{"messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":"x"}]}]}]}`))
	f.Add([]byte(`{"messages":[{"role":"user","content":[{"type":"text"}]}]}`))            // missing text field
	f.Add([]byte(`{"messages":[{"role":"user","content":[{"type":"unknown","text":"x"}]}]}`)) // unknown block type
	f.Add([]byte(`{"messages":[{"role":"user","content":42}]}`))                            // wrong type for content
	f.Add([]byte(`{"messages":[{"content":null}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, body []byte) {
		driveFuzz(t, h.proxy, "/v1/messages", body)
	})
}

// --- FuzzOpenAIToolCallArgs -------------------------------------------------
//
// Tool-call arguments are stringified JSON nested inside the message JSON.
// The proxy parses the outer envelope with json.Unmarshal, then parses each
// tool_call's Arguments string with json.Unmarshal again, then redacts
// recursively through interface{} values (see redactAny + redactJSONArguments).
// This double-parse is the most likely place for a malformed nested string to
// surprise the type switch.

func FuzzOpenAIToolCallArgs(f *testing.F) {
	h := newFuzzHarness(f)
	f.Cleanup(h.cleanup)

	f.Add([]byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`))
	f.Add([]byte(`{"model":"gpt-4","messages":[{"role":"assistant","tool_calls":[{"id":"1","type":"function","function":{"name":"x","arguments":"{}"}}]}]}`))
	f.Add([]byte(`{"model":"gpt-4","messages":[{"role":"assistant","tool_calls":[{"id":"1","type":"function","function":{"name":"x","arguments":"{\"a\":1,\"b\":[\"x\",\"y\"]}"}}]}]}`))
	f.Add([]byte(`{"model":"gpt-4","messages":[{"role":"tool","tool_call_id":"1","content":"result"}]}`))
	f.Add([]byte(`{"messages":[{"tool_calls":[{}]}]}`))
	f.Add([]byte(`{"messages":[{"tool_calls":[{"function":{"arguments":"not-json"}}]}]}`))
	f.Add([]byte(`{"messages":[{"tool_calls":[{"function":{"arguments":"{\"deep\":{\"deeper\":{\"deepest\":\"x\"}}}"}}]}]}`))
	f.Add([]byte(`{"messages":[{"tool_calls":[{"function":{"arguments":"[1,2,3,{\"k\":\"v\"}]"}}]}]}`))
	f.Add([]byte(`{"messages":[{"tool_calls":[{"function":{"arguments":""}}]}]}`))
	f.Add([]byte(`{"messages":[{"tool_calls":null}]}`))
	f.Add([]byte(`{"messages":[{"content":[1,2,3]}]}`)) // content as raw array, not a string

	f.Fuzz(func(t *testing.T, body []byte) {
		driveFuzz(t, h.proxy, "/v1/chat/completions", body)
	})
}

// --- FuzzGeminiRequest ------------------------------------------------------
//
// Gemini parts can carry either text or a functionResponse with an arbitrary
// nested response object. The functionResponse map is fed through redactAny,
// which recurses through map[string]any / []any and dispatches on the concrete
// type — another type-switch surface.

func FuzzGeminiRequest(f *testing.F) {
	h := newFuzzHarness(f)
	f.Cleanup(h.cleanup)

	f.Add([]byte(`{"contents":[{"parts":[{"text":"hello"}]}]}`))
	f.Add([]byte(`{"contents":[{"role":"user","parts":[{"text":"hi"},{"text":"there"}]}]}`))
	f.Add([]byte(`{"contents":[{"parts":[{"functionResponse":{"name":"x","response":{"a":1}}}]}]}`))
	f.Add([]byte(`{"contents":[{"parts":[{"functionResponse":{"name":"x","response":{"nested":{"a":["b","c"]}}}}]}]}`))
	f.Add([]byte(`{"contents":[{"parts":[{"functionResponse":{"name":"x","response":{}}}]}]}`))
	f.Add([]byte(`{"contents":[{"parts":[{"functionResponse":{"name":"x"}}]}]}`)) // response missing
	f.Add([]byte(`{"contents":[{"parts":[]}]}`))
	f.Add([]byte(`{"contents":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, body []byte) {
		driveFuzz(t, h.proxy, "/v1beta/models/gemini-pro:generateContent", body)
	})
}

// --- FuzzBedrockConverseRequest ---------------------------------------------
//
// Bedrock uses fixed-shape structs (BedrockConverseRequest), so the parser
// itself is less exotic than Anthropic or Gemini. The interesting surface is
// the per-message / per-system content loops that iterate slices and indices
// — out-of-bounds or wrong-shape inputs could surprise them.

func FuzzBedrockConverseRequest(f *testing.F) {
	h := newFuzzHarness(f)
	f.Cleanup(h.cleanup)

	f.Add([]byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`))
	f.Add([]byte(`{"messages":[{"role":"user","content":[{"text":"a"},{"text":"b"}]}],"system":[{"text":"sys"}]}`))
	f.Add([]byte(`{"messages":[]}`))
	f.Add([]byte(`{"messages":[{"content":[]}]}`))
	f.Add([]byte(`{"messages":[{"content":null}]}`))
	f.Add([]byte(`{"system":[{"text":""}],"messages":[{"role":"user","content":[{"text":""}]}]}`))
	f.Add([]byte(`{"inferenceConfig":{"maxTokens":1,"temperature":0.5},"messages":[{"role":"user","content":[{"text":"hi"}]}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, body []byte) {
		driveFuzz(t, h.proxy, "/model/anthropic.claude-3-sonnet/converse", body)
	})
}
