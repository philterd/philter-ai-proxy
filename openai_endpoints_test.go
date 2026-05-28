package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClassifyOpenAIEndpoint(t *testing.T) {
	cases := map[string]openAIEndpoint{
		"/v1/chat/completions":                       epChat,
		"/openai/deployments/gpt4o/chat/completions": epChat,
		"/v1/responses":                              epResponses,
		"/v1/embeddings":                             epEmbeddings,
		"/openai/deployments/embed/embeddings":       epEmbeddings,
		"/v1/moderations":                            epModerations,
		"/v1/images/generations":                     epImageGen,
		"/v1/audio/speech":                           epAudioSpeech,
		"/v1/completions":                            epCompletions, // legacy, not chat
		"/v1/batches":                                epPassthrough,
		"/v1/files":                                  epPassthrough,
	}
	for path, want := range cases {
		if got := classifyOpenAIEndpoint(path); got != want {
			t.Errorf("classifyOpenAIEndpoint(%q) = %d, want %d", path, got, want)
		}
	}
}

// redactCapture proxies an OpenAI-style request through ServeHTTP with a Philter
// mock that replaces every filtered string with "REDACTED", and captures the
// body forwarded to the provider.
func redactCapture(t *testing.T, path, body string) string {
	t.Helper()
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	t.Cleanup(philterSrv.Close)

	var forwarded string
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		forwarded = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(providerSrv.Close)

	cfg := testConfig(philterSrv.URL)
	u, _ := url.Parse(providerSrv.URL)
	p := &Proxy{config: cfg, philter: testPhilterClient(philterSrv.URL), openaiTarget: u, openaiClient: http.DefaultClient}

	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: want 200, got %d", path, w.Code)
	}
	return forwarded
}

func TestEmbeddings_StringInputRedacted(t *testing.T) {
	out := redactCapture(t, "/v1/embeddings", `{"model":"text-embedding-3-small","input":"my SSN is 123-45-6789","encoding_format":"float"}`)
	if strings.Contains(out, "123-45-6789") {
		t.Errorf("embeddings input not redacted: %s", out)
	}
	if !strings.Contains(out, "REDACTED") {
		t.Errorf("expected redacted input: %s", out)
	}
	// Non-text fields preserved.
	if !strings.Contains(out, `"encoding_format":"float"`) || !strings.Contains(out, `"model":"text-embedding-3-small"`) {
		t.Errorf("non-text fields not preserved: %s", out)
	}
}

func TestEmbeddings_ArrayInputRedacted(t *testing.T) {
	out := redactCapture(t, "/v1/embeddings", `{"model":"m","input":["John Smith","Jane Doe"]}`)
	if strings.Contains(out, "John Smith") || strings.Contains(out, "Jane Doe") {
		t.Errorf("array input not redacted: %s", out)
	}
}

func TestEmbeddings_TokenArrayLeftUntouched(t *testing.T) {
	// Token-ID inputs (integers) carry no text and must pass through unchanged.
	out := redactCapture(t, "/v1/embeddings", `{"model":"m","input":[123,456,789]}`)
	for _, tok := range []string{"123", "456", "789"} {
		if !strings.Contains(out, tok) {
			t.Errorf("token id %s should be preserved: %s", tok, out)
		}
	}
}

func TestResponsesAPI_StringInputAndInstructionsRedacted(t *testing.T) {
	out := redactCapture(t, "/v1/responses", `{"model":"gpt-4o","instructions":"you help John Smith","input":"my email is a@b.com"}`)
	if strings.Contains(out, "John Smith") || strings.Contains(out, "a@b.com") {
		t.Errorf("responses input/instructions not redacted: %s", out)
	}
}

func TestResponsesAPI_ArrayInputRedacted(t *testing.T) {
	body := `{"model":"gpt-4o","input":[{"role":"user","content":[{"type":"input_text","text":"my phone is 555-1234"}]}]}`
	out := redactCapture(t, "/v1/responses", body)
	if strings.Contains(out, "555-1234") {
		t.Errorf("responses array input text not redacted: %s", out)
	}
}

func TestModerations_InputRedacted(t *testing.T) {
	out := redactCapture(t, "/v1/moderations", `{"input":"contact me at evil@example.com"}`)
	if strings.Contains(out, "evil@example.com") {
		t.Errorf("moderations input not redacted: %s", out)
	}
}

func TestImageGeneration_PromptRedacted(t *testing.T) {
	out := redactCapture(t, "/v1/images/generations", `{"model":"dall-e-3","prompt":"a portrait of John Smith","size":"1024x1024"}`)
	if strings.Contains(out, "John Smith") {
		t.Errorf("image prompt not redacted: %s", out)
	}
	if !strings.Contains(out, `"size":"1024x1024"`) {
		t.Errorf("non-text field not preserved: %s", out)
	}
}

func TestAudioSpeech_InputRedacted(t *testing.T) {
	out := redactCapture(t, "/v1/audio/speech", `{"model":"tts-1","voice":"alloy","input":"call John at 555-9999"}`)
	if strings.Contains(out, "555-9999") {
		t.Errorf("audio speech input not redacted: %s", out)
	}
	if !strings.Contains(out, `"voice":"alloy"`) {
		t.Errorf("non-text field not preserved: %s", out)
	}
}

func TestLegacyCompletions_PromptRedacted(t *testing.T) {
	out := redactCapture(t, "/v1/completions", `{"model":"gpt-3.5-turbo-instruct","prompt":"SSN 123-45-6789"}`)
	if strings.Contains(out, "123-45-6789") {
		t.Errorf("legacy completions prompt not redacted: %s", out)
	}
}

func TestBatch_PassthroughUnchanged(t *testing.T) {
	// Batch requests reference an uploaded file; no inline prompt to redact.
	body := `{"input_file_id":"file-abc","endpoint":"/v1/chat/completions","completion_window":"24h"}`
	out := redactCapture(t, "/v1/batches", body)
	if !strings.Contains(out, `"input_file_id":"file-abc"`) {
		t.Errorf("batch body should pass through unchanged: %s", out)
	}
}

func TestResponsesAPI_TokenUsageParsed(t *testing.T) {
	// Responses API reports input_tokens/output_tokens (not prompt/completion).
	p, c := extractTokenUsage("openai", []byte(`{"usage":{"input_tokens":12,"output_tokens":7}}`))
	if p != 12 || c != 7 {
		t.Errorf("responses usage = (%d,%d), want (12,7)", p, c)
	}
}

func TestEmbeddings_TokenUsageParsed(t *testing.T) {
	// Embeddings report prompt_tokens + total_tokens, no completion.
	p, c := extractTokenUsage("openai", []byte(`{"usage":{"prompt_tokens":9,"total_tokens":9}}`))
	if p != 9 || c != 0 {
		t.Errorf("embeddings usage = (%d,%d), want (9,0)", p, c)
	}
}

// redactCaptureSelective is like redactCapture but uses a Philter mock that only
// redacts the given PII substrings (echoing every other string unchanged), so
// tests can assert that structural fields survive realistic redaction.
func redactCaptureSelective(t *testing.T, proxy *Proxy, philterSrv *httptest.Server, providerBody *string, path, body string, pii ...string) string {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: want 200, got %d (%s)", path, w.Code, w.Body.String())
	}
	return *providerBody
}

func newSelectiveRedactProxy(t *testing.T, pii ...string) (*Proxy, *httptest.Server, *string) {
	t.Helper()
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in, _ := io.ReadAll(r.Body)
		out := string(in)
		for _, p := range pii {
			out = strings.ReplaceAll(out, p, "REDACTED")
		}
		w.Write(explainJSON(out, "doc-id", nil))
	}))
	t.Cleanup(philterSrv.Close)

	var forwarded string
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		forwarded = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(providerSrv.Close)

	cfg := testConfig(philterSrv.URL)
	u, _ := url.Parse(providerSrv.URL)
	p := &Proxy{config: cfg, philter: testPhilterClient(philterSrv.URL), openaiTarget: u, openaiClient: http.DefaultClient}
	return p, philterSrv, &forwarded
}

// TestResponsesAPI_StructuralFieldsSurvive proves that redacting the Responses
// `input` array (via the recursive redactor) removes PII from text values while
// leaving structural enum values like role/type intact — the realistic case
// where Philter redacts only true PII.
func TestResponsesAPI_StructuralFieldsSurvive(t *testing.T) {
	p, philterSrv, fwd := newSelectiveRedactProxy(t, "555-1234")
	body := `{"model":"gpt-4o","input":[{"role":"user","content":[{"type":"input_text","text":"my phone is 555-1234"}]}]}`
	out := redactCaptureSelective(t, p, philterSrv, fwd, "/v1/responses", body, "555-1234")

	if strings.Contains(out, "555-1234") {
		t.Errorf("PII not redacted: %s", out)
	}
	if !strings.Contains(out, `"role":"user"`) {
		t.Errorf("structural field role corrupted: %s", out)
	}
	if !strings.Contains(out, `"type":"input_text"`) {
		t.Errorf("structural field type corrupted: %s", out)
	}
}

// TestOpenAICompatible_EmbeddingsRedacted covers criterion 1's "across ...
// OpenAI-compatible providers": an embeddings request to a configured
// openai-compatible provider is redacted after prefix stripping.
func TestOpenAICompatible_EmbeddingsRedacted(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterSrv.Close()
	var forwarded string
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		forwarded = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer providerSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Providers.OpenAICompatible = map[string]ProviderConfig{"mistral": {Target: providerSrv.URL}}
	u, _ := url.Parse(providerSrv.URL)
	p := &Proxy{
		config:                  cfg,
		philter:                 testPhilterClient(philterSrv.URL),
		openaiCompatibleTargets: map[string]*url.URL{"mistral": u},
		openaiCompatibleClients: map[string]*http.Client{"mistral": http.DefaultClient},
	}

	req := httptest.NewRequest("POST", "/mistral/v1/embeddings", strings.NewReader(`{"model":"mistral-embed","input":"my SSN is 123-45-6789"}`))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if strings.Contains(forwarded, "123-45-6789") {
		t.Errorf("openai-compatible embeddings input not redacted: %s", forwarded)
	}
}
