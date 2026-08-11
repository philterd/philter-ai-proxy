package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// multipartBody builds a form body and returns it with its Content-Type.
func multipartBody(t *testing.T, fields map[string]string) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String(), w.FormDataContentType()
}

func multipartProxy(t *testing.T) *Proxy {
	t.Helper()
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	t.Cleanup(philterSrv.Close)
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("provider must not be reached by an unsupported request")
	}))
	t.Cleanup(providerSrv.Close)

	u, _ := url.Parse(providerSrv.URL)
	return &Proxy{
		config:       testConfig(philterSrv.URL),
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
	}
}

// errorFields pulls the (type, code) pair and message out of an error response.
func errorFields(t *testing.T, body string) (errType, code, message string) {
	t.Helper()
	var resp struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, body)
	}
	return resp.Error.Type, resp.Error.Code, resp.Error.Message
}

func TestMultipart_FileUploadRejectedWithSpecificError(t *testing.T) {
	p := multipartProxy(t)
	body, ct := multipartBody(t, map[string]string{"purpose": "batch"})

	w := sendRequest(p, "/v1/files", body, map[string]string{"Content-Type": ct})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	errType, code, msg := errorFields(t, w.Body.String())
	if errType != "invalid_request" || code != "unsupported_content_type" {
		t.Errorf("got (%s, %s), want (invalid_request, unsupported_content_type)", errType, code)
	}
	if code == "bad_json" {
		t.Error("a well-formed multipart body must not be reported as malformed JSON")
	}
	if !strings.Contains(msg, "Philter") {
		t.Errorf("file-upload message should point at Philter for bulk redaction, got %q", msg)
	}
}

// The error must not be limited to /v1/files; siblings would still say bad_json.
func TestMultipart_OtherEndpointsGetTheSameError(t *testing.T) {
	for _, path := range []string{
		"/v1/audio/transcriptions",
		"/v1/audio/translations",
		"/v1/images/edits",
		"/v1/images/variations",
		"/v1/chat/completions",
	} {
		t.Run(path, func(t *testing.T) {
			p := multipartProxy(t)
			body, ct := multipartBody(t, map[string]string{"model": "whisper-1"})

			w := sendRequest(p, path, body, map[string]string{"Content-Type": ct})

			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", w.Code)
			}
			_, code, _ := errorFields(t, w.Body.String())
			if code != "unsupported_content_type" {
				t.Errorf("code = %q, want unsupported_content_type", code)
			}
		})
	}
}

// Only /v1/files should advise pre-redaction; #40 and #41 are tracked for support.
func TestMultipart_NonFileMessageDoesNotAdviseBulkRedaction(t *testing.T) {
	p := multipartProxy(t)
	body, ct := multipartBody(t, map[string]string{"model": "whisper-1"})

	w := sendRequest(p, "/v1/audio/transcriptions", body, map[string]string{"Content-Type": ct})
	_, _, msg := errorFields(t, w.Body.String())
	if strings.Contains(msg, "before uploading") {
		t.Errorf("audio message should not give file-upload advice, got %q", msg)
	}
	if !strings.Contains(msg, "multipart/form-data") {
		t.Errorf("message should name the unsupported content type, got %q", msg)
	}
}

// The new code must not swallow the case it was meant to be distinguished from.
func TestMultipart_MalformedJSONStillReportsBadJSON(t *testing.T) {
	p := multipartProxy(t)

	w := sendRequest(p, "/v1/chat/completions", `{"model":"gpt-4","messages":`,
		map[string]string{"Content-Type": "application/json"})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	_, code, _ := errorFields(t, w.Body.String())
	if code != "bad_json" {
		t.Errorf("code = %q, want bad_json for a genuinely malformed body", code)
	}
}

// Some clients omit Content-Type and still send valid JSON.
func TestMultipart_MissingContentTypeStillProxied(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()
	reached := false
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer providerSrv.Close()

	u, _ := url.Parse(providerSrv.URL)
	p := &Proxy{
		config:       testConfig(philterSrv.URL),
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
	}

	w := sendRequest(p, "/v1/chat/completions", openAIBody(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !reached {
		t.Error("provider should have been reached")
	}
}

// 401 must win, so the endpoint list is not disclosed pre-auth.
func TestMultipart_AuthStillTakesPrecedence(t *testing.T) {
	p := multipartProxy(t)
	p.keyStore = testKeyStore(map[string]string{"the-valid-key": ""})
	body, ct := multipartBody(t, map[string]string{"purpose": "batch"})

	w := sendRequest(p, "/v1/files", body, map[string]string{"Content-Type": ct})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 for an unauthenticated request, got %d", w.Code)
	}
}

func TestIsMultipartRequest(t *testing.T) {
	cases := []struct {
		contentType string
		want        bool
	}{
		{"multipart/form-data; boundary=abc", true},
		{"MULTIPART/FORM-DATA; boundary=abc", true},
		{"multipart/form-data", true},
		{"application/json", false},
		{"application/json; charset=utf-8", false},
		{"", false},
		{"not a media type", false},
		{"multipart/mixed; boundary=abc", false},
	}
	for _, tc := range cases {
		if got := isMultipartRequest(tc.contentType); got != tc.want {
			t.Errorf("isMultipartRequest(%q) = %v, want %v", tc.contentType, got, tc.want)
		}
	}
}
