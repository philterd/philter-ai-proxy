// stub-provider is a tiny HTTP server that serves OpenAI-shape and
// Anthropic-shape responses for the load-test harness. The real LLM providers
// charge money and rate-limit us; this stub is enough to exercise the proxy's
// JSON parsing, redaction, response-forwarding, and streaming code paths
// without leaving the laptop.
//
// Endpoints:
//
//	POST /v1/chat/completions          OpenAI non-streaming
//	POST /v1/chat/completions?stream=1 OpenAI SSE stream
//	POST /v1/messages                  Anthropic non-streaming
//	POST /v1/messages?stream=1         Anthropic SSE stream
//
// Knobs:
//
//	delay=200ms     - sleep before responding (server-side latency)
//	chunks=8        - number of SSE chunks for streaming endpoints
//	chunk_delay=10ms - delay between chunks
//
// Defaults: 0ms delay, 4 chunks, 10ms chunk_delay.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	addr := envDefault("LISTEN_ADDR", ":8090")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", openAIHandler)
	mux.HandleFunc("/v1/messages", anthropicHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	log.Printf("stub-provider listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func openAIHandler(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body) // drain so the proxy's writes don't block
	r.Body.Close()
	if d := parseDuration(r, "delay", 0); d > 0 {
		time.Sleep(d)
	}
	if r.URL.Query().Get("stream") == "1" {
		streamOpenAI(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"id":      "chatcmpl-stub",
		"object":  "chat.completion",
		"model":   "stub-model",
		"choices": []any{map[string]any{
			"index":         0,
			"finish_reason": "stop",
			"message": map[string]any{
				"role":    "assistant",
				"content": "Hello from the stub provider. Patient SSN 999-99-9999 should not survive outbound scanning.",
			},
		}},
		"usage": map[string]any{
			"prompt_tokens":     42,
			"completion_tokens": 24,
			"total_tokens":      66,
		},
	})
}

func anthropicHandler(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if d := parseDuration(r, "delay", 0); d > 0 {
		time.Sleep(d)
	}
	if r.URL.Query().Get("stream") == "1" {
		streamAnthropic(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"id":          "msg_stub",
		"type":        "message",
		"role":        "assistant",
		"model":       "stub-model",
		"stop_reason": "end_turn",
		"content": []any{map[string]any{
			"type": "text",
			"text": "Hello from the stub provider. Patient SSN 999-99-9999 should not survive outbound scanning.",
		}},
		"usage": map[string]any{
			"input_tokens":  42,
			"output_tokens": 24,
		},
	})
}

func streamOpenAI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	chunks := parseInt(r, "chunks", 4)
	delay := parseDuration(r, "chunk_delay", 10*time.Millisecond)
	tokens := []string{"Hello", " from", " the", " stub", " provider", " with", " streaming", " enabled"}

	for i := 0; i < chunks; i++ {
		tok := tokens[i%len(tokens)]
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q}}]}\n\n", tok)
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(delay)
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func streamAnthropic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	chunks := parseInt(r, "chunks", 4)
	delay := parseDuration(r, "chunk_delay", 10*time.Millisecond)
	tokens := []string{"Hello", " from", " the", " stub", " provider"}

	for i := 0; i < chunks; i++ {
		tok := tokens[i%len(tokens)]
		fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":%q}}\n\n", tok)
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(delay)
	}
	fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func parseDuration(r *http.Request, key string, def time.Duration) time.Duration {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func parseInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
