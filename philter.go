package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// --- Philter API types -------------------------------------------------------

type Span struct {
	FilterType string  `json:"filterType"`
	Confidence float64 `json:"confidence"`
}

type Explanation struct {
	AppliedSpans []Span `json:"appliedSpans"`
}

type ExplainResponse struct {
	FilteredText string      `json:"filteredText"`
	Context      string      `json:"context"`
	DocumentId   string      `json:"documentId"`
	Explanation  Explanation `json:"explanation"`
}

type FilterResponse struct {
	FilteredText     string
	Context          string
	DocumentId       string
	EntityCount      int
	EntityTypes      []string
	EntityTypeCounts map[string]int
	Latency          time.Duration
}

// --- Circuit breaker ---------------------------------------------------------

// CircuitOpenError is returned when the circuit breaker is open and the fallback action is "block".
type CircuitOpenError struct{}

func (e *CircuitOpenError) Error() string {
	return "philter circuit breaker is open"
}

type cbState int

const (
	cbStateClosed   cbState = iota
	cbStateOpen
	cbStateHalfOpen
)

type circuitBreaker struct {
	mu           sync.Mutex
	state        cbState
	failures     int
	threshold    int
	openedAt     time.Time
	probeTimeout time.Duration
	fallback     string // "block" or "passthrough"
}

func newCircuitBreaker(threshold int, probeTimeout time.Duration, fallback string) *circuitBreaker {
	return &circuitBreaker{
		state:        cbStateClosed,
		threshold:    threshold,
		probeTimeout: probeTimeout,
		fallback:     fallback,
	}
}

// allow returns whether the request should proceed and, if not, which fallback applies.
func (cb *circuitBreaker) allow() (allowed bool, fallback string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case cbStateClosed:
		return true, ""
	case cbStateOpen:
		if time.Since(cb.openedAt) >= cb.probeTimeout {
			cb.state = cbStateHalfOpen
			return true, ""
		}
		return false, cb.fallback
	case cbStateHalfOpen:
		return true, ""
	}
	return true, ""
}

func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = cbStateClosed
}

func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	if cb.state == cbStateHalfOpen || cb.failures >= cb.threshold {
		cb.state = cbStateOpen
		cb.openedAt = time.Now()
	}
}

// State returns the name of the current state ("closed", "open", "half-open").
func (cb *circuitBreaker) State() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case cbStateClosed:
		return "closed"
	case cbStateOpen:
		return "open"
	case cbStateHalfOpen:
		return "half-open"
	}
	return "unknown"
}

// blocking reports whether the breaker is currently rejecting requests with
// the "block" fallback. Half-open is treated as serving (a probe goes
// through); only the open+block state means the proxy will return 503 to
// every request that arrives.
func (cb *circuitBreaker) blocking() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state == cbStateOpen && cb.fallback == "block"
}

// --- PhilterClient -----------------------------------------------------------

// filterFunc is a Philter call abstraction used by redactAny and redactJSONArguments.
type filterFunc func(input, ctx, docID, policy string) (FilterResponse, error)

// PhilterClient wraps an HTTP client with retry and circuit breaker logic.
type PhilterClient struct {
	httpClient   *http.Client
	endpoint     string
	maxAttempts  int
	initialDelay time.Duration
	maxDelay     time.Duration
	cb           *circuitBreaker
}

func newPhilterClient(httpClient *http.Client, endpoint string, retryCfg RetryConfig, cbCfg CircuitBreakerConfig) *PhilterClient {
	pc := &PhilterClient{
		httpClient:   httpClient,
		endpoint:     endpoint,
		maxAttempts:  retryCfg.MaxAttempts,
		initialDelay: time.Duration(retryCfg.InitialBackoffMs) * time.Millisecond,
		maxDelay:     time.Duration(retryCfg.MaxBackoffMs) * time.Millisecond,
	}
	if pc.maxAttempts <= 0 {
		pc.maxAttempts = 1
	}
	if cbCfg.Enabled {
		threshold := cbCfg.Threshold
		if threshold <= 0 {
			threshold = 5
		}
		timeout := time.Duration(cbCfg.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		fallback := cbCfg.Fallback
		if fallback == "" {
			fallback = "block"
		}
		pc.cb = newCircuitBreaker(threshold, timeout, fallback)
	}
	return pc
}

// Ready reports whether the client can currently serve traffic. The only
// state that returns false is "circuit breaker is open AND its fallback is
// block" - i.e. every request that arrives right now will be rejected. With
// no breaker configured, or with the breaker closed/half-open, or with the
// breaker open and fallback=passthrough, the client is considered ready
// (individual requests may still fail; the proxy is just not categorically
// down).
//
// Used by the /readyz handler so transient Philter blips don't cause
// Kubernetes to restart healthy pods.
func (pc *PhilterClient) Ready() bool {
	if pc == nil || pc.cb == nil {
		return true
	}
	return !pc.cb.blocking()
}

// Filter calls the Philter /api/explain endpoint with retry and circuit breaker logic.
// It satisfies the filterFunc type when used as a method value (pc.Filter).
func (pc *PhilterClient) Filter(input, ctx, docID, policy string) (FilterResponse, error) {
	if pc.cb != nil {
		allowed, fallback := pc.cb.allow()
		if !allowed {
			if fallback == "passthrough" {
				slog.Warn("Philter circuit breaker open, forwarding unredacted", "document_id", docID)
				return FilterResponse{FilteredText: input}, nil
			}
			return FilterResponse{}, &CircuitOpenError{}
		}
	}

	var lastErr error
	delay := pc.initialDelay

	for attempt := 0; attempt < pc.maxAttempts; attempt++ {
		if attempt > 0 {
			sleep := delay
			if jitterRange := int64(delay / 2); jitterRange > 0 {
				sleep += time.Duration(rand.Int63n(jitterRange))
			}
			time.Sleep(sleep)
			delay *= 2
			if delay > pc.maxDelay {
				delay = pc.maxDelay
			}
		}

		fr, statusCode, err := filterHTTP(pc.httpClient, pc.endpoint, input, ctx, docID, policy)
		if err == nil {
			if pc.cb != nil {
				pc.cb.recordSuccess()
			}
			return fr, nil
		}
		lastErr = err

		if !isTransientError(statusCode, err) {
			break
		}
	}

	if pc.cb != nil {
		pc.cb.recordFailure()
	}
	return FilterResponse{}, lastErr
}

// filterHTTP performs a single HTTP call to the Philter /api/explain endpoint.
// Returns (response, httpStatusCode, error). statusCode is 0 for network-level errors.
func filterHTTP(client *http.Client, endpoint, input, ctx, docID, policy string) (FilterResponse, int, error) {
	base, err := url.Parse(endpoint + "/api/explain")
	if err != nil {
		return FilterResponse{}, 0, fmt.Errorf("failed to parse Philter endpoint: %w", err)
	}

	params := url.Values{}
	params.Add("c", ctx)
	params.Add("d", docID)
	params.Add("p", policy)
	base.RawQuery = params.Encode()

	request, err := http.NewRequest("POST", base.String(), bytes.NewReader([]byte(input)))
	if err != nil {
		return FilterResponse{}, 0, fmt.Errorf("failed to create Philter request: %w", err)
	}
	request.Header.Add("Content-Type", "text/plain")

	start := time.Now()
	response, err := client.Do(request)
	latency := time.Since(start)
	if err != nil {
		return FilterResponse{}, 0, fmt.Errorf("Philter request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return FilterResponse{}, response.StatusCode, fmt.Errorf("Philter returned HTTP %d", response.StatusCode)
	}

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return FilterResponse{}, response.StatusCode, fmt.Errorf("failed to read Philter response: %w", err)
	}

	var explainResp ExplainResponse
	if err := json.Unmarshal(responseData, &explainResp); err != nil {
		return FilterResponse{}, response.StatusCode, fmt.Errorf("failed to parse Philter response: %w", err)
	}

	typesSet := make(map[string]struct{})
	typeCounts := make(map[string]int)
	for _, span := range explainResp.Explanation.AppliedSpans {
		typesSet[span.FilterType] = struct{}{}
		typeCounts[span.FilterType]++
	}
	entityTypes := make([]string, 0, len(typesSet))
	for t := range typesSet {
		entityTypes = append(entityTypes, t)
	}

	return FilterResponse{
		FilteredText:     explainResp.FilteredText,
		Context:          explainResp.Context,
		DocumentId:       explainResp.DocumentId,
		EntityCount:      len(explainResp.Explanation.AppliedSpans),
		EntityTypes:      entityTypes,
		EntityTypeCounts: typeCounts,
		Latency:          latency,
	}, response.StatusCode, nil
}

// isTransientError returns true if the error is worth retrying.
// HTTP 5xx responses and network-level errors are considered transient.
func isTransientError(statusCode int, err error) bool {
	if statusCode >= 500 {
		return true
	}
	if statusCode > 0 {
		return false // 4xx or other non-zero: not transient
	}
	// statusCode == 0 means network-level error
	var netErr net.Error
	return errors.As(err, &netErr)
}

// Filter is a backward-compatible wrapper around filterHTTP for direct use in tests and simple callers.
// Production code should use PhilterClient.Filter for retry and circuit breaker support.
func Filter(client *http.Client, endpoint, input, ctx, docID, policy string) (FilterResponse, error) {
	fr, _, err := filterHTTP(client, endpoint, input, ctx, docID, policy)
	return fr, err
}
