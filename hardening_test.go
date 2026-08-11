package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// hardeningProxy builds a proxy with the given listen config and working Philter
// + provider mocks.
func hardeningProxy(t *testing.T, listen ListenConfig) *Proxy {
	t.Helper()
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	t.Cleanup(philterSrv.Close)
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	t.Cleanup(providerSrv.Close)

	cfg := testConfig(philterSrv.URL)
	cfg.Listen = listen
	u, _ := url.Parse(providerSrv.URL)
	return &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
	}
}

func bodyOfSize(n int) string {
	// A valid-ish chat body padded to exceed n bytes via the message content.
	pad := strings.Repeat("a", n)
	return `{"model":"gpt-4o","messages":[{"role":"user","content":"` + pad + `"}]}`
}

func TestHardening_OversizedBodyRejectedWith413(t *testing.T) {
	// Tiny 1 KiB cap; send ~2 KiB.
	p := hardeningProxy(t, ListenConfig{MaxRequestBodyBytes: 1024})
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(bodyOfSize(2048)))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "payload_too_large") || !strings.Contains(body, "request_body_too_large") {
		t.Errorf("expected structured 413 error, got: %s", body)
	}
}

func TestHardening_UnderLimitAllowed(t *testing.T) {
	p := hardeningProxy(t, ListenConfig{MaxRequestBodyBytes: 1 << 20}) // 1 MiB cap
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(bodyOfSize(1024)))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("body under the cap should pass, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHardening_DefaultLimitApplied(t *testing.T) {
	// No MaxRequestBodyBytes set → default (10 MiB) applies.
	p := hardeningProxy(t, ListenConfig{})
	if got := p.config.Listen.effectiveMaxRequestBodyBytes(); got != DefaultMaxRequestBodyBytes {
		t.Fatalf("default cap = %d, want %d", got, DefaultMaxRequestBodyBytes)
	}
	// A body well over the default is rejected.
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(bodyOfSize(DefaultMaxRequestBodyBytes+1024)))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("body over the default cap should be 413, got %d", w.Code)
	}
}

func TestEffectiveMaxRequestBodyBytes(t *testing.T) {
	if got := (ListenConfig{}).effectiveMaxRequestBodyBytes(); got != DefaultMaxRequestBodyBytes {
		t.Errorf("unset = %d, want default %d", got, DefaultMaxRequestBodyBytes)
	}
	if got := (ListenConfig{MaxRequestBodyBytes: 4096}).effectiveMaxRequestBodyBytes(); got != 4096 {
		t.Errorf("configured = %d, want 4096", got)
	}
}

func TestHardenedServer_DefaultsAndOverrides(t *testing.T) {
	// Defaults applied when unset.
	srv := hardenedServer(":8080", http.NewServeMux(), ListenConfig{})
	if srv.ReadHeaderTimeout != time.Duration(DefaultReadHeaderTimeoutMs)*time.Millisecond {
		t.Errorf("default ReadHeaderTimeout = %v", srv.ReadHeaderTimeout)
	}
	if srv.MaxHeaderBytes != DefaultMaxHeaderBytes {
		t.Errorf("default MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
	if srv.ReadTimeout != 0 {
		t.Errorf("ReadTimeout should be unset by default, got %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout must stay 0 so streaming responses are unbounded, got %v", srv.WriteTimeout)
	}

	// Overrides honored.
	srv = hardenedServer(":8080", http.NewServeMux(), ListenConfig{
		ReadHeaderTimeoutMs: 3000,
		MaxHeaderBytes:      4096,
		ReadTimeoutMs:       9000,
	})
	if srv.ReadHeaderTimeout != 3*time.Second {
		t.Errorf("override ReadHeaderTimeout = %v", srv.ReadHeaderTimeout)
	}
	if srv.MaxHeaderBytes != 4096 {
		t.Errorf("override MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
	if srv.ReadTimeout != 9*time.Second {
		t.Errorf("override ReadTimeout = %v", srv.ReadTimeout)
	}
}

// TestHardening_OversizedBody_EndToEnd drives the full HTTP stack (a real
// server + real client connection), not just ServeHTTP, so the actual
// MaxBytesReader/413 behavior is exercised end to end.
func TestHardening_OversizedBody_EndToEnd(t *testing.T) {
	p := hardeningProxy(t, ListenConfig{MaxRequestBodyBytes: 1024})
	srv := httptest.NewServer(p)
	defer srv.Close()

	// Oversized → 413 with the structured error.
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(bodyOfSize(4096)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: want 413, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "request_body_too_large") {
		t.Errorf("expected structured 413 body, got: %s", string(b))
	}

	// A small request still succeeds through the same server.
	resp2, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(bodyOfSize(64)))
	if err != nil {
		t.Fatalf("post small: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("small body should pass, got %d", resp2.StatusCode)
	}
}

func TestValidateConfig_HardeningNegativeRejected(t *testing.T) {
	for _, mut := range []func(*Config){
		func(c *Config) { c.Listen.MaxRequestBodyBytes = -1 },
		func(c *Config) { c.Listen.MaxHeaderBytes = -1 },
		func(c *Config) { c.Listen.ReadHeaderTimeoutMs = -1 },
		func(c *Config) { c.Listen.ReadTimeoutMs = -1 },
		func(c *Config) { c.Listen.TLSHandshakeTimeoutMs = -1 },
		func(c *Config) { c.Listen.MaxConcurrentTLSHandshakes = -1 },
	} {
		cfg := defaultConfig()
		mut(cfg)
		if err := validateConfig(cfg); err == nil {
			t.Error("expected validation error for negative hardening value")
		}
	}
}

func TestEffectiveTLSHandshakeTimeout(t *testing.T) {
	if got := (ListenConfig{}).effectiveTLSHandshakeTimeout(); got != time.Duration(DefaultListenTLSHandshakeTimeoutMs)*time.Millisecond {
		t.Errorf("unset = %v, want default %v", got, time.Duration(DefaultListenTLSHandshakeTimeoutMs)*time.Millisecond)
	}
	if got := (ListenConfig{TLSHandshakeTimeoutMs: 2500}).effectiveTLSHandshakeTimeout(); got != 2500*time.Millisecond {
		t.Errorf("configured = %v, want 2.5s", got)
	}
}

// TestHandshakeTimeoutListener_DropsSlowHandshake drives a full HTTPS server
// wrapped with the listener and dials a raw TCP connection that never sends
// any TLS bytes. The server must close the conn once the handshake deadline
// passes.
func TestHandshakeTimeoutListener_DropsSlowHandshake(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	certPEM, keyPEM := genSelfSignedForTest(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	wrapped := newHandshakeTimeoutListener(tls.NewListener(tcpLn, tlsCfg), 100*time.Millisecond, 0, nil)

	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go srv.Serve(wrapped)
	defer srv.Close()

	addr := tcpLn.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Don't send any TLS handshake bytes. The server should close us after the
	// handshake deadline (100ms). Read with a generous bound so we observe the
	// close even if the deadline fires slightly later than 100ms.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	start := time.Now()
	_, err = conn.Read(buf)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected the server to drop the slow-handshake connection, got read error nil")
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("connection dropped too late (%v); deadline did not fire", elapsed)
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("connection dropped before deadline (%v)", elapsed)
	}
}

// TestHandshakeTimeoutListener_EstablishedConnUnaffected confirms that once
// the TLS handshake completes, request reads and response writes are not
// bounded by the handshake deadline.
func TestHandshakeTimeoutListener_EstablishedConnUnaffected(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	certPEM, keyPEM := genSelfSignedForTest(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	wrapped := newHandshakeTimeoutListener(tls.NewListener(tcpLn, tlsCfg), 200*time.Millisecond, 0, nil)

	srv := &http.Server{
		// Sleep longer than the handshake timeout to prove that, post-
		// handshake, the deadline no longer constrains the connection.
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(500 * time.Millisecond)
			w.Write([]byte("ok"))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go srv.Serve(wrapped)
	defer srv.Close()

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("https://" + tcpLn.Addr().String() + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", string(body))
	}
}

// TestHandshakeTimeoutListener_SlowHandshakeDoesNotStallOtherAccepts is the
// DoS-resilience check: a stalled handshake on one conn must not block accepts
// of other conns. We open one slow client, then verify a second client can
// still complete a handshake well within the slow-client's deadline.
func TestHandshakeTimeoutListener_SlowHandshakeDoesNotStallOtherAccepts(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	certPEM, keyPEM := genSelfSignedForTest(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	wrapped := newHandshakeTimeoutListener(tls.NewListener(tcpLn, tlsCfg), 2*time.Second, 0, nil)

	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go srv.Serve(wrapped)
	defer srv.Close()

	// Slow client: open TCP, never send TLS bytes.
	slow, err := net.Dial("tcp", tcpLn.Addr().String())
	if err != nil {
		t.Fatalf("dial slow: %v", err)
	}
	defer slow.Close()

	// Fast client should complete its handshake and request quickly.
	client := &http.Client{
		Timeout: 1 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	start := time.Now()
	resp, err := client.Get("https://" + tcpLn.Addr().String() + "/")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("fast client failed while slow client was stalling: %v", err)
	}
	defer resp.Body.Close()
	if elapsed > 800*time.Millisecond {
		t.Errorf("fast client took %v -- slow handshake stalled accept loop", elapsed)
	}
}

func TestEffectiveMaxConcurrentTLSHandshakes(t *testing.T) {
	if got := (ListenConfig{}).effectiveMaxConcurrentTLSHandshakes(); got != DefaultMaxConcurrentTLSHandshakes {
		t.Errorf("unset = %d, want default %d", got, DefaultMaxConcurrentTLSHandshakes)
	}
	if got := (ListenConfig{MaxConcurrentTLSHandshakes: 4}).effectiveMaxConcurrentTLSHandshakes(); got != 4 {
		t.Errorf("configured = %d, want 4", got)
	}
}

// newTLSTestServer builds an HTTPS server wrapped with a handshakeTimeoutListener
// using the given handshake timeout, concurrency ceiling, and shed callback. It
// returns the listen address and registers cleanup.
func newTLSTestServer(t *testing.T, timeout time.Duration, maxConcurrent int, onShed, onSlotAcquired func(), handler http.HandlerFunc) string {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	certPEM, keyPEM := genSelfSignedForTest(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	wrapped := newHandshakeTimeoutListenerWithHook(tls.NewListener(tcpLn, tlsCfg), timeout, maxConcurrent, onShed, onSlotAcquired)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go srv.Serve(wrapped)
	t.Cleanup(func() { srv.Close() })
	return tcpLn.Addr().String()
}

// TestHandshakeTimeoutListener_UnderCapUnaffected confirms that with handshake
// concurrency headroom, ordinary clients complete requests and nothing is shed.
func TestHandshakeTimeoutListener_UnderCapUnaffected(t *testing.T) {
	var shed int64
	addr := newTLSTestServer(t, 2*time.Second, 8, func() { atomic.AddInt64(&shed, 1) }, nil,
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	for i := 0; i < 6; i++ {
		resp, err := client.Get("https://" + addr + "/")
		if err != nil {
			t.Fatalf("request %d failed under cap: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "ok" {
			t.Errorf("request %d body = %q, want ok", i, string(body))
		}
	}
	if got := atomic.LoadInt64(&shed); got != 0 {
		t.Errorf("shed = %d under cap, want 0", got)
	}
}

// TestHandshakeTimeoutListener_OverCapSheds is the DoS backstop: with the
// ceiling set to 1 and a stalled handshake holding the only slot, a second
// incoming connection is dropped immediately and the shed callback fires.
func TestHandshakeTimeoutListener_OverCapSheds(t *testing.T) {
	var shed int64
	slotAcquired := make(chan struct{}, 1)
	// Long handshake timeout so the stalled conn keeps its slot for the test.
	addr := newTLSTestServer(t, 3*time.Second, 1,
		func() { atomic.AddInt64(&shed, 1) },
		func() {
			select {
			case slotAcquired <- struct{}{}:
			default:
			}
		},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// Conn 1: raw TCP that never sends TLS bytes. The listener accepts it,
	// acquires the single handshake slot, and blocks in HandshakeContext.
	stall, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial stall: %v", err)
	}
	defer stall.Close()

	// Wait until the stalled handshake has definitely occupied the only slot,
	// rather than racing a fixed sleep (which is flaky under CI scheduling).
	select {
	case <-slotAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the stalled handshake to occupy the only slot")
	}

	// Conn 2: another raw TCP conn. The slot is full, so the listener must
	// close it immediately and invoke onShed -- well before any handshake
	// deadline could fire.
	shedConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial shed: %v", err)
	}
	defer shedConn.Close()

	// A shed conn is closed on the accept path, so the read fails at once with
	// EOF or a reset. An un-shed one stays open and instead hits this deadline.
	// Keying off which error arrives beats timing the read: it says the same
	// thing without a wall-clock threshold to lose under CI contention.
	shedConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	_, err = shedConn.Read(buf)
	if err == nil {
		t.Fatal("expected the over-cap connection to be dropped, got read error nil")
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		t.Errorf("over-cap conn was not shed; the read hit its own deadline instead of a close")
	}
	// Read returning means the peer saw the close, which the accept path does
	// only after onShed. Loading the counter here pins that ordering.
	if got := atomic.LoadInt64(&shed); got != 1 {
		t.Errorf("shed = %d, want 1", got)
	}
}

// TestHandshakeTimeoutListener_ShedDoesNotAffectEstablished confirms that while
// the handshake slots are saturated by stalled connections, an already-counted
// peer's request still completes -- the ceiling gates only the handshake phase,
// and the slot is released the moment the handshake resolves.
func TestHandshakeTimeoutListener_ShedDoesNotAffectEstablished(t *testing.T) {
	var shed int64
	slotAcquired := make(chan struct{}, 1)
	addr := newTLSTestServer(t, 3*time.Second, 1,
		func() { atomic.AddInt64(&shed, 1) },
		func() {
			select {
			case slotAcquired <- struct{}{}:
			default:
			}
		},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// A real client completes its handshake (acquiring and immediately
	// releasing the single slot), then issues requests. Because the slot is
	// freed as soon as the handshake resolves, the established connection's
	// keep-alive requests are never gated by the ceiling.
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Discard the slot signal from the first client's handshake so the wait
	// below observes the stalled connection specifically.
	select {
	case <-slotAcquired:
	default:
	}

	// Now saturate the slot with a stalled handshake, and wait until it has
	// definitely occupied the only slot before proving the established
	// connection is unaffected.
	stall, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial stall: %v", err)
	}
	defer stall.Close()
	select {
	case <-slotAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the stalled handshake to occupy the only slot")
	}

	// The established keep-alive connection still serves requests.
	resp2, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("established conn request failed while slot saturated: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", string(body))
	}
}

// genSelfSignedForTest returns a self-signed cert + key pair as PEM bytes,
// valid for 127.0.0.1 / localhost. Used by handshake-timeout tests that need
// a real TLS server.
func genSelfSignedForTest(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM
}
