package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/time/rate"
)

// writeTestCert generates a self-signed certificate (usable as both a CA and a
// client cert) and writes the cert + key to temp files. Returns their paths.
func writeTestCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-redis"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestBuildRedisTLSConfig_CAAndClientCert(t *testing.T) {
	certPath, keyPath := writeTestCert(t)

	tlsCfg, err := buildRedisTLSConfig(RedisTLSConfig{
		Enabled: true,
		CACert:  certPath, // reuse the self-signed cert as the CA bundle
		Cert:    certPath,
		Key:     keyPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected RootCAs to be set from caCert")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected one client certificate, got %d", len(tlsCfg.Certificates))
	}
}

func TestBuildRedisTLSConfig_InsecureSkipVerify(t *testing.T) {
	tlsCfg, err := buildRedisTLSConfig(RedisTLSConfig{Enabled: true, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be set")
	}
}

func TestBuildRedisTLSConfig_CertWithoutKey(t *testing.T) {
	certPath, _ := writeTestCert(t)
	_, err := buildRedisTLSConfig(RedisTLSConfig{Enabled: true, Cert: certPath})
	if err == nil {
		t.Error("expected error when cert is set without key")
	}
}

func TestBuildRedisTLSConfig_MissingCAFile(t *testing.T) {
	_, err := buildRedisTLSConfig(RedisTLSConfig{Enabled: true, CACert: "/nonexistent/ca.pem"})
	if err == nil {
		t.Error("expected error for missing CA file")
	}
}

func TestBuildRedisTLSConfig_UnparseableCA(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := buildRedisTLSConfig(RedisTLSConfig{Enabled: true, CACert: bad})
	if err == nil {
		t.Error("expected error for unparseable CA file")
	}
}

// TestNewRedisBackend_TLSError confirms a TLS-construction failure surfaces all
// the way through the backend constructor (and thus newProxyRateLimiter).
func TestNewRedisBackend_TLSError(t *testing.T) {
	_, err := newRedisBackend(RedisBackendConfig{
		Address: "localhost:6379",
		TLS:     RedisTLSConfig{Enabled: true, CACert: "/nonexistent/ca.pem"},
	})
	if err == nil {
		t.Error("expected newRedisBackend to fail on bad TLS material")
	}

	cfg := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		Backend: RateLimitBackendConfig{
			Type:  "redis",
			Redis: RedisBackendConfig{Address: "localhost:6379", TLS: RedisTLSConfig{Enabled: true, CACert: "/nonexistent/ca.pem"}},
		},
	}
	if _, err := newProxyRateLimiter(cfg, nil, nil); err == nil {
		t.Error("expected newProxyRateLimiter to fail when the redis backend can't be built")
	}
}

// TestProxyRateLimiter_MetricsEmitted asserts the backend latency/error-rate
// metrics are actually observed — the "metrics expose backend latency and error
// rate" acceptance criterion.
func TestProxyRateLimiter_MetricsEmitted(t *testing.T) {
	// Error + fail-open path: errors counter, fallback counter, and an
	// error-result latency observation should all increment.
	m := newMetrics(prometheus.NewRegistry())
	rl := &ProxyRateLimiter{
		backend:      errBackend{},
		fallback:     newMemoryBackend(),
		failureMode:  "open",
		metrics:      m,
		defaultLimit: 1000,
		defaultBurst: 1000,
		perKeyLimit:  map[string]rate.Limit{},
		perKeyBurst:  map[string]int{},
	}
	defer rl.Close()

	rl.Allow(context.Background(), "client")

	if got := testutil.ToFloat64(m.rateLimitBackendErrors.WithLabelValues("redis")); got < 1 {
		t.Errorf("expected backend error counter >= 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.rateLimitFallback); got < 1 {
		t.Errorf("expected fallback counter >= 1, got %v", got)
	}
	if got := testutil.CollectAndCount(m.rateLimitBackendDuration); got < 1 {
		t.Errorf("expected at least one latency observation, got %d series", got)
	}

	// Success path: an "ok"-result latency observation should be recorded and
	// no error counted.
	m2 := newMetrics(prometheus.NewRegistry())
	rl2 := &ProxyRateLimiter{
		backend:      newMemoryBackend(),
		failureMode:  "open",
		metrics:      m2,
		defaultLimit: 1000,
		defaultBurst: 1000,
		perKeyLimit:  map[string]rate.Limit{},
		perKeyBurst:  map[string]int{},
	}
	defer rl2.Close()

	if allowed, _ := rl2.Allow(context.Background(), "client"); !allowed {
		t.Fatal("expected request to be allowed by memory backend")
	}
	if got := testutil.ToFloat64(m2.rateLimitBackendErrors.WithLabelValues("memory")); got != 0 {
		t.Errorf("expected no backend errors on success path, got %v", got)
	}
	if got := testutil.CollectAndCount(m2.rateLimitBackendDuration); got < 1 {
		t.Errorf("expected an ok-result latency observation, got %d series", got)
	}
}

// TestProxyRateLimiter_GlobalBackstop_ViaRedis confirms the global bucket is
// enforced through the backend (not just the per-client bucket).
func TestProxyRateLimiter_GlobalBackstop_ViaRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	cfg := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1000, // generous per-client
		Burst:             1000,
		Global:            RateLimitBucket{RequestsPerSecond: 0.001, Burst: 2}, // tight global
		Backend:           RateLimitBackendConfig{Type: "redis", Redis: RedisBackendConfig{Address: mr.Addr()}},
	}
	rl, err := newProxyRateLimiter(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	ctx := context.Background()
	// Distinct clients each within their own per-client limit, but the shared
	// global bucket (burst=2) should still block after two requests.
	blocked := false
	for i := 0; i < 6; i++ {
		if allowed, _ := rl.Allow(ctx, "client-"+string(rune('a'+i))); !allowed {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Error("expected the global backstop to block once its burst was exhausted, across distinct clients")
	}
}
