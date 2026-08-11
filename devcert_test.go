package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestKeypair stands in for an operator-supplied certificate on disk.
func writeTestKeypair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM, err := generateSelfSignedPEM()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestGenerateSelfSignedCert_CompletesAHandshake(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestGenerateSelfSignedCert_DiffersEveryCall(t *testing.T) {
	first, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	a, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.ParseCertificate(second.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Error("two generated certificates share a serial number")
	}
	firstKey, ok := a.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected key type %T", a.PublicKey)
	}
	if firstKey.Equal(b.PublicKey) {
		t.Error("two generated certificates share a public key")
	}
}

func TestGenerateSelfSignedCert_HasLocalhostSANs(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("localhost is not covered: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("127.0.0.1 is not covered: %v", err)
	}
}

func TestResolveServerCertificate_UsesConfiguredKeypair(t *testing.T) {
	certPath, keyPath := writeTestKeypair(t)
	got, err := resolveServerCertificate(ListenConfig{Cert: certPath, Key: keyPath})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Certificate[0]) != string(want.Certificate[0]) {
		t.Error("resolved certificate is not the configured one")
	}
}

func TestResolveServerCertificate_ConfiguredKeypairBeatsDevFlag(t *testing.T) {
	certPath, keyPath := writeTestKeypair(t)
	got, err := resolveServerCertificate(ListenConfig{Cert: certPath, Key: keyPath, DevSelfSignedCert: true})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Certificate[0]) != string(want.Certificate[0]) {
		t.Error("the dev flag overrode an explicitly configured certificate")
	}
}

// Falling back to a generated certificate here would silently serve an
// untrusted one in place of the certificate the operator asked for.
func TestResolveServerCertificate_UnreadableKeypairIsFatalEvenWithDevFlag(t *testing.T) {
	_, err := resolveServerCertificate(ListenConfig{
		Cert:              "/nonexistent/tls.crt",
		Key:               "/nonexistent/tls.key",
		DevSelfSignedCert: true,
	})
	if err == nil {
		t.Fatal("expected an unreadable keypair to fail rather than fall back to generation")
	}
	if !strings.Contains(err.Error(), "listen.cert") {
		t.Errorf("error should name the config field, got %v", err)
	}
}

func TestResolveServerCertificate_MissingFileWithFlagOffIsFatal(t *testing.T) {
	_, err := resolveServerCertificate(ListenConfig{
		Cert: "/nonexistent/tls.crt",
		Key:  "/nonexistent/tls.key",
	})
	if err == nil {
		t.Fatal("expected a missing keypair to fail startup")
	}
	for _, want := range []string{"listen.cert", "listen.key", "installation guide"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s, got %v", want, err)
		}
	}
}

func TestResolveServerCertificate_GeneratesWhenOnlyDevFlagSet(t *testing.T) {
	cert, err := resolveServerCertificate(ListenConfig{DevSelfSignedCert: true})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "philter-ai-proxy" {
		t.Errorf("unexpected subject %q", leaf.Subject.CommonName)
	}
}

func TestResolveServerCertificate_NoCertConfiguredFailsWithGuidance(t *testing.T) {
	_, err := resolveServerCertificate(ListenConfig{})
	if err == nil {
		t.Fatal("expected startup to fail with no certificate configured")
	}
	for _, want := range []string{"listen.cert", "listen.key", "listen.devSelfSignedCert", "installation guide"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s, got %v", want, err)
		}
	}
}

func TestResolveServerCertificate_HalfConfiguredKeypairIsRejected(t *testing.T) {
	certPath, _ := writeTestKeypair(t)
	_, err := resolveServerCertificate(ListenConfig{Cert: certPath})
	if err == nil || !strings.Contains(err.Error(), "listen.key") {
		t.Errorf("expected a missing listen.key to be reported, got %v", err)
	}
	_, err = resolveServerCertificate(ListenConfig{Key: certPath})
	if err == nil || !strings.Contains(err.Error(), "listen.cert") {
		t.Errorf("expected a missing listen.cert to be reported, got %v", err)
	}
}
