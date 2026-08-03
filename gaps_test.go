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
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- #193: error-response helpers ----------------------------------------

func TestWriteMarshalFailed(t *testing.T) {
	p := &Proxy{}
	w := httptest.NewRecorder()
	p.writeMarshalFailed(w, &AuditEntry{RequestID: "req-1"}, errors.New("boom: internal struct field LeakyName"))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"internal_error", "marshal_failed", "req-1"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q: %s", want, body)
		}
	}
	// The raw error (struct field names, etc.) must never reach the client.
	if strings.Contains(body, "LeakyName") || strings.Contains(body, "boom") {
		t.Errorf("response leaked the internal error detail: %s", body)
	}
}

func TestWriteBodyReadError(t *testing.T) {
	p := &Proxy{}
	w := httptest.NewRecorder()
	p.writeBodyReadError(w, &AuditEntry{RequestID: "req-2"}, errors.New("connection reset internals"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"invalid_request", "body_read", "req-2"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "connection reset internals") {
		t.Errorf("response leaked the internal error detail: %s", body)
	}
}

// --- #189: inbound mTLS authentication (end to end) ----------------------

// genCAAndClientCert returns a self-signed client CA and a client certificate
// signed by it (PEM). The CA is used to configure the proxy's mTLS listener;
// the client cert is presented by the "valid" client.
func genCAAndClientCert(t *testing.T) (caCertPEM, clientCertPEM, clientKeyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Client CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	clientCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	clientKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return caCertPEM, clientCertPEM, clientKeyPEM
}

func TestBuildInboundMTLSConfig_Errors(t *testing.T) {
	// Missing CA file.
	if _, err := buildInboundMTLSConfig(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
		t.Error("expected an error for a missing client CA file")
	}
	// File that is not a valid PEM certificate.
	bad := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildInboundMTLSConfig(bad); err == nil {
		t.Error("expected an error for an unparseable client CA file")
	}
}

// TestInboundMTLS_E2E drives the proxy's mTLS listener (built via the production
// buildInboundMTLSConfig) over a real TLS connection: a client presenting a
// CA-signed certificate is admitted, and a client with no certificate is
// rejected at the handshake.
func TestInboundMTLS_E2E(t *testing.T) {
	caCertPEM, clientCertPEM, clientKeyPEM := genCAAndClientCert(t)

	caFile := filepath.Join(t.TempDir(), "client-ca.pem")
	if err := os.WriteFile(caFile, caCertPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	tlsCfg, err := buildInboundMTLSConfig(caFile)
	if err != nil {
		t.Fatalf("buildInboundMTLSConfig: %v", err)
	}

	// /livez is served without auth/Philter, so a minimal proxy is enough to
	// exercise the TLS layer end to end.
	p := &Proxy{config: testConfig("https://philter.invalid:8080")}
	srv := httptest.NewUnstartedServer(p)
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	// Both clients trust the server's (auto-generated) cert. They differ only in
	// whether they present a client certificate. Build them separately rather
	// than via srv.Client(), which returns a single shared client.
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(srv.Certificate())
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}

	// 1. A client presenting a CA-signed cert is admitted.
	okClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      serverRoots,
		Certificates: []tls.Certificate{clientCert},
	}}}
	resp, err := okClient.Get(srv.URL + "/livez")
	if err != nil {
		t.Fatalf("client with a valid cert was rejected: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid-cert client: status = %d, want 200", resp.StatusCode)
	}

	// 2. A client presenting no certificate is rejected at the handshake.
	noCertClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: serverRoots,
	}}}
	if _, err := noCertClient.Get(srv.URL + "/livez"); err == nil {
		t.Error("client with no certificate should have been rejected by mTLS")
	}
}
