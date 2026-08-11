package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"
)

const devCertValidity = 365 * 24 * time.Hour

const certDocsHint = " (see the Certificates section of the installation guide)"

// resolveServerCertificate returns the certificate the listener should serve.
// A configured keypair always wins, and a configured keypair that fails to load
// is fatal rather than a reason to generate one.
func resolveServerCertificate(c ListenConfig) (tls.Certificate, error) {
	switch {
	case c.Cert != "" && c.Key != "":
		if c.DevSelfSignedCert {
			slog.Warn("Ignoring listen.devSelfSignedCert because listen.cert and listen.key are set",
				"cert", c.Cert, "key", c.Key)
		}
		cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to load the TLS keypair from listen.cert %q and listen.key %q: %w"+certDocsHint, c.Cert, c.Key, err)
		}
		return cert, nil

	case c.Cert != "" || c.Key != "":
		missing, set := "listen.key", "listen.cert"
		if c.Cert == "" {
			missing, set = "listen.cert", "listen.key"
		}
		return tls.Certificate{}, fmt.Errorf("%s is set but %s is not; both are required to serve TLS"+certDocsHint, set, missing)

	case c.DevSelfSignedCert:
		cert, err := generateSelfSignedCert()
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to generate the evaluation certificate: %w", err)
		}
		slog.Warn("Serving a generated self-signed certificate: FOR EVALUATION ONLY, NOT FOR PRODUCTION",
			"reason", "listen.devSelfSignedCert is true",
			"consequence", "clients must disable certificate verification to connect",
			"action", "set listen.cert and listen.key, and remove listen.devSelfSignedCert",
			"valid_for", devCertValidity.String(),
		)
		return cert, nil

	default:
		return tls.Certificate{}, fmt.Errorf("no TLS certificate configured: set listen.cert and listen.key to your certificate and private key, or set listen.devSelfSignedCert: true to generate a throwaway certificate for evaluation" + certDocsHint)
	}
}

// generateSelfSignedCert builds a keypair that never touches disk.
func generateSelfSignedCert() (tls.Certificate, error) {
	certPEM, keyPEM, err := generateSelfSignedPEM()
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func generateSelfSignedPEM() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generating serial: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Philter AI Proxy (evaluation)"},
			CommonName:   "philter-ai-proxy",
		},
		// Backdated for client clock skew.
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(devCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", "philter-ai-proxy"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		template.DNSNames = append(template.DNSNames, hostname)
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}
