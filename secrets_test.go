package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSecret_Literal(t *testing.T) {
	got, err := resolveSecret("test", "plain-literal-key")
	if err != nil {
		t.Fatal(err)
	}
	if got != "plain-literal-key" {
		t.Errorf("expected literal passthrough, got %q", got)
	}
}

func TestResolveSecret_EnvVar(t *testing.T) {
	t.Setenv("PHILTER_TEST_SECRET", "from-env")
	got, err := resolveSecret("test", "${PHILTER_TEST_SECRET}")
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-env" {
		t.Errorf("expected from-env, got %q", got)
	}
}

func TestResolveSecret_EnvVar_Unset(t *testing.T) {
	os.Unsetenv("PHILTER_TEST_MISSING")
	_, err := resolveSecret("test", "${PHILTER_TEST_MISSING}")
	if err == nil {
		t.Fatal("expected error for unset env var")
	}
}

func TestResolveSecret_EnvVar_Empty(t *testing.T) {
	t.Setenv("PHILTER_TEST_EMPTY", "")
	_, err := resolveSecret("test", "${PHILTER_TEST_EMPTY}")
	if err == nil {
		t.Fatal("expected error for empty env var")
	}
}

func TestResolveSecret_EnvVar_EmptyName(t *testing.T) {
	_, err := resolveSecret("test", "${}")
	if err == nil {
		t.Fatal("expected error for empty env var name")
	}
}

func TestResolveSecret_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	// Trailing newline is common (echo > file) and must be trimmed.
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveSecret("test", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-file" {
		t.Errorf("expected from-file (newline trimmed), got %q", got)
	}
}

func TestResolveSecret_File_Missing(t *testing.T) {
	_, err := resolveSecret("test", "file:/nonexistent/secret/path")
	if err == nil {
		t.Fatal("expected error for missing secret file")
	}
}

func TestResolveSecret_File_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, []byte("\n  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := resolveSecret("test", "file:"+path)
	if err == nil {
		t.Fatal("expected error for empty secret file")
	}
}

// TestResolveSecret_NoValueEcho asserts criterion #4: resolution errors must
// not echo the resolved secret value (they may name the env var / file path).
func TestResolveSecret_NoValueEcho(t *testing.T) {
	t.Setenv("PHILTER_TEST_DUP", "super-secret-value")
	// Force a downstream duplicate error path by resolving two refs to the
	// same value and feeding them through validation.
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("super-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tmp := filepath.Join(dir, "config.yaml")
	cfgYAML := "philter:\n  endpoint: https://localhost:8080\nauth:\n  apiKeys:\n    - key: ${PHILTER_TEST_DUP}\n    - key: file:" + path + "\n"
	if err := os.WriteFile(tmp, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadConfig(tmp)
	if err == nil {
		t.Fatal("expected duplicate-key validation error")
	}
	if strings.Contains(err.Error(), "super-secret-value") {
		t.Errorf("error message leaked the secret value: %v", err)
	}
}

// TestLoadConfig_ResolvesSecrets is the end-to-end happy path: env and file
// references resolve, and a literal still works (backwards compatibility).
func TestLoadConfig_ResolvesSecrets(t *testing.T) {
	t.Setenv("PHILTER_TEST_KEY_A", "env-key-a")
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key-b")
	if err := os.WriteFile(keyFile, []byte("file-key-b\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tmp := filepath.Join(dir, "config.yaml")
	cfgYAML := "philter:\n  endpoint: https://localhost:8080\nauth:\n  apiKeys:\n    - key: ${PHILTER_TEST_KEY_A}\n    - key: file:" + keyFile + "\n    - key: literal-key-c\n"
	if err := os.WriteFile(tmp, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(tmp)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"env-key-a", "file-key-b", "literal-key-c"}
	if len(cfg.Auth.APIKeys) != len(want) {
		t.Fatalf("expected %d keys, got %d", len(want), len(cfg.Auth.APIKeys))
	}
	for i, w := range want {
		if cfg.Auth.APIKeys[i].Key != w {
			t.Errorf("key[%d]: expected %q, got %q", i, w, cfg.Auth.APIKeys[i].Key)
		}
	}
}
