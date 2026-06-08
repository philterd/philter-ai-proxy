package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestParseCLI_ConfigFlag(t *testing.T) {
	t.Setenv("PHILTER_PROXY_CONFIG", "")
	var buf bytes.Buffer
	opts, err := parseCLI([]string{"--config", "/tmp/foo.yaml"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.configPath != "/tmp/foo.yaml" {
		t.Errorf("path: got %q", opts.configPath)
	}
	if opts.validateOnly {
		t.Error("validate should be false")
	}
}

func TestParseCLI_ValidateFlag(t *testing.T) {
	t.Setenv("PHILTER_PROXY_CONFIG", "")
	var buf bytes.Buffer
	opts, err := parseCLI([]string{"--validate-config", "--config", "/tmp/bar.yaml"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.configPath != "/tmp/bar.yaml" {
		t.Errorf("path: got %q", opts.configPath)
	}
	if !opts.validateOnly {
		t.Error("validate should be true")
	}
}

func TestParseCLI_EnvFallback(t *testing.T) {
	t.Setenv("PHILTER_PROXY_CONFIG", "/etc/from-env.yaml")
	var buf bytes.Buffer
	opts, err := parseCLI([]string{}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.configPath != "/etc/from-env.yaml" {
		t.Errorf("expected env var fallback, got %q", opts.configPath)
	}
}

func TestParseCLI_FlagOverridesEnv(t *testing.T) {
	t.Setenv("PHILTER_PROXY_CONFIG", "/etc/from-env.yaml")
	var buf bytes.Buffer
	opts, err := parseCLI([]string{"--config", "/tmp/from-flag.yaml"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.configPath != "/tmp/from-flag.yaml" {
		t.Errorf("expected --config to override env, got %q", opts.configPath)
	}
}

func TestParseCLI_UnknownFlag(t *testing.T) {
	var buf bytes.Buffer
	_, err := parseCLI([]string{"--no-such-flag"}, &buf)
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestParseCLI_VersionFlag(t *testing.T) {
	t.Setenv("PHILTER_PROXY_CONFIG", "")
	var buf bytes.Buffer
	opts, err := parseCLI([]string{"--version"}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.showVersion {
		t.Error("showVersion should be true")
	}
}

func TestVersionString(t *testing.T) {
	got := versionString()
	if !strings.HasPrefix(got, "philter-ai-proxy ") {
		t.Errorf("version string should start with the binary name, got %q", got)
	}
	if !strings.Contains(got, version) {
		t.Errorf("version string should contain the version %q, got %q", version, got)
	}
}

func TestRunValidateConfig_OK(t *testing.T) {
	tmp, _ := os.CreateTemp("", "vcfg-ok-*.yaml")
	tmp.WriteString(`
listen:
  port: 8443
philter:
  endpoint: https://philter.internal:8080
providers:
  openai:
    target: https://api.openai.com
  anthropic:
    target: https://api.anthropic.com
  gemini:
    target: https://gemini.example.com
  ollama:
    target: http://localhost:11434
`)
	tmp.Close()
	defer os.Remove(tmp.Name())

	var out, errOut bytes.Buffer
	code := runValidateConfig(tmp.Name(), &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(out.String(), "config OK") {
		t.Errorf("expected 'config OK' on stdout, got %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Errorf("expected empty stderr on success, got %q", errOut.String())
	}
}

func TestRunValidateConfig_InvalidYAML(t *testing.T) {
	tmp, _ := os.CreateTemp("", "vcfg-bad-*.yaml")
	tmp.WriteString("invalid: yaml: [broken")
	tmp.Close()
	defer os.Remove(tmp.Name())

	var out, errOut bytes.Buffer
	code := runValidateConfig(tmp.Name(), &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "config invalid") {
		t.Errorf("expected 'config invalid' on stderr, got %q", errOut.String())
	}
}

func TestRunValidateConfig_MissingPath(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runValidateConfig("", &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "config invalid") {
		t.Errorf("expected 'config invalid' on stderr, got %q", errOut.String())
	}
}

func TestRunValidateConfig_NonexistentFile(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runValidateConfig("/no/such/file.yaml", &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "config invalid") {
		t.Errorf("expected 'config invalid' on stderr, got %q", errOut.String())
	}
}

func TestRunValidateConfig_SemanticError(t *testing.T) {
	tmp, _ := os.CreateTemp("", "vcfg-semantic-*.yaml")
	tmp.WriteString(`
listen:
  port: 999999
philter:
  endpoint: https://philter.internal:8080
`)
	tmp.Close()
	defer os.Remove(tmp.Name())

	var out, errOut bytes.Buffer
	code := runValidateConfig(tmp.Name(), &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "listen.port") {
		t.Errorf("expected error to name listen.port, got %q", errOut.String())
	}
}
