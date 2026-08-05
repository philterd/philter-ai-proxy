package main

import (
	"fmt"
	"os"
	"strings"
)

// resolveSecret expands a configured secret reference into its actual value.
//
// Three forms are supported so that secrets need not be stored in plaintext in
// the config file (which would otherwise end up in version control or baked
// into container images):
//
//   - ${ENV_VAR}        - read from the named environment variable
//   - file:/path/secret - read from a file (trailing whitespace is trimmed)
//   - anything else      - used verbatim (backwards-compatible literal)
//
// The function is deliberately generic (it takes only the raw reference and a
// human-readable field name for errors) so it can be reused for any future
// secret-bearing config field, such as provider auth headers.
//
// Errors never include the resolved secret value. They may include the
// reference itself (the env var name or file path), which is not sensitive.
func resolveSecret(field, raw string) (string, error) {
	switch {
	case strings.HasPrefix(raw, "${") && strings.HasSuffix(raw, "}"):
		name := strings.TrimSpace(raw[2 : len(raw)-1])
		if name == "" {
			return "", fmt.Errorf("config: %s has an empty ${} environment variable reference", field)
		}
		value, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("config: %s references environment variable %q, which is not set", field, name)
		}
		if value == "" {
			return "", fmt.Errorf("config: %s references environment variable %q, which is empty", field, name)
		}
		return value, nil

	case strings.HasPrefix(raw, "file:"):
		path := strings.TrimPrefix(raw, "file:")
		if path == "" {
			return "", fmt.Errorf("config: %s has an empty file: secret reference", field)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("config: %s failed to read secret file %q: %w", field, path, err)
		}
		value := strings.TrimRight(string(data), "\r\n \t")
		if value == "" {
			return "", fmt.Errorf("config: %s secret file %q is empty", field, path)
		}
		return value, nil

	default:
		return raw, nil
	}
}

// resolveSecrets expands every secret-bearing field in the config in place,
// replacing ${ENV_VAR} and file: references with their actual values before the
// config is validated and the keys are hashed. Literal values pass through
// unchanged so existing configs keep working.
func resolveSecrets(cfg *Config) error {
	for i := range cfg.Auth.APIKeys {
		field := fmt.Sprintf("auth.apiKeys[%d].key", i)
		resolved, err := resolveSecret(field, cfg.Auth.APIKeys[i].Key)
		if err != nil {
			return err
		}
		cfg.Auth.APIKeys[i].Key = resolved
	}

	return nil
}
