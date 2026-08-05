package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// API keys are stored in memory as one of two hashed forms, never plaintext:
//
//   - sha256:   sha256$<64-hex-chars>
//   - bcrypt:   bcrypt$$2a$10$...  (the bcrypt hash itself starts with `$2a$`
//                                   or `$2b$`/`$2y$`, which is fine - we only
//                                   split on the FIRST `$`)
//
// Plaintext keys in config (no recognized prefix) are hashed with sha256 at
// load and never stored as plaintext beyond the initial parse.
//
// SHA256 is the default because API keys are typically high-entropy random
// tokens. Brute-forcing 256 bits of entropy from a hash is infeasible, so a
// fast hash + constant-time compare provides adequate protection against the
// stated threat (heap dump exposing live credentials). bcrypt is supported
// for users with existing bcrypt key-management workflows or compliance
// requirements; its per-request cost is significant (see docs/configuration.md
// "Authentication" for a latency table).

const (
	hashAlgoSHA256 = "sha256"
	hashAlgoBcrypt = "bcrypt"
)

// storedKey is the in-memory representation of one configured API key.
// The plaintext is discarded after construction.
type storedKey struct {
	algo string
	hash []byte
	// id is a stable identifier for this entry, used as the client identifier
	// in audit log lines. Derived
	// from the entry's position at load time ("key-0", "key-1", ...) so it
	// stays useful even when the raw key has been hashed away.
	id     string
	policy string
	scopes *APIKeyScopes
}

// resolvedKey is what keyStore.lookup returns on a successful match: the
// stable opaque ID plus everything the request path needs to authorize the
// call. The raw key value is never returned.
type resolvedKey struct {
	ID     string
	Policy string
	Scopes *APIKeyScopes
}

// keyStore is the lookup structure assembled at startup from the auth config.
type keyStore struct {
	entries []storedKey
}

// parseStoredKey turns a single config entry (`s`) into an in-memory storedKey.
//
//   - If s starts with `sha256$`, the rest is decoded as 32 bytes of hex.
//   - If s starts with `bcrypt$`, the rest is treated as a bcrypt hash string.
//   - Otherwise s is treated as plaintext and hashed with sha256 at load.
//
// The plaintext form is convenient for quickstart configs; production users
// should pre-hash to keep plaintext keys out of the YAML.
func parseStoredKey(s, id, policy string, scopes *APIKeyScopes) (storedKey, error) {
	if s == "" {
		return storedKey{}, fmt.Errorf("api key value must not be empty")
	}
	base := storedKey{id: id, policy: policy, scopes: scopes}
	if algo, rest, ok := strings.Cut(s, "$"); ok {
		switch algo {
		case hashAlgoSHA256:
			h, err := hex.DecodeString(rest)
			if err != nil {
				return storedKey{}, fmt.Errorf("sha256 hash %q: %w", rest, err)
			}
			if len(h) != sha256.Size {
				return storedKey{}, fmt.Errorf("sha256 hash must be %d bytes (got %d)", sha256.Size, len(h))
			}
			base.algo = hashAlgoSHA256
			base.hash = h
			return base, nil
		case hashAlgoBcrypt:
			// The bcrypt module verifies the hash format on use; reject any
			// obviously-malformed value here so misconfigurations surface at
			// startup rather than on the first 401.
			if _, err := bcrypt.Cost([]byte(rest)); err != nil {
				return storedKey{}, fmt.Errorf("bcrypt hash %q: %w", rest, err)
			}
			base.algo = hashAlgoBcrypt
			base.hash = []byte(rest)
			return base, nil
		}
		// Unknown algo prefix: fall through to treating as plaintext. This
		// could mask typos like `sha256:abc` (wrong separator) but the alternative
		// - rejecting unknown prefixes - prevents future extensibility.
	}
	sum := sha256.Sum256([]byte(s))
	base.algo = hashAlgoSHA256
	base.hash = sum[:]
	return base, nil
}

// keyIDForIndex returns the legacy positional identifier `key-N` for the
// entry at position `i`. Use `keyIDFor(entry, i)` from the wiring code so
// an explicit `auth.apiKeys[].id` overrides the positional default.
func keyIDForIndex(i int) string {
	return fmt.Sprintf("key-%d", i)
}

// keyIDFor returns the stable identifier for an APIKeyEntry: its explicit
// `id` when set, otherwise the legacy positional `key-N`. Use this from the
// concurrency wiring so all per-key buckets agree on
// the same identifier the keyStore will later return from lookup().
func keyIDFor(entry APIKeyEntry, i int) string {
	if entry.ID != "" {
		return entry.ID
	}
	return keyIDForIndex(i)
}

// newKeyStore builds a keyStore from the auth config. Returns nil when no
// keys are configured (auth disabled).
func newKeyStore(entries []APIKeyEntry) (*keyStore, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	ks := &keyStore{entries: make([]storedKey, 0, len(entries))}
	for i, e := range entries {
		id := e.ID
		if id == "" {
			// Backwards-compatible fallback. Positional IDs are unstable
			// across `auth.apiKeys` edits; configuration.md flags this and
			// the documentation strongly recommends setting `id:` explicitly.
			id = keyIDForIndex(i)
		}
		sk, err := parseStoredKey(e.Key, id, e.Policy, e.Scopes)
		if err != nil {
			return nil, fmt.Errorf("auth.apiKeys[%d]: %w", i, err)
		}
		ks.entries = append(ks.entries, sk)
	}
	return ks, nil
}

// lookup returns the resolved key on a successful match, or (nil, false)
// otherwise. The loop walks **every** configured entry regardless of an
// early hit so the elapsed time is independent of the position of the
// matching entry (or whether a match exists at all). Closing that timing
// oracle is essential for bcrypt-configured deployments, where the
// per-entry cost is on the order of milliseconds and the position of a
// matching key would otherwise be trivially observable from the network.
//
// Per-entry comparison itself is already constant-time:
//   - sha256 entries use subtle.ConstantTimeCompare over fixed-size buffers.
//   - bcrypt entries use bcrypt.CompareHashAndPassword, documented to
//     compare in constant time.
//
// When multiple entries match (which the config-load duplicate check
// already rejects, so this is a defensive choice) the first match wins.
func (ks *keyStore) lookup(clientKey string) (*resolvedKey, bool) {
	if ks == nil || len(ks.entries) == 0 {
		return nil, false
	}
	keyBytes := []byte(clientKey)
	sum := sha256.Sum256(keyBytes)

	matchIdx := -1
	for i := range ks.entries {
		e := &ks.entries[i]
		var hit bool
		switch e.algo {
		case hashAlgoSHA256:
			hit = subtle.ConstantTimeCompare(sum[:], e.hash) == 1
		case hashAlgoBcrypt:
			hit = bcrypt.CompareHashAndPassword(e.hash, keyBytes) == nil
		}
		if hit && matchIdx == -1 {
			matchIdx = i
		}
	}
	if matchIdx == -1 {
		return nil, false
	}
	e := &ks.entries[matchIdx]
	return &resolvedKey{ID: e.id, Policy: e.policy, Scopes: e.scopes}, true
}

// hashPlaintextKeySHA256 returns the canonical `sha256$<hex>` string for a
// plaintext key. Exposed so tests can build expected values and so a future
// CLI helper can print pre-hashed lines for config.
func hashPlaintextKeySHA256(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hashAlgoSHA256 + "$" + hex.EncodeToString(sum[:])
}

// hashPlaintextKeyBcrypt returns the canonical `bcrypt$<bcrypt-hash>` string
// for a plaintext key at the given cost (4-31; bcrypt's defined range).
func hashPlaintextKeyBcrypt(plaintext string, cost int) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash: %w", err)
	}
	return hashAlgoBcrypt + "$" + string(h), nil
}
