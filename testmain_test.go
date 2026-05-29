package main

// TestMain installs package-wide test-time setup. Currently:
//
//   - Silences the go-redis library's internal logger. Tests like
//     `TestRedisBackend_ErrorWhenDown` deliberately close miniredis to
//     exercise the unreachable-Redis code path, and the library logs every
//     dial failure to stderr via its built-in logger. The connection
//     failures are *the expected behavior under test*, but the chatter
//     swamps the visible output of `make test`.
//
// All real test setup runs through `m.Run()`; if it returns non-zero, we
// exit with the same code so `go test` reports failure correctly.

import (
	"context"
	"os"
	"testing"

	"github.com/redis/go-redis/v9"
)

// silentRedisLogger satisfies the (unexported) redis logging interface
// structurally. SetLogger documents the signature as
// `Printf(ctx, format, v...)`; matching it here is enough to suppress
// the library's per-attempt dial-failure log lines.
type silentRedisLogger struct{}

func (silentRedisLogger) Printf(_ context.Context, _ string, _ ...interface{}) {}

func TestMain(m *testing.M) {
	redis.SetLogger(silentRedisLogger{})
	os.Exit(m.Run())
}
