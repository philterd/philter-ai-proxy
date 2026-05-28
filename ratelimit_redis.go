package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

// tokenBucketScript is an atomic token-bucket implemented in Lua so the
// read-refill-write cycle happens in a single round-trip and stays consistent
// across replicas. It uses the Redis server clock (TIME) rather than a
// client-supplied timestamp so replicas with skewed clocks still agree.
//
//	KEYS[1] = bucket key
//	ARGV[1] = rate (tokens per second)
//	ARGV[2] = burst (bucket capacity)
//	ARGV[3] = tokens requested (always 1 here)
//
// Returns {allowed (0|1), retry_after_ms}.
const tokenBucketScript = `
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local requested = tonumber(ARGV[3])

local t = redis.call('TIME')
local now = tonumber(t[1]) + tonumber(t[2]) / 1000000

local data = redis.call('HMGET', key, 'tk', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then
  tokens = burst
  ts = now
end

local delta = now - ts
if delta < 0 then delta = 0 end
tokens = math.min(burst, tokens + delta * rate)

local allowed = 0
local retry_ms = 0
if tokens >= requested then
  allowed = 1
  tokens = tokens - requested
else
  if rate > 0 then
    retry_ms = math.ceil((requested - tokens) / rate * 1000)
  else
    retry_ms = 1000
  end
end

redis.call('HSET', key, 'tk', tokens, 'ts', now)
-- GC idle buckets: expire after the bucket would refill to full, +1s slack.
local ttl = 1
if rate > 0 then ttl = math.ceil(burst / rate) + 1 end
redis.call('EXPIRE', key, ttl)

return {allowed, retry_ms}
`

// redisBackend is a shared token-bucket store backed by Redis. State lives in
// Redis, so all replicas enforce one consistent limit.
type redisBackend struct {
	client    *redis.Client
	script    *redis.Script
	keyPrefix string
}

func newRedisBackend(cfg RedisBackendConfig) (*redisBackend, error) {
	opts := &redis.Options{
		Addr:     cfg.Address,
		Username: cfg.Username,
		Password: cfg.Password,
		DB:       cfg.DB,
	}

	if cfg.TLS.Enabled {
		tlsCfg, err := buildRedisTLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		opts.TLSConfig = tlsCfg
	}

	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "philter:rl:"
	}

	return &redisBackend{
		client:    redis.NewClient(opts),
		script:    redis.NewScript(tokenBucketScript),
		keyPrefix: prefix,
	}, nil
}

func (b *redisBackend) Name() string { return "redis" }

func (b *redisBackend) Allow(ctx context.Context, key string, limit rate.Limit, burst int) (bool, time.Duration, error) {
	res, err := b.script.Run(ctx, b.client, []string{b.keyPrefix + key}, float64(limit), burst, 1).Result()
	if err != nil {
		return false, 0, fmt.Errorf("redis rate-limit script: %w", err)
	}

	vals, ok := res.([]interface{})
	if !ok || len(vals) != 2 {
		return false, 0, fmt.Errorf("redis rate-limit script: unexpected result %#v", res)
	}
	allowed, ok1 := vals[0].(int64)
	retryMs, ok2 := vals[1].(int64)
	if !ok1 || !ok2 {
		return false, 0, fmt.Errorf("redis rate-limit script: non-integer result %#v", res)
	}

	if allowed == 1 {
		return true, 0, nil
	}
	return false, time.Duration(retryMs) * time.Millisecond, nil
}

func (b *redisBackend) Close() error {
	return b.client.Close()
}

// buildRedisTLSConfig assembles a *tls.Config supporting an optional custom CA
// (server verification) and an optional client certificate (mTLS to Redis).
func buildRedisTLSConfig(cfg RedisTLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}

	if cfg.CACert != "" {
		caCert, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read redis CA certificate %s: %w", cfg.CACert, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse redis CA certificate %s", cfg.CACert)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.Cert != "" || cfg.Key != "" {
		if cfg.Cert == "" || cfg.Key == "" {
			return nil, fmt.Errorf("redis TLS: both cert and key must be set for client authentication")
		}
		pair, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load redis client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	return tlsCfg, nil
}
