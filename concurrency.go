package main

// ConcurrencyLimiter bounds the number of requests being processed at the same
// time. A global cap protects the proxy as a whole; an optional per-API-key
// cap protects a noisy client from starving everyone else. Both caps are
// independent — a request must acquire whichever ones apply.
//
// A nil receiver is a valid no-op limiter (always allows).
type ConcurrencyLimiter struct {
	global chan struct{}            // nil when no global limit
	perKey map[string]chan struct{} // nil/empty when no per-key limits
}

func newConcurrencyLimiter(globalLimit int, perKey map[string]int) *ConcurrencyLimiter {
	cl := &ConcurrencyLimiter{}
	if globalLimit > 0 {
		cl.global = make(chan struct{}, globalLimit)
	}
	if len(perKey) > 0 {
		cl.perKey = make(map[string]chan struct{}, len(perKey))
		for k, n := range perKey {
			if n > 0 {
				cl.perKey[k] = make(chan struct{}, n)
			}
		}
	}
	return cl
}

// Acquire tries to take a slot for the request.
//
//   - clientKey may be empty when auth is disabled; per-key limits then do not apply.
//   - allowed=true means the caller should proceed and must invoke release exactly once.
//   - allowed=false means the request was shed; scope is "global" or "per_key".
//
// release is always non-nil; on rejection it is a no-op.
func (cl *ConcurrencyLimiter) Acquire(clientKey string) (allowed bool, scope string, release func()) {
	noop := func() {}
	if cl == nil {
		return true, "", noop
	}

	var keySem chan struct{}
	if clientKey != "" {
		keySem = cl.perKey[clientKey]
	}

	if cl.global != nil {
		select {
		case cl.global <- struct{}{}:
		default:
			return false, "global", noop
		}
	}

	if keySem != nil {
		select {
		case keySem <- struct{}{}:
		default:
			if cl.global != nil {
				<-cl.global
			}
			return false, "per_key", noop
		}
	}

	release = func() {
		if keySem != nil {
			<-keySem
		}
		if cl.global != nil {
			<-cl.global
		}
	}
	return true, "", release
}

// hasPerKeyConcurrency reports whether any API key in keys has a per-key
// concurrency limit configured. Used by main() to decide whether to construct
// a ConcurrencyLimiter when no global limit is set.
func hasPerKeyConcurrency(keys []APIKeyEntry) bool {
	for _, k := range keys {
		if k.MaxConcurrent > 0 {
			return true
		}
	}
	return false
}

// perKeyConcurrencyMap builds the (key → slots) map used to construct the
// limiter. Entries with MaxConcurrent <= 0 are skipped.
func perKeyConcurrencyMap(keys []APIKeyEntry) map[string]int {
	if len(keys) == 0 {
		return nil
	}
	out := make(map[string]int)
	for _, k := range keys {
		if k.MaxConcurrent > 0 {
			out[k.Key] = k.MaxConcurrent
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

