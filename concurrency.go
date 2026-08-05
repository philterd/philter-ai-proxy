package main

// ConcurrencyLimiter bounds in-flight requests, protecting the proxy and the
// Philter instance behind it. Per-client policy belongs to the AI gateway.
// A nil receiver is a valid no-op limiter (always allows).
type ConcurrencyLimiter struct {
	global chan struct{} // nil when no global limit
}

func newConcurrencyLimiter(globalLimit int) *ConcurrencyLimiter {
	cl := &ConcurrencyLimiter{}
	if globalLimit > 0 {
		cl.global = make(chan struct{}, globalLimit)
	}
	return cl
}

// Acquire tries to take a slot for the request.
//
//   - allowed=true means the caller should proceed and must invoke release exactly once.
//   - allowed=false means the request was shed; scope is "global".
//
// release is always non-nil; on rejection it is a no-op.
func (cl *ConcurrencyLimiter) Acquire() (allowed bool, scope string, release func()) {
	noop := func() {}
	if cl == nil || cl.global == nil {
		return true, "", noop
	}

	select {
	case cl.global <- struct{}{}:
	default:
		return false, "global", noop
	}

	release = func() {
		<-cl.global
	}
	return true, "", release
}
