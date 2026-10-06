package x

import "context"

type waitObserverKey struct{}

// WithWaitObserver observes only the actual pacing sleep of this request.
// Reason is "gap", "jitter", "spread" or "reset". The returned callback
// runs after that actual sleep or context cancellation.
// Observers receive no request, response, account or credential values.
func WithWaitObserver(ctx context.Context, observe func(reason string) func(cancelled bool)) context.Context {
	if ctx == nil || observe == nil {
		return ctx
	}
	return context.WithValue(ctx, waitObserverKey{}, observe)
}

func beginObservedWait(ctx context.Context, reason string) (done func(bool)) {
	done = func(bool) {}
	observe, _ := ctx.Value(waitObserverKey{}).(func(string) func(bool))
	if observe == nil {
		return done
	}
	// Observational code cannot change provider work if an observer panics.
	defer func() { _ = recover() }()
	if callback := observe(reason); callback != nil {
		return func(cancelled bool) {
			defer func() { _ = recover() }()
			callback(cancelled)
		}
	}
	return done
}
