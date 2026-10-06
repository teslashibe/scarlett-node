package x

import "context"

type decodeObserverKey struct{}

// WithDecodeObserver observes this request's response status check, body read
// and GraphQL decoding. The completion flag reflects the existing returned
// error, and no provider content or error text is passed to the observer.
func WithDecodeObserver(ctx context.Context, observe func() func(failed bool)) context.Context {
	if ctx == nil || observe == nil {
		return ctx
	}
	return context.WithValue(ctx, decodeObserverKey{}, observe)
}

func beginObservedDecode(ctx context.Context) (done func(bool)) {
	done = func(bool) {}
	observe, _ := ctx.Value(decodeObserverKey{}).(func() func(bool))
	if observe == nil {
		return done
	}
	defer func() { _ = recover() }()
	if callback := observe(); callback != nil {
		return func(failed bool) {
			defer func() { _ = recover() }()
			callback(failed)
		}
	}
	return done
}
