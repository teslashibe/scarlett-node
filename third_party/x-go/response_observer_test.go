package x

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type observerFixtureTransport func(*http.Request) (*http.Response, error)

func (f observerFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDecodeObserverReflectsExistingParseError(t *testing.T) {
	for _, body := range []string{`{"data":{}}`, `{"data":`} {
		c := &Client{pacing: &RequestPacing{}, httpClient: &http.Client{Transport: observerFixtureTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})}}
		var begun, completed, failed bool
		ctx := WithDecodeObserver(context.Background(), func() func(bool) {
			begun = true
			return func(value bool) { completed, failed = true, value }
		})
		_, err := c.doGraphQLGET(ctx, "synthetic-id", "synthetic-operation", []byte(`{}`), []byte(`{}`))
		if !begun || !completed || failed != (err != nil) {
			t.Fatal("decode observation disagreed with the existing result", begun, completed, failed, err)
		}
	}
}

func TestDecodeObserverPanicsDoNotChangeRead(t *testing.T) {
	for _, atStart := range []bool{true, false} {
		c := &Client{pacing: &RequestPacing{}, httpClient: &http.Client{Transport: observerFixtureTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"data":{"synthetic":true}}`)), Request: r}, nil
		})}}
		ctx := WithDecodeObserver(context.Background(), func() func(bool) {
			if atStart {
				panic("synthetic observational failure")
			}
			return func(bool) { panic("synthetic observational failure") }
		})
		data, err := c.doGraphQLGET(ctx, "synthetic-id", "synthetic-operation", []byte(`{}`), []byte(`{}`))
		if err != nil || string(data) != `{"synthetic":true}` {
			t.Fatal("observer changed the provider read", string(data), err)
		}
	}
}
