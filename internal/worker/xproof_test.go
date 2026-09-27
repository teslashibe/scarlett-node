package worker

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// fakeXProver answers `prove-x` with a gzipped, chunked X response echoing the
// request line, after checking the request the transport serialized.
func fakeXProver(mode string) {
	var in struct {
		Verifier, Token, Request string
	}
	data, _ := io.ReadAll(os.Stdin)
	_ = json.Unmarshal(data, &in)
	raw, err := base64.StdEncoding.DecodeString(in.Request)
	req := string(raw)
	if mode == "xfail" || err != nil || len(os.Args) != 2 || os.Args[1] != "prove-x" || in.Verifier != "verifier:7047" || len(in.Token) != 64 ||
		!strings.HasPrefix(req, "GET /i/api/graphql/") || !strings.Contains(req, "\r\nConnection: close\r\n") ||
		!strings.Contains(req, "\r\nAccept-Encoding: gzip\r\n") || !strings.HasSuffix(req, "\r\n\r\n") {
		fmt.Fprintln(os.Stderr, "bad prove-x input")
		os.Exit(1)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	fmt.Fprintf(zw, `{"echo":%q}`, strings.SplitN(req, "\r\n", 2)[0])
	zw.Close()
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", gz.Len(), gz.String())
	out, _ := json.Marshal(map[string]any{"status": "proof_sent", "response": base64.StdEncoding.EncodeToString([]byte(resp))})
	fmt.Println(string(out))
	os.Exit(0)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestXTransport(t *testing.T) {
	var passed []string
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		passed = append(passed, r.URL.String())
		return &http.Response{StatusCode: 204, Body: http.NoBody, Request: r}, nil
	})
	client := &http.Client{Transport: XTransport{Prover: os.Args[0], Verifier: "verifier:7047", Token: strings.Repeat("ab", 32), Base: base}}
	read := "https://x.com/i/api/graphql/q/TweetResultByRestId?variables=%7B%7D"

	t.Setenv("SCARLETT_FAKE_PROVER", "x")
	resp, err := client.Get(read)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if want := `{"echo":"GET /i/api/graphql/q/TweetResultByRestId?variables=%7B%7D HTTP/1.1"}`; string(body) != want || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("proven read = %q, encoding %q", body, resp.Header.Get("Content-Encoding"))
	}

	if _, err := client.Get("https://abs.twimg.com/responsive-web/client-web/ondemand.s.a.js"); err != nil || len(passed) != 1 {
		t.Fatalf("non-API request: err %v, passed %v", err, passed)
	}
	for _, refused := range []*http.Request{
		mustRequest(t, http.MethodPost, "https://x.com/i/api/graphql/q/FavoriteTweet"),
		mustRequest(t, http.MethodGet, "https://x.com/i/api/1.1/dm/inbox_initial_state.json"),
	} {
		if _, err := client.Do(refused); !errors.Is(err, errUnprovenXCall) {
			t.Fatalf("%s %s: err %v, want refusal", refused.Method, refused.URL.Path, err)
		}
	}

	t.Setenv("SCARLETT_FAKE_PROVER", "xfail")
	if _, err := client.Get(read); err == nil || !strings.Contains(err.Error(), "bad prove-x input") {
		t.Fatalf("prover failure: err %v", err)
	}
}

func mustRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
