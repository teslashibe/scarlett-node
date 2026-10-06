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
	"time"
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
	// "xrelay..." stands in for the helper's keyed relay command; every other mode for MPC-TLS.
	command := "prove-x"
	if strings.HasPrefix(mode, "xrelay") {
		command = "relay-x"
	}
	if mode == "xfail" || err != nil || len(os.Args) != 2 || os.Args[1] != command || in.Verifier != "verifier:7047" || len(in.Token) != 64 ||
		!strings.HasPrefix(req, "GET /i/api/graphql/") || !strings.Contains(req, "\r\nConnection: close\r\n") ||
		!strings.Contains(req, "\r\nAccept-Encoding: gzip\r\n") || !strings.HasSuffix(req, "\r\n\r\n") {
		fmt.Fprintln(os.Stderr, "bad prove-x input")
		os.Exit(1)
	}
	if mode == "xdiagfail" || mode == "xdiagcancel" {
		fmt.Fprintln(os.Stderr, `SCARLETT_DIAGNOSTICS={"version":1,"duration_ms":4,"outcome":"error","spans":[{"phase":"x_tcp_connect","start_ms":0,"duration_ms":4,"outcome":"error"}]}`)
		if mode == "xdiagcancel" {
			if marker := os.Getenv("SCARLETT_FAKE_DIAG_READY"); marker != "" {
				_ = os.WriteFile(marker, []byte("synthetic diagnostic emitted"), 0600)
			}
			time.Sleep(time.Second)
		}
		fmt.Fprintln(os.Stderr, "synthetic helper failure")
		os.Exit(1)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	fmt.Fprintf(zw, `{"echo":%q}`, strings.SplitN(req, "\r\n", 2)[0])
	zw.Close()
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", gz.Len(), gz.String())
	summary := map[string]any{"status": "proof_sent", "response": base64.StdEncoding.EncodeToString([]byte(resp))}
	if strings.HasPrefix(mode, "xdiag") {
		time.Sleep(25 * time.Millisecond)
		summary["verifier_sent_bytes"] = 41
		summary["verifier_received_bytes"] = 71
		summary["verifier_transport_layer"] = "tcp_payload"
		switch mode {
		case "xdiag":
			summary["diagnostics"] = json.RawMessage(`{"version":1,"duration_ms":20,"outcome":"success","spans":[{"phase":"x_tcp_connect","start_ms":0,"duration_ms":10,"outcome":"success"}]}`)
		case "xdiaglegacy":
			summary["duration_ms"] = 20
		case "xdiagbad":
			summary["diagnostics"] = json.RawMessage(`{"version":1,"duration_ms":20.1,"duration_ms":10.1,"spans":[],"secret":"SECRET_PRIVATE_DIAGNOSTIC"}`)
		case "xdiagnull":
			summary["diagnostics"] = json.RawMessage(`{"version":1,"duration_ms":null,"outcome":"success","spans":[]}`)
		case "xdiaglegacynull":
			summary["duration_ms"] = nil
		}
	}
	// "...traffic" adds the verifier counters both X helpers flatten into their summary.
	if strings.HasSuffix(mode, "traffic") {
		summary["verifier_sent_bytes"] = 41
		summary["verifier_received_bytes"] = 71
		summary["verifier_transport_layer"] = "tcp_payload"
	}
	out, _ := json.Marshal(summary)
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

// The relay flag changes only which helper command proves the read: the
// request, the refusals and the response handling stay the MPC-TLS ones.
func TestXTransportRelayUsesTheRelayCommandOnly(t *testing.T) {
	read := "https://x.com/i/api/graphql/q/TweetResultByRestId?variables=%7B%7D"
	transport := XTransport{Prover: os.Args[0], Verifier: "verifier:7047", Token: strings.Repeat("ab", 32), Relay: true}
	client := &http.Client{Transport: transport}

	t.Setenv("SCARLETT_FAKE_PROVER", "xrelay")
	resp, err := client.Get(read)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if want := `{"echo":"GET /i/api/graphql/q/TweetResultByRestId?variables=%7B%7D HTTP/1.1"}`; string(body) != want {
		t.Fatalf("relayed read = %q", body)
	}
	if _, err := client.Do(mustRequest(t, http.MethodPost, "https://x.com/i/api/graphql/q/FavoriteTweet")); !errors.Is(err, errUnprovenXCall) {
		t.Fatalf("relay transport sent a write: %v", err)
	}
	// A helper that only speaks MPC-TLS must not be given a relay job, and the reverse.
	t.Setenv("SCARLETT_FAKE_PROVER", "x")
	if _, err := client.Get(read); err == nil {
		t.Fatal("relay transport ran the MPC-TLS command")
	}
	transport.Relay = false
	t.Setenv("SCARLETT_FAKE_PROVER", "xrelay")
	if _, err := (&http.Client{Transport: transport}).Get(read); err == nil {
		t.Fatal("MPC-TLS transport ran the relay command")
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
