package funding

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFinalizedRPCSnapshotAndTerminalStateRecheck(t *testing.T) {
	v, trust, expected, quote, sig := fixture(t)
	_, _, c, j, a := accountFixture(t)
	var calls atomic.Int32
	var closed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var input struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Error("bad RPC request")
			w.WriteHeader(400)
			return
		}
		var result any
		switch input.Method {
		case "getGenesisHash":
			result = trust.Genesis.String()
		case "getMultipleAccounts":
			var keys []string
			var options map[string]string
			if len(input.Params) != 2 || json.Unmarshal(input.Params[0], &keys) != nil || json.Unmarshal(input.Params[1], &options) != nil || !reflect.DeepEqual(keys, []string{c.Address.String(), j.Address.String(), a.Address.String()}) || options["commitment"] != "finalized" || options["encoding"] != "base64" {
				t.Error("RPC did not request exact canonical finalized accounts")
				w.WriteHeader(400)
				return
			}
			job := append([]byte{}, j.Data...)
			if closed.Load() {
				job[217] = 1
			}
			rows := []any{}
			for _, account := range []Account{c, {Address: j.Address, Owner: j.Owner, Data: job}, a} {
				rows = append(rows, map[string]any{"data": []string{base64.StdEncoding.EncodeToString(account.Data), "base64"}, "owner": account.Owner.String(), "executable": false, "lamports": 1})
			}
			result = map[string]any{"context": map[string]any{"slot": 42}, "value": rows}
		default:
			t.Error("unexpected RPC method")
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	defer server.Close()
	checker, e := NewRPC(server.URL, trust)
	if e != nil {
		t.Fatal(e)
	}
	evidence, e := checker.Verify(context.Background(), quote, sig, expected, 0, time.Unix(v.Now, 0))
	if e != nil || evidence.FinalizedSlot != 42 || !evidence.Prototype || calls.Load() != 2 {
		t.Fatal("finalized prototype snapshot failed", e, evidence, calls.Load())
	}
	closed.Store(true)
	if _, e = checker.Verify(context.Background(), quote, sig, expected, 0, time.Unix(v.Now, 0)); e == nil || calls.Load() != 4 {
		t.Fatal("cached funded evidence survived terminal transition", e)
	}
	bad := append([]byte{}, sig...)
	bad[0] ^= 1
	if _, e = checker.Verify(context.Background(), quote, bad, expected, 0, time.Unix(v.Now, 0)); e == nil || calls.Load() != 4 {
		t.Fatal("invalid signature caused RPC work", e)
	}
}

func TestRPCFailuresAndWrongGenesisNeverBecomeFunding(t *testing.T) {
	v, trust, expected, quote, sig := fixture(t)
	for name, response := range map[string]string{
		"wrong genesis":  `{"jsonrpc":"2.0","id":1,"result":"11111111111111111111111111111111"}`,
		"error":          `{"jsonrpc":"2.0","id":1,"error":{"code":-32000},"result":null}`,
		"wrong id":       `{"jsonrpc":"2.0","id":2,"result":"` + trust.Genesis.String() + `"}`,
		"oversize":       strings.Repeat("x", 16385),
		"trailing JSON":  `{"jsonrpc":"2.0","id":1,"result":"` + trust.Genesis.String() + `"} {}`,
		"missing result": `{"jsonrpc":"2.0","id":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(response)) }))
			defer server.Close()
			checker, e := NewRPC(server.URL, trust)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = checker.Verify(context.Background(), quote, sig, expected, 0, time.Unix(v.Now, 0)); e == nil || calls.Load() != 1 {
				t.Fatal("RPC failure became funding or retried", e, calls.Load())
			}
		})
	}
	t.Run("redirect", func(t *testing.T) {
		var forwarded atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) }))
		defer target.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
		defer server.Close()
		checker, e := NewRPC(server.URL, trust)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = checker.Verify(context.Background(), quote, sig, expected, 0, time.Unix(v.Now, 0)); e == nil || forwarded.Load() != 0 {
			t.Fatal("RPC endpoint redirected", e)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
		}))
		defer server.Close()
		checker, e := NewRPC(server.URL, trust)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		started := time.Now()
		if _, e = checker.Verify(ctx, quote, sig, expected, 0, time.Unix(v.Now, 0)); e == nil || time.Since(started) > time.Second {
			t.Fatal("cancelled RPC became funding or hung", e)
		}
	})
}

func TestRPCOriginAndPrototypeNetworkPins(t *testing.T) {
	_, trust, _, _, _ := fixture(t)
	for _, origin := range []string{"http://localhost:8899", "http://example.com", "ftp://127.0.0.1:8899", "https://user:password@example.com", "https://example.com/#other", ""} {
		if _, e := NewRPC(origin, trust); e == nil {
			t.Fatal("untrusted RPC endpoint accepted")
		}
	}
	mainnet, e := ParseKey("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d")
	if e != nil {
		t.Fatal(e)
	}
	trust.Genesis = mainnet
	if _, e = NewRPC("https://example.invalid", trust); e == nil {
		t.Fatal("prototype accepted mainnet")
	}
}
