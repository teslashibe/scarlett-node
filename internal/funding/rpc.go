package funding

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Evidence describes test-USDC escrow only. Real revenue and paid eligibility
// require the separately reviewed production payment contract.
type Evidence struct {
	Quote         Quote
	FinalizedSlot uint64
	Prototype     bool
}
type Verifier struct {
	origin string
	trust  Trust
	http   *http.Client
}

func NewRPC(origin string, t Trust) (*Verifier, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" || t.Validate() != nil {
		return nil, ErrInvalid
	}
	// HTTP is reserved for a literal loopback prototype validator. An endpoint
	// selected in a lease never reaches this constructor.
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, ErrInvalid
	}
	mainnet, e := ParseKey("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d")
	if e != nil || t.Genesis == mainnet {
		return nil, ErrInvalid
	}
	return &Verifier{origin: origin, trust: t, http: &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (v *Verifier) call(ctx context.Context, method string, params any, result any) error {
	raw, e := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if e != nil {
		return ErrInvalid
	}
	r, e := http.NewRequestWithContext(ctx, "POST", v.origin, bytes.NewReader(raw))
	if e != nil {
		return ErrInvalid
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := v.http.Do(r)
	if e != nil {
		return ErrInvalid
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrInvalid
	}
	raw, e = io.ReadAll(io.LimitReader(response.Body, 16385))
	if e != nil || len(raw) > 16384 {
		return ErrInvalid
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.JSONRPC != "2.0" || envelope.ID != 1 || (len(envelope.Error) > 0 && !bytes.Equal(envelope.Error, []byte("null"))) || len(envelope.Result) == 0 || bytes.Equal(envelope.Result, []byte("null")) || json.Unmarshal(envelope.Result, result) != nil {
		return ErrInvalid
	}
	return nil
}

// Verify never submits a transaction or calls a provider. Each RPC exchange
// occurs once, uses a reviewed local endpoint and has a combined three-second
// deadline. A transport failure is not evidence that a job is funded.
func (v *Verifier) Verify(ctx context.Context, raw, signature []byte, expected Expected, kind byte, now time.Time) (Evidence, error) {
	started := time.Now()
	if v == nil || v.http == nil {
		return Evidence{}, ErrInvalid
	}
	q, e := VerifyQuote(v.trust, raw, signature, expected, now)
	if e != nil {
		return Evidence{}, e
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var genesis string
	if v.call(ctx, "getGenesisHash", []any{}, &genesis) != nil || genesis != v.trust.Genesis.String() {
		return Evidence{}, ErrInvalid
	}
	job, _, e := PDA(v.trust.Program, []byte("job"), q.JobID[:])
	if e != nil {
		return Evidence{}, e
	}
	escrow, _, e := PDA(v.trust.Program, []byte("escrow"), job[:])
	if e != nil {
		return Evidence{}, e
	}
	addresses := []Key{v.trust.Config, job, escrow}
	keys := []string{addresses[0].String(), addresses[1].String(), addresses[2].String()}
	var snapshot struct {
		Context struct {
			Slot uint64 `json:"slot"`
		} `json:"context"`
		Value []*struct {
			Data       []string `json:"data"`
			Owner      string   `json:"owner"`
			Executable *bool    `json:"executable"`
			Lamports   uint64   `json:"lamports"`
		} `json:"value"`
	}
	if v.call(ctx, "getMultipleAccounts", []any{keys, map[string]any{"commitment": "finalized", "encoding": "base64"}}, &snapshot) != nil || snapshot.Context.Slot == 0 || len(snapshot.Value) != 3 {
		return Evidence{}, ErrInvalid
	}
	accounts := make([]Account, 3)
	for i, a := range snapshot.Value {
		if a == nil || len(a.Data) != 2 || a.Data[1] != "base64" || a.Executable == nil || a.Lamports == 0 {
			return Evidence{}, ErrInvalid
		}
		owner, e := ParseKey(a.Owner)
		if e != nil {
			return Evidence{}, e
		}
		data, e := base64.StdEncoding.Strict().DecodeString(a.Data[0])
		if e != nil || base64.StdEncoding.EncodeToString(data) != a.Data[0] {
			return Evidence{}, ErrInvalid
		}
		accounts[i] = Account{Address: addresses[i], Owner: owner, Executable: *a.Executable, Data: data}
	}
	if CheckAccounts(v.trust, q, kind, accounts[0], accounts[1], accounts[2]) != nil || !time.Unix(int64(q.JobDeadline), 0).After(now.Add(time.Since(started))) {
		return Evidence{}, ErrInvalid
	}
	return Evidence{Quote: q, FinalizedSlot: snapshot.Context.Slot, Prototype: true}, nil
}
