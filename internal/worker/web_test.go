package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// fakeWebProver stands in for `scarlett-prover relay-web`. It checks the hop
// input the worker built, logs it for the test and answers as the verifier
// would through OUTCOME: final, or a redirect to the next hop URL.
func fakeWebProver(mode string) {
	var in webHopInput
	data, _ := io.ReadAll(os.Stdin)
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || len(os.Args) != 2 || os.Args[1] != "relay-web" || in.Verifier != "verifier:7047" || len(in.Token) != 64 || in.Port != 443 || len(in.Payload) == 0 || in.TimeoutMS < 1000 || in.TimeoutMS > 30000 {
		fmt.Fprintln(os.Stderr, "bad relay-web input")
		os.Exit(2)
	}
	if ip, err := netip.ParseAddr(in.IP); err != nil || ip.Zone() != "" {
		fmt.Fprintln(os.Stderr, "relay-web input without an IP literal")
		os.Exit(2)
	}
	if log := os.Getenv("SCARLETT_FAKE_WEB_LOG"); log != "" {
		f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			f.Write(append(bytes.TrimSpace(data), '\n'))
			f.Close()
		}
	}
	var payload struct {
		MaxRedirects int `json:"max_redirects"`
	}
	_ = json.Unmarshal(in.Payload, &payload)
	fail := func(class string) {
		fmt.Fprintln(os.Stderr, `SCARLETT_DIAGNOSTICS={"version":1,"duration_ms":4,"outcome":"error","spans":[{"phase":"x_tcp_connect","start_ms":0,"duration_ms":4,"outcome":"error"}]}`)
		fmt.Fprintln(os.Stderr, "Error: synthetic relay-web failure")
		fmt.Fprintln(os.Stderr, webErrorPrefix+class)
		os.Exit(1)
	}
	summary := map[string]any{"status": "proof_sent", "verifier_sent_bytes": 900 + in.Hop, "verifier_received_bytes": 4000, "verifier_transport_layer": "tcp_payload", "hop": in.Hop, "status_code": 200, "final": true, "target_sent_bytes": 300, "target_received_bytes": 4000, "duration_ms": 12, "diagnostics": json.RawMessage(`{"version":1,"duration_ms":10,"outcome":"success","spans":[{"phase":"x_tcp_connect","start_ms":0,"duration_ms":3,"outcome":"success"}]}`)}
	redirect := func(next string) {
		summary["status_code"], summary["final"], summary["next_url"] = 301, false, next
	}
	switch mode {
	case "web-final":
	case "web-chain":
		// example.com -> www.example.com/a -> cdn.example.net/b (final)
		switch in.Hop {
		case 0:
			redirect("https://www.example.com/a")
		case 1:
			redirect("https://cdn.example.net/b")
		}
	case "web-loop":
		// The verifier makes the last allowed hop final.
		if in.Hop < payload.MaxRedirects {
			redirect(fmt.Sprintf("https://www.example.com/%d", in.Hop+1))
		}
	case "web-liar":
		// Claims another hop past the payload's redirect limit.
		redirect(fmt.Sprintf("https://www.example.com/%d", in.Hop+1))
	case "web-later-fails":
		if in.Hop > 0 {
			fail("fetch_failed")
		}
		redirect("https://www.example.com/")
	case "web-later-misuse":
		if in.Hop > 0 {
			fmt.Fprintln(os.Stderr, "Error: "+relayMisuseMarker)
			os.Exit(1)
		}
		redirect("https://www.example.com/")
	case "web-connect":
		fail("connect_failed")
	case "web-proxy":
		fail("proxy_failed")
	case "web-fetch":
		fail("fetch_failed")
	case "web-unclassified":
		fmt.Fprintln(os.Stderr, "Error: something else")
		os.Exit(1)
	case "web-misuse":
		fmt.Fprintln(os.Stderr, "Error: "+relayMisuseMarker)
		os.Exit(1)
	case "web-sleep":
		time.Sleep(time.Minute)
	case "web-big":
		summary["padding"] = strings.Repeat("a", maxWebStdout)
	case "web-wronghop":
		summary["hop"] = in.Hop + 1
	case "web-insecure-next":
		redirect("http://www.example.com/")
	case "web-float":
		summary["status_code"] = 200.5
	}
	out, _ := json.Marshal(summary)
	fmt.Println(string(out))
	os.Exit(0)
}

func webFixtureLease(t *testing.T) coordinator.Lease {
	t.Helper()
	raw, err := os.ReadFile("../../api/fixtures/lease-web.json")
	if err != nil {
		t.Fatal(err)
	}
	var l coordinator.Lease
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	l.LeaseDeadline = time.Now().Add(118 * time.Second)
	l.SettlementDeadline = l.LeaseDeadline
	return l
}

func webConfig() config.Config {
	return config.Config{Executor: config.ExecutorServices, Services: []string{"web"}, Verifier: "verifier:7047", Prover: os.Args[0], Profile: "standard", MaxInputBytes: 32768, MaxOutputTokens: 2048, WebConcurrency: 4, InferenceTimeout: 5 * time.Second}
}

// webLease rebuilds lease terms around a different payload and request URL,
// keeping the digests consistent so only the intended rule is under test.
func webLease(t *testing.T, mutate func(*webPlan)) coordinator.Lease {
	t.Helper()
	l := webFixtureLease(t)
	plan, ok := decodeWebPlan(l.WebPayload)
	if !ok {
		t.Fatal("fixture payload refused")
	}
	mutate(&plan)
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	l.WebPayload = raw
	l.WebRequest = &coordinator.WebRequest{Operation: "scrape", URL: plan.URL}
	request, _ := json.Marshal(l.WebRequest)
	l.InputSHA256 = SHA(string(request))
	return l
}

func TestValidateWebLease(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	c := webConfig()
	l := webFixtureLease(t)
	plan, deadline, code := validateWebLease(c, l)
	if code != "" || plan.URL != "https://example.com/" || plan.MaxRedirects != 5 || len(plan.Headers) != 3 || !bytes.Equal(plan.raw, l.WebPayload) {
		t.Fatal("fixture lease refused", code)
	}
	if want := l.LeaseDeadline.Add(-webReportMargin); !deadline.Equal(want) {
		t.Fatal("report margin not kept", deadline, want)
	}
	if limit := ProofSampleLimit(c, l); limit != 6 {
		t.Fatal("proof sample limit", limit)
	}
	setPayload := func(l *coordinator.Lease, payload string) { l.WebPayload = json.RawMessage(payload) }
	a2 := string(l.WebPayload)
	for name, mutate := range map[string]func(*coordinator.Lease){
		"input digest": func(l *coordinator.Lease) { l.InputSHA256 = strings.Repeat("0", 64) },
		"url mismatch": func(l *coordinator.Lease) {
			setPayload(l, strings.Replace(a2, "https://example.com/", "https://example.org/", 1))
		},
		"http url": func(l *coordinator.Lease) { *l = webLease(t, func(p *webPlan) { p.URL = "http://example.com/" }) },
		"unknown payload field": func(l *coordinator.Lease) {
			setPayload(l, strings.Replace(a2, `"type":"web.fetch"`, `"type":"web.fetch","cookie":"a"`, 1))
		},
		"duplicate key": func(l *coordinator.Lease) {
			setPayload(l, strings.Replace(a2, `"type":"web.fetch"`, `"type":"web.fetch","type":"web.fetch"`, 1))
		},
		"float": func(l *coordinator.Lease) {
			setPayload(l, strings.Replace(a2, `"max_redirects":5`, `"max_redirects":5.0`, 1))
		},
		"missing headers": func(l *coordinator.Lease) { setPayload(l, strings.Replace(a2, `,"headers":[`, `,"x":[`, 1)) },
		"null headers": func(l *coordinator.Lease) {
			setPayload(l, a2[:strings.Index(a2, `"headers"`)]+`"headers":null}`)
		},
		"missing max_redirects": func(l *coordinator.Lease) { setPayload(l, strings.Replace(a2, `"max_redirects":5,`, ``, 1)) },
		"header not allowlisted": func(l *coordinator.Lease) {
			*l = webLease(t, func(p *webPlan) { p.Headers[0].Name = "cookie" })
		},
		"header out of order": func(l *coordinator.Lease) {
			*l = webLease(t, func(p *webPlan) { p.Headers[0], p.Headers[1] = p.Headers[1], p.Headers[0] })
		},
		"header repeated": func(l *coordinator.Lease) {
			*l = webLease(t, func(p *webPlan) { p.Headers[1] = p.Headers[0] })
		},
		"header value control": func(l *coordinator.Lease) {
			*l = webLease(t, func(p *webPlan) { p.Headers[0].Value = "a\r\nCookie: b" })
		},
		"header value space": func(l *coordinator.Lease) { *l = webLease(t, func(p *webPlan) { p.Headers[0].Value = " a" }) },
		"header value long": func(l *coordinator.Lease) {
			*l = webLease(t, func(p *webPlan) { p.Headers[0].Value = strings.Repeat("a", 513) })
		},
		"max_redirects 6":      func(l *coordinator.Lease) { *l = webLease(t, func(p *webPlan) { p.MaxRedirects = 6 }) },
		"max_redirects -1":     func(l *coordinator.Lease) { *l = webLease(t, func(p *webPlan) { p.MaxRedirects = -1 }) },
		"response bytes 0":     func(l *coordinator.Lease) { *l = webLease(t, func(p *webPlan) { p.MaxResponseBytes = 0 }) },
		"response bytes large": func(l *coordinator.Lease) { *l = webLease(t, func(p *webPlan) { p.MaxResponseBytes = 10<<20 + 1 }) },
		"proof mode":           func(l *coordinator.Lease) { *l = webLease(t, func(p *webPlan) { p.ProofMode = "mpc" }) },
		"proof policy":         func(l *coordinator.Lease) { *l = webLease(t, func(p *webPlan) { p.ProofPolicy = "x-relay-v1" }) },
		"payload type":         func(l *coordinator.Lease) { *l = webLease(t, func(p *webPlan) { p.Type = "x.read" }) },
		"missing token":        func(l *coordinator.Lease) { l.VerifierToken = "" },
		"short token":          func(l *coordinator.Lease) { l.VerifierToken = "ab" },
		"codex payload":        func(l *coordinator.Lease) { l.CodexPayload = json.RawMessage(`{}`) },
		"x request":            func(l *coordinator.Lease) { l.XRequest = &coordinator.XRequest{Operation: "post", PostID: "1"} },
		"x payload":            func(l *coordinator.Lease) { l.XPayload = json.RawMessage(`{}`) },
		"model":                func(l *coordinator.Lease) { l.ModelID = "gpt-5.5" },
		"tokens":               func(l *coordinator.Lease) { l.MaxOutputTokens = 1 },
		"operation": func(l *coordinator.Lease) {
			l.WebRequest = &coordinator.WebRequest{Operation: "crawl", URL: "https://example.com/"}
		},
		"no request": func(l *coordinator.Lease) { l.WebRequest = nil },
		"service":    func(l *coordinator.Lease) { l.ServiceType = "x_read" },
		"profile":    func(l *coordinator.Lease) { l.Profile = "other" },
		"oversized request": func(l *coordinator.Lease) {
			*l = webLease(t, func(p *webPlan) { p.URL = "https://example.com/" + strings.Repeat("a", 2000) })
		},
	} {
		m := webFixtureLease(t)
		mutate(&m)
		cc := c
		if name == "oversized request" {
			cc.MaxInputBytes = 1024
		}
		if _, _, code := validateWebLease(cc, m); code != "invalid_lease" {
			t.Errorf("%s: code %q, want invalid_lease", name, code)
		}
	}
	// Well-formed terms naming a page the node refuses to fetch.
	for _, url := range []string{"https://Example.com/", "https://x.com/", "https://www.twitter.com/a", "https://printer.local/", "https://10.0.0.1/", "https://example.com:8443/", "https://user@example.com/"} {
		m := webLease(t, func(p *webPlan) { p.URL = url })
		if _, _, code := validateWebLease(c, m); code != "web_egress_denied" {
			t.Errorf("%s: code %q, want web_egress_denied", url, code)
		}
		if run := runWeb(t, "web-final", m, c, publicAnswers); run.code != "web_egress_denied" || len(run.asked) != 0 || len(run.inputs) != 0 {
			t.Errorf("%s: run %q, asked %v", url, run.code, run.asked)
		}
	}
	expired := webFixtureLease(t)
	expired.LeaseDeadline = time.Now().Add(webReportMargin - time.Second)
	if _, _, code := validateWebLease(c, expired); code != "expired" {
		t.Fatal("lease inside the report margin ran", code)
	}
	HaltRelay("test")
	if _, _, code := validateWebLease(c, l); code != "invalid_lease" || WebOfferServable(c, l.WebPayload) {
		t.Fatal("halted relay still serves web")
	}
}

func TestWebOfferServable(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	c := webConfig()
	l := webFixtureLease(t)
	if !WebOfferServable(c, l.WebPayload) {
		t.Fatal("fixture offer refused")
	}
	for _, payload := range []string{"", "{", `{"proof_mode":"mpc","proof_policy":"web-relay-v1"}`, `{"proof_mode":"relay","proof_policy":"x-relay-v1"}`, `{"proof_mode":"relay"}`} {
		if WebOfferServable(c, json.RawMessage(payload)) {
			t.Fatalf("payload %q servable", payload)
		}
	}
}

// fakeResolver answers from a fixed table and records every host asked.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	asked   []string
}

func (r *fakeResolver) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, host)
	if addrs, ok := r.answers[host]; ok {
		return addrs, nil
	}
	return nil, errors.New("synthetic NXDOMAIN")
}

func addrs(values ...string) []netip.Addr {
	out := []netip.Addr{}
	for _, v := range values {
		out = append(out, netip.MustParseAddr(v))
	}
	return out
}

// staticEgress is a guard with no NAT64 prefix and no local address.
func staticEgress() *WebEgress { return NewWebEgressWith(nil, nil) }

type webRun struct {
	code   string
	inputs []webHopInput
	asked  []string
}

func runWeb(t *testing.T, mode string, l coordinator.Lease, c config.Config, answers map[string][]netip.Addr) webRun {
	t.Helper()
	log := filepath.Join(t.TempDir(), "relay-web.log")
	t.Setenv("SCARLETT_FAKE_PROVER", mode)
	t.Setenv("SCARLETT_FAKE_WEB_LOG", log)
	r := &fakeResolver{answers: answers}
	code := Web{Config: c, Resolver: r.resolve, Egress: staticEgress()}.Run(context.Background(), l)
	run := webRun{code: code, asked: r.asked}
	raw, err := os.ReadFile(log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var in webHopInput
		if err := json.Unmarshal(line, &in); err != nil {
			t.Fatal(err)
		}
		run.inputs = append(run.inputs, in)
	}
	return run
}

var publicAnswers = map[string][]netip.Addr{
	"example.com":     addrs("2606:2800:21f:cb07:6820:80da:af6b:8b2c", "93.184.215.14"),
	"www.example.com": addrs("2606:2800:21f:cb07:6820:80da:af6b:8b2c"),
	"cdn.example.net": addrs("::ffff:151.101.1.57", "151.101.65.57"),
}

func TestWebRunHops(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	c := webConfig()
	t.Run("single final hop", func(t *testing.T) {
		run := runWeb(t, "web-final", webFixtureLease(t), c, publicAnswers)
		if run.code != "" || len(run.inputs) != 1 {
			t.Fatal(run.code, len(run.inputs))
		}
		in := run.inputs[0]
		// The checked IPv4 address, never a hostname-only dial.
		if in.IP != "93.184.215.14" || in.Port != 443 || in.URL != "https://example.com/" || in.Hop != 0 || in.Proxy != nil || !bytes.Equal(in.Payload, webFixtureLease(t).WebPayload) || in.Token != strings.Repeat("ab", 32) || in.TimeoutMS != 30000 {
			t.Fatalf("unexpected hop input %+v", in)
		}
	})
	t.Run("redirect chain", func(t *testing.T) {
		run := runWeb(t, "web-chain", webFixtureLease(t), c, publicAnswers)
		if run.code != "" || len(run.inputs) != 3 {
			t.Fatal(run.code, len(run.inputs))
		}
		if strings.Join(run.asked, ",") != "example.com,www.example.com,cdn.example.net" {
			t.Fatal("each hop must resolve its own host", run.asked)
		}
		want := []struct{ url, ip string }{{"https://example.com/", "93.184.215.14"}, {"https://www.example.com/a", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"}, {"https://cdn.example.net/b", "151.101.1.57"}}
		for i, in := range run.inputs {
			if in.Hop != i || in.URL != want[i].url || in.IP != want[i].ip {
				t.Fatalf("hop %d: %+v", i, in)
			}
		}
	})
	t.Run("redirect limit", func(t *testing.T) {
		run := runWeb(t, "web-loop", webFixtureLease(t), c, publicAnswers)
		if run.code != "" || len(run.inputs) != 6 {
			t.Fatal(run.code, len(run.inputs))
		}
		limited := webLease(t, func(p *webPlan) { p.MaxRedirects = 0 })
		if run = runWeb(t, "web-liar", limited, c, publicAnswers); run.code != "web_fetch_failed" || len(run.inputs) != 1 {
			t.Fatal("hop-0 helper claiming a redirect past the limit", run.code, len(run.inputs))
		}
		if run = runWeb(t, "web-liar", webFixtureLease(t), c, publicAnswers); run.code != "" || len(run.inputs) != 6 {
			t.Fatal("later helper claiming a redirect past the limit", run.code, len(run.inputs))
		}
	})
	t.Run("later hop DNS failure is proven", func(t *testing.T) {
		answers := map[string][]netip.Addr{"example.com": publicAnswers["example.com"]}
		run := runWeb(t, "web-chain", webFixtureLease(t), c, answers)
		if run.code != "" || len(run.inputs) != 1 || len(run.asked) != 2 {
			t.Fatal(run.code, len(run.inputs), run.asked)
		}
	})
	t.Run("later hop egress denial is proven", func(t *testing.T) {
		answers := map[string][]netip.Addr{"example.com": publicAnswers["example.com"], "www.example.com": addrs("192.168.1.1")}
		if run := runWeb(t, "web-chain", webFixtureLease(t), c, answers); run.code != "" || len(run.inputs) != 1 {
			t.Fatal(run.code, len(run.inputs))
		}
	})
	t.Run("later hop helper failure is proven", func(t *testing.T) {
		if run := runWeb(t, "web-later-fails", webFixtureLease(t), c, publicAnswers); run.code != "" || len(run.inputs) != 2 {
			t.Fatal(run.code, len(run.inputs))
		}
	})
	t.Run("insecure next URL from the helper ends the chain", func(t *testing.T) {
		if run := runWeb(t, "web-insecure-next", webFixtureLease(t), c, publicAnswers); run.code != "web_fetch_failed" || len(run.inputs) != 1 {
			t.Fatal(run.code, len(run.inputs))
		}
	})
	for _, tc := range []struct {
		name, mode, code string
		answers          map[string][]netip.Addr
	}{
		{"dns failure", "web-final", "web_dns_failed", map[string][]netip.Addr{}},
		{"no addresses", "web-final", "web_dns_failed", map[string][]netip.Addr{"example.com": {}}},
		{"private address", "web-final", "web_egress_denied", map[string][]netip.Addr{"example.com": addrs("10.1.2.3")}},
		{"mixed public and private", "web-final", "web_egress_denied", map[string][]netip.Addr{"example.com": addrs("93.184.215.14", "127.0.0.1")}},
		{"connect", "web-connect", "web_connect_failed", publicAnswers},
		{"proxy", "web-proxy", "web_proxy_failed", publicAnswers},
		{"fetch", "web-fetch", "web_fetch_failed", publicAnswers},
		{"unclassified", "web-unclassified", "web_fetch_failed", publicAnswers},
		{"stdout over the cap", "web-big", "web_fetch_failed", publicAnswers},
		{"wrong hop", "web-wronghop", "web_fetch_failed", publicAnswers},
		{"float in summary", "web-float", "web_fetch_failed", publicAnswers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := runWeb(t, tc.mode, webFixtureLease(t), c, tc.answers)
			if run.code != tc.code {
				t.Fatalf("code %q, want %q", run.code, tc.code)
			}
			if (tc.code == "web_dns_failed" || tc.code == "web_egress_denied") && len(run.inputs) != 0 {
				t.Fatal("helper ran for a refused hop")
			}
		})
	}
	t.Run("missing helper", func(t *testing.T) {
		missing := c
		missing.Prover = filepath.Join(t.TempDir(), "no-such-helper")
		if run := runWeb(t, "web-final", webFixtureLease(t), missing, publicAnswers); run.code != "prover_error" {
			t.Fatal(run.code)
		}
	})
	t.Run("non-canonical hop", func(t *testing.T) {
		r := &fakeResolver{answers: publicAnswers}
		out := Web{Config: c, Resolver: r.resolve, Egress: staticEgress()}.hop(context.Background(), webPlan{}, "", 0, "https://Example.com/", r.resolve, staticEgress())
		if out.code != "web_egress_denied" || len(r.asked) != 0 {
			t.Fatal("non-canonical hop URL resolved", out.code)
		}
	})
}

func TestWebRunMisuseHaltsRelay(t *testing.T) {
	for _, mode := range []string{"web-misuse", "web-later-misuse"} {
		t.Run(mode, func(t *testing.T) {
			ResetRelayHaltForTests()
			t.Cleanup(ResetRelayHaltForTests)
			run := runWeb(t, mode, webFixtureLease(t), webConfig(), publicAnswers)
			if run.code != "relay_misuse" || !RelayHalted() {
				t.Fatal("misuse not latched", run.code)
			}
			if WebOfferServable(webConfig(), webFixtureLease(t).WebPayload) {
				t.Fatal("halted node still offers web")
			}
		})
	}
}

func TestWebRunDeadline(t *testing.T) {
	ResetRelayHaltForTests()
	l := webFixtureLease(t)
	l.LeaseDeadline = time.Now().Add(webReportMargin + 2500*time.Millisecond)
	l.SettlementDeadline = l.LeaseDeadline
	started := time.Now()
	run := runWeb(t, "web-sleep", l, webConfig(), publicAnswers)
	if run.code != "expired" || len(run.inputs) != 1 || run.inputs[0].TimeoutMS > 2500 || time.Since(started) > 5*time.Second {
		t.Fatal("deadline not enforced", run.code, time.Since(started))
	}
	l.LeaseDeadline = time.Now().Add(webReportMargin + 500*time.Millisecond)
	l.SettlementDeadline = l.LeaseDeadline
	if run = runWeb(t, "web-final", l, webConfig(), publicAnswers); run.code != "expired" || len(run.inputs) != 0 {
		t.Fatal("a hop with under a second left ran", run.code)
	}
}

// The proxy reaches the helper, which needs it, and nothing else: no status,
// heartbeat, formatted configuration or log line repeats it.
func TestWebProxyStaysLocal(t *testing.T) {
	ResetRelayHaltForTests()
	proxy, err := config.ParseWebProxy("http://synthetic-user:synthetic-secret@proxy.synthetic.invalid:8080")
	if err != nil {
		t.Fatal(err)
	}
	c := webConfig()
	c.WebEgressProxy = proxy
	run := runWeb(t, "web-final", webFixtureLease(t), c, publicAnswers)
	if run.code != "" || len(run.inputs) != 1 {
		t.Fatal(run.code)
	}
	in := run.inputs[0]
	if in.Proxy == nil || in.Proxy.Host != "proxy.synthetic.invalid" || in.Proxy.Port != 8080 || in.Proxy.Authorization != "Basic c3ludGhldGljLXVzZXI6c3ludGhldGljLXNlY3JldA==" || in.IP != "93.184.215.14" {
		t.Fatalf("proxy hop input %+v", in.Proxy)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		text := fmt.Sprintf(format, c) + fmt.Sprintf(format, *c.WebEgressProxy) + fmt.Sprintf(format, c.WebEgressProxy)
		for _, secret := range []string{"synthetic-secret", "synthetic-user", "proxy.synthetic.invalid", "c3ludGhldGlj"} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s prints the proxy: %s", format, secret)
			}
		}
	}
}

func TestWebProofTrafficSamplesEachHop(t *testing.T) {
	ResetRelayHaltForTests()
	var mu sync.Mutex
	samples := []attempts.ProofSample{}
	begun := 0
	ctx := WithProofObserver(context.Background(), func() (func(attempts.ProofSample) error, error) {
		mu.Lock()
		begun++
		ordinal := begun
		mu.Unlock()
		return func(s attempts.ProofSample) error {
			mu.Lock()
			defer mu.Unlock()
			s.Ordinal = ordinal
			samples = append(samples, s)
			return nil
		}, nil
	})
	t.Setenv("SCARLETT_FAKE_PROVER", "web-chain")
	r := &fakeResolver{answers: publicAnswers}
	if code := (Web{Config: webConfig(), Resolver: r.resolve, Egress: staticEgress()}).Run(ctx, webFixtureLease(t)); code != "" {
		t.Fatal(code)
	}
	if len(samples) != 3 {
		t.Fatal("one sample per hop", len(samples))
	}
	for i, s := range samples {
		if s.Ordinal != i+1 || s.State != "complete" || *s.SentBytes != uint64(900+i) || *s.ReceivedBytes != 4000 {
			t.Fatalf("sample %d: %+v", i, s)
		}
	}
}

func TestParseWebSummaryStatusRange(t *testing.T) {
	for _, tc := range []struct {
		status string
		ok     bool
	}{{"200", true}, {"404", true}, {"999", true}, {"103", false}, {"1000", false}} {
		line := []byte(`{"status":"proof_sent","hop":0,"url":"https://example.com/","status_code":` + tc.status + `,"final":true}`)
		out, err := parseWebSummary(line, false, 0, "https://example.com/", 5)
		if (err == nil) != tc.ok || tc.ok && !out.final {
			t.Fatalf("status %s: %+v %v", tc.status, out, err)
		}
	}
}
