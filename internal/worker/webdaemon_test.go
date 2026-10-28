package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// fakeLog appends one JSON line to the file named by env, if set.
func fakeLog(env string, v any) {
	path := os.Getenv(env)
	if path == "" {
		return
	}
	raw, _ := json.Marshal(v)
	if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
		f.Write(append(raw, '\n'))
		f.Close()
	}
}

// fakeRelayWebInput reads relay-web's stdin into in and returns the input as
// one line. A pre-dialed hop (E1) logs its first line to
// SCARLETT_FAKE_PREDIAL_LOG, then waits for the token line; end of input
// there ends it as the real helper does, unsent.
func fakeRelayWebInput(in *webHopInput) []byte {
	stdin := bufio.NewReader(os.Stdin)
	first, _ := stdin.ReadBytes('\n')
	d := json.NewDecoder(bytes.NewReader(first))
	d.DisallowUnknownFields()
	if d.Decode(in) != nil {
		fmt.Fprintln(os.Stderr, "bad relay-web input")
		os.Exit(2)
	}
	if !in.Predial {
		return first
	}
	if in.Token != "" {
		fmt.Fprintln(os.Stderr, "a pre-dial carries no token")
		os.Exit(2)
	}
	fakeLog("SCARLETT_FAKE_PREDIAL_LOG", map[string]any{"event": "waiting", "input": json.RawMessage(bytes.TrimSpace(first))})
	second, err := stdin.ReadBytes('\n')
	if len(bytes.TrimSpace(second)) == 0 && err == io.EOF {
		fakeLog("SCARLETT_FAKE_PREDIAL_LOG", map[string]any{"event": "aborted"})
		fmt.Println(`{"status":"predial_aborted","verifier_sent_bytes":512,"verifier_received_bytes":2048,"verifier_transport_layer":"tcp_payload","duration_ms":3}`)
		os.Exit(0)
	}
	var line struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(second, &line) != nil || len(line.Token) != 64 {
		fmt.Fprintln(os.Stderr, "bad token line")
		os.Exit(2)
	}
	fakeLog("SCARLETT_FAKE_PREDIAL_LOG", map[string]any{"event": "token"})
	in.Token, in.Predial = line.Token, false
	merged, _ := json.Marshal(in)
	return merged
}

// fakeWebDaemon stands in for `scarlett-prover serve` when the mode starts
// with "web-daemon": it logs every request to SCARLETT_FAKE_DAEMON_LOG and
// answers a hop as fakeWebProver answers relay-web. Other modes have no
// daemon: it exits, and the node runs hops one-shot.
func fakeWebDaemon(mode string) {
	if !strings.HasPrefix(mode, "web-daemon") {
		os.Exit(2)
	}
	stdin := bufio.NewReader(os.Stdin)
	stdout := bufio.NewWriter(os.Stdout)
	write := func(v any) {
		raw, _ := json.Marshal(v)
		binary.Write(stdout, binary.BigEndian, uint32(len(raw)))
		stdout.Write(raw)
		stdout.Flush()
	}
	write(map[string]any{"type": "ready", "version": 1})
	waiting := map[string]webHopInput{}
	answer := func(id string, in webHopInput) {
		switch mode {
		case "web-daemon-crash-before":
			os.Exit(3)
		case "web-daemon-silent":
			// Stuck: the hop is never answered.
			return
		}
		write(map[string]any{"type": "presenting", "id": id})
		summary := map[string]any{"status": "proof_sent", "verifier_sent_bytes": 900 + in.Hop, "verifier_received_bytes": 4000, "verifier_transport_layer": "tcp_payload", "hop": in.Hop, "status_code": 200, "final": true, "target_sent_bytes": 300, "target_received_bytes": 4000, "duration_ms": 12, "diagnostics": json.RawMessage(`{"version":1,"duration_ms":10,"outcome":"success","spans":[{"phase":"pool_checkout_warm","start_ms":0,"duration_ms":0,"outcome":"success"},{"phase":"x_tcp_connect","start_ms":0,"duration_ms":3,"outcome":"success"}]}`)}
		switch mode {
		case "web-daemon-crash-after":
			os.Exit(3)
		case "web-daemon-misuse":
			write(map[string]any{"type": "error", "id": id, "class": "fetch_failed", "error": relayMisuseMarker + ": synthetic", "presented": true, "diagnostics": json.RawMessage(`{"version":1,"duration_ms":4,"outcome":"error","spans":[]}`)})
			return
		case "web-daemon-unopened":
			write(map[string]any{"type": "error", "id": id, "class": "fetch_failed", "error": relayUnopenedMarker + ": it ended the hop first (session_timeout)", "presented": true, "diagnostics": json.RawMessage(`{"version":1,"duration_ms":4,"outcome":"error","spans":[]}`)})
			return
		case "web-daemon-late-unopened":
			// The session runs to its own deadline, after the job's.
			time.Sleep(2500 * time.Millisecond)
			write(map[string]any{"type": "error", "id": id, "class": "fetch_failed", "error": relayUnopenedMarker + ": the session ended first: relay session timed out", "presented": true, "diagnostics": json.RawMessage(`{"version":1,"duration_ms":2500,"outcome":"error","spans":[]}`)})
			return
		case "web-daemon-too-large":
			write(map[string]any{"type": "error", "id": id, "class": "page_too_large", "error": "verifier ended the hop: page_too_large", "presented": true, "diagnostics": json.RawMessage(`{"version":1,"duration_ms":40,"outcome":"error","spans":[{"phase":"relay_session","start_ms":2,"duration_ms":38,"outcome":"error"}]}`)})
			return
		case "web-daemon-chain":
			switch in.Hop {
			case 0:
				summary["status_code"], summary["final"], summary["next_url"] = 301, false, "https://www.example.com/a"
			case 1:
				summary["status_code"], summary["final"], summary["next_url"] = 301, false, "https://cdn.example.net/b"
			}
		}
		write(map[string]any{"type": "summary", "id": id, "summary": summary})
	}
	for {
		var size uint32
		if binary.Read(stdin, binary.BigEndian, &size) != nil {
			os.Exit(0)
		}
		raw := make([]byte, size)
		if _, err := io.ReadFull(stdin, raw); err != nil {
			os.Exit(0)
		}
		var request struct {
			Type  string          `json:"type"`
			ID    string          `json:"id"`
			Token string          `json:"token"`
			Size  int             `json:"size"`
			Input json.RawMessage `json:"input"`
		}
		json.Unmarshal(raw, &request)
		var in webHopInput
		if request.Type == "hop" {
			d := json.NewDecoder(bytes.NewReader(request.Input))
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil || in.Predial {
				os.Exit(4)
			}
		}
		fakeLog("SCARLETT_FAKE_DAEMON_LOG", map[string]any{"type": request.Type, "id": request.ID, "size": request.Size, "hop": in.Hop, "url": in.URL, "token": request.Token + in.Token})
		switch request.Type {
		case "hop":
			if in.Token == "" {
				waiting[request.ID] = in
			} else {
				answer(request.ID, in)
			}
		case "token":
			in, ok := waiting[request.ID]
			delete(waiting, request.ID)
			if ok {
				in.Token = request.Token
				answer(request.ID, in)
			}
		case "cancel":
			if _, ok := waiting[request.ID]; ok {
				delete(waiting, request.ID)
				write(map[string]any{"type": "cancelled", "id": request.ID, "diagnostics": json.RawMessage(`{"version":1,"duration_ms":4,"outcome":"cancelled","spans":[]}`)})
			}
		}
	}
}

// fakeLines reads a fake helper's JSON-lines log.
func fakeLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var lines []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var v map[string]any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, v)
	}
	return lines
}

// eventually waits for a fake log to hold n lines.
func eventually(t *testing.T, path string, n int) []map[string]any {
	t.Helper()
	for start := time.Now(); time.Since(start) < 10*time.Second; time.Sleep(10 * time.Millisecond) {
		if lines := fakeLines(t, path); len(lines) >= n {
			return lines
		}
	}
	t.Fatalf("%s never had %d lines: %v", filepath.Base(path), n, fakeLines(t, path))
	return nil
}

// useWebDaemon runs this test's hops on the daemon when the mode has one.
func useWebDaemon(t *testing.T, mode string) (daemonLog, webLog, predialLog string) {
	t.Helper()
	// Not t.TempDir: a daemon a test abandoned is killed about two seconds
	// after it is replaced and may still write its log while the test ends,
	// so removal retries until that process is gone.
	dir, err := os.MkdirTemp("", "webdaemon-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for range 50 {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Errorf("daemon test directory %s still busy", dir)
	})
	daemonLog, webLog, predialLog = filepath.Join(dir, "daemon.log"), filepath.Join(dir, "relay-web.log"), filepath.Join(dir, "predial.log")
	t.Setenv("SCARLETT_FAKE_PROVER", mode)
	t.Setenv("SCARLETT_FAKE_DAEMON_LOG", daemonLog)
	t.Setenv("SCARLETT_FAKE_WEB_LOG", webLog)
	t.Setenv("SCARLETT_FAKE_PREDIAL_LOG", predialLog)
	resetWebDaemons()
	webDaemonEnabled.Store(true)
	t.Cleanup(func() {
		webDaemonEnabled.Store(false)
		resetWebDaemons()
	})
	return
}

// resetWebDaemons ends every daemon and forgets its crashes.
func resetWebDaemons() {
	StopWebDaemons()
	webDaemons.Lock()
	webDaemons.crashes = map[daemonKey][]time.Time{}
	webDaemons.Unlock()
}

// webOffer is the fixture lease as offered: no token yet.
func webOffer(t *testing.T) coordinator.Lease {
	l := webFixtureLease(t)
	l.VerifierToken = ""
	l.AcceptanceRequired = true
	return l
}

func webWorkerFor(answers map[string][]netip.Addr) Web {
	r := &fakeResolver{answers: answers}
	return Web{Config: webConfig(), Resolver: r.resolve, Egress: staticEgress(), busyWait: func(int) time.Duration { return 10 * time.Millisecond }}
}

func TestWebHopsRunOnTheDaemon(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	daemonLog, webLog, _ := useWebDaemon(t, "web-daemon-chain")
	report := webWorkerFor(publicAnswers).Report(context.Background(), webFixtureLease(t))
	if report.Code != "" {
		t.Fatal(report.Code)
	}
	if lines := fakeLines(t, webLog); len(lines) != 0 {
		t.Fatal("a hop ran one-shot", lines)
	}
	var hops []map[string]any
	pool := false
	for _, line := range fakeLines(t, daemonLog) {
		switch line["type"] {
		case "hop":
			hops = append(hops, line)
		case "pool":
			pool = true
		}
	}
	// Every hop carries its token: none was started before an accept here.
	if !pool || len(hops) != 3 || hops[0]["url"] != "https://example.com/" || hops[2]["url"] != "https://cdn.example.net/b" {
		t.Fatal("daemon requests", fakeLines(t, daemonLog))
	}
	for _, hop := range hops {
		if hop["token"] != strings.Repeat("ab", 32) {
			t.Fatal("hop without its token", hop)
		}
	}
}

func TestWebDaemonDeathBeforeTheTokenRunsTheHopOneShot(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	_, webLog, _ := useWebDaemon(t, "web-daemon-crash-before")
	report := webWorkerFor(publicAnswers).Report(context.Background(), webFixtureLease(t))
	if report.Code != "" {
		t.Fatal(report.Code)
	}
	// The daemon never announced the token, so it was never sent: the hop ran again one-shot.
	if lines := fakeLines(t, webLog); len(lines) != 1 || lines[0]["token"] != strings.Repeat("ab", 32) {
		t.Fatal("one-shot runs", lines)
	}
}

func TestWebDaemonDeathAfterTheTokenFailsTheHop(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	_, webLog, _ := useWebDaemon(t, "web-daemon-crash-after")
	report := webWorkerFor(publicAnswers).Report(context.Background(), webFixtureLease(t))
	// The token may have been spent: never repeated.
	if report.Code != "web_fetch_failed" {
		t.Fatal(report.Code)
	}
	if lines := fakeLines(t, webLog); len(lines) != 0 {
		t.Fatal("a presented hop ran again", lines)
	}
}

func TestWebDaemonMisuseHaltsRelay(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	useWebDaemon(t, "web-daemon-misuse")
	report := webWorkerFor(publicAnswers).Report(context.Background(), webFixtureLease(t))
	if report.Code != "relay_misuse" || !RelayHalted() {
		t.Fatal("misuse not latched", report.Code)
	}
}

// A daemon hop the verifier ended before opening the request is the
// node's uncertain attempt, not misuse: relay is not halted.
func TestWebDaemonUnopenedSessionIsUncertainNotMisuse(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	useWebDaemon(t, "web-daemon-unopened")
	report := webWorkerFor(publicAnswers).Report(context.Background(), webFixtureLease(t))
	if report.Code != "execution_uncertain" || RelayHalted() || RelayPaused() {
		t.Fatal("unopened daemon hop", report.Code, RelayHalted(), RelayPaused())
	}
}

// The node stops waiting for a daemon hop when its job ends; what the
// daemon says about the verifier afterwards still counts toward a rest.
func TestWebDaemonReplyAfterTheJobEndedStillCountsAnUnopenedRecord(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	useWebDaemon(t, "web-daemon-late-unopened")
	w := webWorkerFor(publicAnswers)
	if daemonFor(w.Config) == nil {
		t.Fatal("no daemon")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if report := w.Report(ctx, webFixtureLease(t)); report.Code != "expired" {
		t.Fatal("job past its deadline", report.Code)
	}
	for start := time.Now(); ; time.Sleep(20 * time.Millisecond) {
		relayRest.Lock()
		counted := len(relayRest.unopened)
		relayRest.Unlock()
		if counted == 1 && !RelayHalted() {
			return
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("late reply counted %d unopened sessions, halted %v", counted, RelayHalted())
		}
	}
}

func TestWebDaemonThatDoesNotStartLeavesHopsOneShot(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	_, webLog, _ := useWebDaemon(t, "web-final")
	for i := 0; i < daemonCrashLimit+1; i++ {
		if report := webWorkerFor(publicAnswers).Report(context.Background(), webFixtureLease(t)); report.Code != "" {
			t.Fatal(report.Code)
		}
	}
	if lines := fakeLines(t, webLog); len(lines) != daemonCrashLimit+1 {
		t.Fatal("one-shot runs", len(lines))
	}
	// After the crash limit it is not tried again for a while.
	webDaemons.Lock()
	crashes := len(webDaemons.crashes[daemonKeyOf(webConfig())])
	webDaemons.Unlock()
	if crashes != daemonCrashLimit {
		t.Fatal("daemon starts", crashes)
	}
}

// The E1 pre-dial, one-shot: the helper starts without a token before the
// accept, and gets it only at hop 0 after the accept.
func TestWebPredialGetsItsTokenOnlyAfterTheAccept(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	_, webLog, predialLog := useWebDaemon(t, "web-final")
	webDaemonEnabled.Store(false)
	w := webWorkerFor(publicAnswers)
	offer := webOffer(t)
	// The accept failed: the helper ends without a token or a target.
	p := w.StartPredial(context.Background(), offer)
	if p == nil {
		t.Fatal("no pre-dial for a relay web offer")
	}
	lines := eventually(t, predialLog, 1)
	var first webHopInput
	raw, _ := json.Marshal(lines[0]["input"])
	if json.Unmarshal(raw, &first) != nil || !first.Predial || first.Token != "" || first.IP != "93.184.215.14" || first.Hop != 0 {
		t.Fatal("pre-dial input", lines[0])
	}
	p.Cancel()
	if lines = eventually(t, predialLog, 2); lines[1]["event"] != "aborted" {
		t.Fatal("cancelled pre-dial", lines)
	}
	if lines := fakeLines(t, webLog); len(lines) != 0 {
		t.Fatal("a cancelled pre-dial ran a hop", lines)
	}

	// The accept succeeded: the token goes out at hop 0, on the pre-dialed helper.
	os.Remove(predialLog)
	p = w.StartPredial(context.Background(), offer)
	eventually(t, predialLog, 1)
	accepted := webFixtureLease(t)
	accepted.LeaseDeadline, accepted.SettlementDeadline = offer.LeaseDeadline, offer.SettlementDeadline
	ctx := p.Accepted(context.Background(), accepted)
	if report := w.Report(ctx, accepted); report.Code != "" {
		t.Fatal(report.Code)
	}
	p.Cancel()
	if lines := fakeLines(t, predialLog); len(lines) != 2 || lines[1]["event"] != "token" {
		t.Fatal("pre-dial events", lines)
	}
	if lines := fakeLines(t, webLog); len(lines) != 1 || lines[0]["token"] != strings.Repeat("ab", 32) || lines[0]["ip"] != "93.184.215.14" {
		t.Fatal("hop", lines)
	}
}

// The E1 pre-dial on the daemon: the hop is sent without its token, and
// the token, or a cancel, follows the accept.
func TestWebPredialOnTheDaemon(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	daemonLog, webLog, _ := useWebDaemon(t, "web-daemon-final")
	w := webWorkerFor(publicAnswers)
	offer := webOffer(t)
	p := w.StartPredial(context.Background(), offer)
	lines := eventually(t, daemonLog, 2)
	if lines[0]["type"] != "pool" || lines[1]["type"] != "hop" || lines[1]["token"] != "" {
		t.Fatal("daemon requests", lines)
	}
	p.Cancel()
	if lines = eventually(t, daemonLog, 3); lines[2]["type"] != "cancel" || lines[2]["id"] != lines[1]["id"] {
		t.Fatal("cancel", lines)
	}
	p = w.StartPredial(context.Background(), offer)
	lines = eventually(t, daemonLog, 4)
	accepted := webFixtureLease(t)
	accepted.LeaseDeadline, accepted.SettlementDeadline = offer.LeaseDeadline, offer.SettlementDeadline
	if report := w.Report(p.Accepted(context.Background(), accepted), accepted); report.Code != "" {
		t.Fatal(report.Code)
	}
	p.Cancel()
	var tokens []map[string]any
	for _, line := range fakeLines(t, daemonLog) {
		if line["type"] == "token" {
			tokens = append(tokens, line)
		}
	}
	if len(tokens) != 1 || tokens[0]["id"] != lines[3]["id"] || tokens[0]["token"] != strings.Repeat("ab", 32) {
		t.Fatal("tokens", fakeLines(t, daemonLog))
	}
	if lines := fakeLines(t, webLog); len(lines) != 0 {
		t.Fatal("one-shot runs", lines)
	}
}

func TestWebPredialEndsUnsentWhenItCannotServeTheHop(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	_, webLog, predialLog := useWebDaemon(t, "web-final")
	webDaemonEnabled.Store(false)
	answers := map[string][]netip.Addr{"example.com": addrs("93.184.215.14")}
	w := webWorkerFor(answers)
	offer := webOffer(t)
	p := w.StartPredial(context.Background(), offer)
	eventually(t, predialLog, 1)
	// By hop 0 the name resolves elsewhere: the pre-dial ends unsent, and the hop runs afresh.
	answers["example.com"] = addrs("93.184.215.15")
	accepted := webFixtureLease(t)
	accepted.LeaseDeadline, accepted.SettlementDeadline = offer.LeaseDeadline, offer.SettlementDeadline
	if report := w.Report(p.Accepted(context.Background(), accepted), accepted); report.Code != "" {
		t.Fatal(report.Code)
	}
	if lines := eventually(t, predialLog, 2); lines[1]["event"] != "aborted" {
		t.Fatal("pre-dial", lines)
	}
	if lines := fakeLines(t, webLog); len(lines) != 1 || lines[0]["ip"] != "93.184.215.15" {
		t.Fatal("hop", lines)
	}
	// Another lease than the offer's ends it too.
	os.Remove(predialLog)
	p = w.StartPredial(context.Background(), offer)
	eventually(t, predialLog, 1)
	other := accepted
	other.Fence = "33333333-3333-4333-8333-000000000000"
	p.Accepted(context.Background(), other)
	if lines := eventually(t, predialLog, 2); lines[1]["event"] != "aborted" {
		t.Fatal("pre-dial for another lease", lines)
	}
}

// Hang mode A (cross-binary e2e, 2026-10-12): a hop the daemon never
// answers must end with its hop time, freeing its slot, and the daemon that
// broke its promise to answer by then is replaced.
func TestWebHopTheDaemonNeverAnswersEndsAndTheDaemonIsReplaced(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	daemonLog, webLog, _ := useWebDaemon(t, "web-daemon-silent")
	w := webWorkerFor(publicAnswers)
	w.hopTime = time.Second
	stuck := daemonFor(w.Config)
	if stuck == nil {
		t.Fatal("no daemon")
	}
	started := time.Now()
	report := w.Report(context.Background(), webFixtureLease(t))
	if elapsed := time.Since(started); report.Code != "web_fetch_failed" || elapsed < w.hopTime+webHelperGrace || elapsed > w.hopTime+webHelperGrace+3*time.Second {
		t.Fatalf("report %+v after %s", report, elapsed)
	}
	// Never repeated one-shot: the hop's time is spent.
	if lines := fakeLines(t, webLog); len(lines) != 0 {
		t.Fatal("one-shot runs", lines)
	}
	webDaemons.Lock()
	crashes, running := len(webDaemons.crashes[daemonKeyOf(w.Config)]), webDaemons.running[daemonKeyOf(w.Config)]
	webDaemons.Unlock()
	if crashes != 1 || running == stuck {
		t.Fatalf("the stuck daemon was not replaced: %d crashes", crashes)
	}
	if fresh := daemonFor(w.Config); fresh == nil || fresh == stuck {
		t.Fatal("no fresh daemon for the next hop")
	}
	if hops := countType(fakeLines(t, daemonLog), "hop"); hops != 1 {
		t.Fatal("hops sent", hops)
	}
}

// The same for a pre-dialed hop 0: its token goes to the daemon after the
// accept and is never answered.
func TestWebPredialWhoseTokenIsNeverAnsweredEnds(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	daemonLog, webLog, _ := useWebDaemon(t, "web-daemon-silent")
	w := webWorkerFor(publicAnswers)
	w.hopTime = time.Second
	offer := webOffer(t)
	p := w.StartPredial(context.Background(), offer)
	eventually(t, daemonLog, 2)
	accepted := webFixtureLease(t)
	accepted.LeaseDeadline, accepted.SettlementDeadline = offer.LeaseDeadline, offer.SettlementDeadline
	started := time.Now()
	report := w.Report(p.Accepted(context.Background(), accepted), accepted)
	p.Cancel()
	if elapsed := time.Since(started); report.Code != "web_fetch_failed" || elapsed > w.hopTime+webHelperGrace+3*time.Second {
		t.Fatalf("report %+v after %s", report, elapsed)
	}
	if tokens := countType(fakeLines(t, daemonLog), "token"); tokens != 1 {
		t.Fatal("tokens sent", tokens)
	}
	if lines := fakeLines(t, webLog); len(lines) != 0 {
		t.Fatal("one-shot runs", lines)
	}
	if webBusy.Load() != 0 {
		t.Fatal("hops still counted busy", webBusy.Load())
	}
}

// Hang mode B: the daemon's answer that the verifier refused the page as too
// large reaches the report at once.
func TestWebDaemonPageTooLargeReachesTheReport(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	_, webLog, _ := useWebDaemon(t, "web-daemon-too-large")
	started := time.Now()
	report := webWorkerFor(publicAnswers).Report(context.Background(), webFixtureLease(t))
	if report != (WebReport{Code: "page_too_large", Stage: "wire", ObservedBytes: coordinator.PageMax + 1}) || time.Since(started) > 5*time.Second {
		t.Fatalf("report %+v after %s", report, time.Since(started))
	}
	if lines := fakeLines(t, webLog); len(lines) != 0 {
		t.Fatal("a presented hop ran again", lines)
	}
	if webBusy.Load() != 0 {
		t.Fatal("hops still counted busy", webBusy.Load())
	}
}

// A pre-dialed hop 0 counts once toward the warm pool's size, from its
// pre-dial to its end: the pool is not shrunk and grown again around it.
func TestWebPredialedHopCountsOnceForTheWarmPool(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	daemonLog, _, _ := useWebDaemon(t, "web-daemon-final")
	w := webWorkerFor(publicAnswers)
	w.Config.WebConcurrency = 3
	offer := webOffer(t)
	p := w.StartPredial(context.Background(), offer)
	eventually(t, daemonLog, 2)
	accepted := webFixtureLease(t)
	accepted.LeaseDeadline, accepted.SettlementDeadline = offer.LeaseDeadline, offer.SettlementDeadline
	if report := w.Report(p.Accepted(context.Background(), accepted), accepted); report.Code != "" {
		t.Fatal(report.Code)
	}
	p.Cancel()
	var sizes []any
	for _, line := range fakeLines(t, daemonLog) {
		if line["type"] == "pool" {
			sizes = append(sizes, line["size"])
		}
	}
	// 3 slots, one job: min(2, 3-1) = 2 throughout.
	if len(sizes) != 1 || sizes[0] != float64(2) {
		t.Fatal("pool sizes", sizes)
	}
	if webBusy.Load() != 0 {
		t.Fatal("hops still counted busy", webBusy.Load())
	}
}

func TestDaemonLogPassesLinesOnCleanAndBounded(t *testing.T) {
	l := &daemonLog{lines: make(chan string, 4)}
	l.Write([]byte("first\npart"))
	l.Write([]byte("ial line\x1b[31m\nthird\n"))
	if got := []string{<-l.lines, <-l.lines, <-l.lines}; got[0] != "first" || got[1] != "partial line [31m" || got[2] != "third" {
		t.Fatal(got)
	}
	// A full queue drops lines rather than blocking the daemon, and says so.
	for i := 0; i < 6; i++ {
		l.Write([]byte(fmt.Sprintf("line %d\n", i)))
	}
	if l.dropped != 2 {
		t.Fatal("dropped", l.dropped)
	}
	for i := 0; i < 4; i++ {
		<-l.lines
	}
	l.Write([]byte(strings.Repeat("x", 300) + "\n"))
	if dropped, line := <-l.lines, <-l.lines; dropped != "(2 lines dropped)" || len(line) != 240 {
		t.Fatal(dropped, len(line))
	}
	l.Write([]byte("last words"))
	if last := l.close(); last != "last words" {
		t.Fatal(last)
	}
	l.Write([]byte("after the end\n"))
}

func countType(lines []map[string]any, kind string) int {
	n := 0
	for _, line := range lines {
		if line["type"] == kind {
			n++
		}
	}
	return n
}

func TestOnlyRelayWebOffersArePredialed(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	w := webWorkerFor(publicAnswers)
	accepted := webFixtureLease(t)
	browser := webOffer(t)
	browser.WebRequest = &coordinator.WebRequest{Operation: "scrape", URL: browser.WebRequest.URL, Mode: "browser"}
	notWeb := webOffer(t)
	notWeb.ServiceType = "x_read"
	unfunded := webOffer(t)
	unfunded.AcceptanceRequired = false
	expiring := webOffer(t)
	expiring.LeaseDeadline = time.Now().Add(5 * time.Second)
	expiring.SettlementDeadline = expiring.LeaseDeadline
	for name, l := range map[string]coordinator.Lease{"already accepted": accepted, "browser": browser, "not web": notWeb, "unfunded": unfunded, "expiring": expiring} {
		if p := w.StartPredial(context.Background(), l); p != nil {
			p.Cancel()
			t.Fatal(name)
		}
	}
	HaltRelay("test")
	if w.StartPredial(context.Background(), webOffer(t)) != nil {
		t.Fatal("halted relay pre-dialed")
	}
	// Every method is nil-safe.
	var none *WebPredial
	none.Cancel()
	if ctx := none.Accepted(context.Background(), accepted); ctx.Value(webPredialKey{}) != nil {
		t.Fatal("nil predial in context")
	}
}

// TestRealWebDaemonSpeaksTheProtocol runs the real `scarlett-prover serve`
// named by SCARLETT_REAL_PROVER (skipped otherwise) against a verifier
// address nothing listens on: the client and the daemon agree on framing,
// the ready handshake, a hop without its token, cancel, and an unsent
// failure's reply.
func TestRealWebDaemonSpeaksTheProtocol(t *testing.T) {
	prover := os.Getenv("SCARLETT_REAL_PROVER")
	if prover == "" {
		t.Skip("SCARLETT_REAL_PROVER is not set")
	}
	resetWebDaemons()
	webDaemonEnabled.Store(true)
	t.Cleanup(func() {
		webDaemonEnabled.Store(false)
		resetWebDaemons()
	})
	c := webConfig()
	c.Prover, c.Verifier, c.VerifierPlaintextFixture = prover, "127.0.0.1:9", true
	d := daemonFor(c)
	if d == nil {
		t.Fatal("the real daemon did not start")
	}
	l := webFixtureLease(t)
	in := webHopInput{Verifier: c.Verifier, PlaintextFixture: true, Hop: 0, URL: "https://example.com/", IP: "93.184.215.14", Port: 443, Payload: l.WebPayload, TimeoutMS: 5000, Proxy: &webProxyInput{Host: "127.0.0.1", Port: 9}}
	// Started without its token, then cancelled: nothing was sent.
	h, err := d.startHop(in)
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	waiting := d.hops[h.id] != nil
	d.mu.Unlock()
	if !waiting {
		t.Fatal("hop not waiting")
	}
	d.cancel(h)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if reply := d.wait(ctx, h); reply.Type != "cancelled" || reply.Presented || len(reply.Diagnostics) == 0 {
		t.Fatalf("cancel reply %+v", reply)
	}
	// With its token: the proxy is unreachable, so it fails before the token goes out.
	in.Token = strings.Repeat("ab", 32)
	result, ok := d.run(ctx, in)
	if !ok || !result.fromDaemon || result.class != "proxy_failed" || result.err == nil {
		t.Fatalf("hop result %+v %v", result, ok)
	}
	if code := webFailureCode(ctx, result.cause, result.class); code != "web_proxy_failed" {
		t.Fatal(code)
	}
}
