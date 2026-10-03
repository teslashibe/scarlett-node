//go:build xperf

package worker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	x "github.com/teslashibe/x-go"
	"golang.org/x/sys/unix"
)

// This harness is experimental and deliberately independent of XTransport's
// production defaults. Credentials enter only through private local files.
type xperfConfig struct {
	session, prover, verifier, ca, api, key, output         string
	mode, headers, workload, networkProfile, serverName     string
	mpcNetwork                                              string
	samples, maxRecv, sentRecords, recvRecords              int
	prepareHoldMS, batchReads                               int
	responseReady                                           bool
	concurrency, accountCapacity, receiptCapacity           int
	minGapMS, sustainedSeconds, simulatedDelayMS, bandwidth int
}

func xperfConfiguration() (xperfConfig, error) {
	c := xperfConfig{session: os.Getenv("SCARLETT_X_SESSION"), prover: os.Getenv("SCARLETT_PROVER"), verifier: os.Getenv("SCARLETT_VERIFIER"), ca: os.Getenv("SCARLETT_VERIFIER_CA_FILE"), api: os.Getenv("SCARLETT_VERIFIER_API"), output: os.Getenv("SCARLETT_XPERF_OUTPUT"), mode: os.Getenv("SCARLETT_XPERF_MODE"), headers: os.Getenv("SCARLETT_XPERF_HEADERS"), workload: os.Getenv("SCARLETT_XPERF_WORKLOAD"), networkProfile: os.Getenv("SCARLETT_XPERF_NETWORK_PROFILE"), serverName: os.Getenv("SCARLETT_XPERF_VERIFIER_SERVER_NAME"), mpcNetwork: os.Getenv("SCARLETT_XPERF_MPC_NETWORK")}
	if c.mpcNetwork == "" {
		c.mpcNetwork = "reduce_bandwidth"
	}
	if c.mpcNetwork != "reduce_bandwidth" && c.mpcNetwork != "reduce_roundtrips" || c.mode == "proxy" && c.mpcNetwork != "reduce_bandwidth" {
		return c, errors.New("invalid_mpc_network")
	}
	if c.mode == "" {
		c.mode = "mpc"
	}
	if c.headers == "" {
		c.headers = "normal"
	}
	if c.workload == "" {
		c.workload = "search"
	}
	if c.mode != "mpc" && c.mode != "proxy" || c.headers != "normal" && c.headers != "minimal" || !xperfWorkloadAllowed(c.workload) {
		return c, errors.New("invalid_variant")
	}
	var err error
	for _, p := range []struct {
		name          string
		out           *int
		def, min, max int
	}{
		{"SCARLETT_XPERF_SAMPLES", &c.samples, 1, 1, 1000},
		{"SCARLETT_XPERF_MAX_RECV", &c.maxRecv, 0, 0, 256 << 10},
		{"SCARLETT_XPERF_SENT_RECORDS", &c.sentRecords, 0, 0, 32},
		{"SCARLETT_XPERF_RECV_RECORDS", &c.recvRecords, 0, 0, 32},
		{"SCARLETT_XPERF_PREPARE_HOLD_MS", &c.prepareHoldMS, 0, 0, 30000},
		{"SCARLETT_XPERF_CONCURRENCY", &c.concurrency, 1, 1, 4},
		{"SCARLETT_XPERF_ACCOUNT_CAPACITY", &c.accountCapacity, 1, 1, 4},
		{"SCARLETT_XPERF_RECEIPT_CAPACITY", &c.receiptCapacity, 1, 1, 4},
		{"SCARLETT_XPERF_MIN_GAP_MS", &c.minGapMS, 1000, 0, 60000},
		{"SCARLETT_XPERF_SUSTAINED_SECONDS", &c.sustainedSeconds, 0, 0, 3600},
		{"SCARLETT_XPERF_BANDWIDTH_BYTES_SECOND", &c.bandwidth, 0, 0, 1000000000},
		{"SCARLETT_XPERF_BATCH_READS", &c.batchReads, 0, 0, 2},
	} {
		*p.out = p.def
		if value := os.Getenv(p.name); value != "" {
			*p.out, err = strconv.Atoi(value)
		}
		if err != nil || *p.out < p.min || *p.out > p.max {
			return c, errors.New("invalid_variant")
		}
	}
	if c.concurrency != 1 && c.concurrency != 2 && c.concurrency != 4 || c.sustainedSeconds > 0 && c.sustainedSeconds < 60 {
		return c, errors.New("invalid_capacity_or_window")
	}
	if c.networkProfile == "" {
		c.networkProfile = "direct"
	}
	var ok bool
	c.simulatedDelayMS, ok = xperfNetworkDelay(c.networkProfile)
	if !ok || c.networkProfile == "direct" && c.bandwidth != 0 {
		return c, errors.New("invalid_network_profile")
	}
	if c.serverName != "" {
		host, _, e := net.SplitHostPort(c.verifier)
		if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || len(c.serverName) > 253 || strings.ContainsAny(c.serverName, "/:@ \t\r\n") {
			return c, errors.New("unsafe_verifier_server_name")
		}
	}
	if c.batchReads != 0 && c.batchReads != 2 || (c.workload == "batch") != (c.batchReads == 2) || c.batchReads == 2 && c.mode != "mpc" {
		return c, errors.New("invalid_variant")
	}
	if c.sentRecords != 0 && c.sentRecords < 3 || c.recvRecords != 0 && c.recvRecords < 3 {
		return c, errors.New("invalid_record_allocation")
	}
	if v := os.Getenv("SCARLETT_XPERF_RESPONSE_READY"); v != "" && v != "0" && v != "1" {
		return c, errors.New("invalid_variant")
	}
	c.responseReady = os.Getenv("SCARLETT_XPERF_RESPONSE_READY") == "1"
	if c.mode == "proxy" && (c.sentRecords != 0 || c.recvRecords != 0 || c.prepareHoldMS != 0) {
		return c, errors.New("mpc_option_on_proxy")
	}
	if c.session == "" || c.prover == "" || c.verifier == "" || c.api == "" || c.output == "" {
		return c, errors.New("missing_configuration")
	}
	u, err := url.Parse(c.api)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return c, errors.New("unsafe_control_origin")
	}
	if c.networkProfile != "direct" {
		raw, e := xperfPrivateRead(filepath.Join(c.output, "shaper-ready.json"), 4096)
		var ready struct {
			Schema    int    `json:"schema"`
			Listen    string `json:"listen"`
			Topology  string `json:"topology"`
			Profile   string `json:"profile"`
			Delay     int    `json:"simulated_one_way_delay_ms"`
			Bandwidth int    `json:"bandwidth_bytes_second"`
		}
		if e != nil || json.Unmarshal(raw, &ready) != nil || ready.Schema != 1 || ready.Listen != c.verifier || ready.Topology != "simulated_loopback_tcp_tls" || ready.Profile != c.networkProfile || ready.Delay != c.simulatedDelayMS || ready.Bandwidth != c.bandwidth {
			return c, errors.New("simulated_shaper_binding_missing")
		}
	}
	c.api = strings.TrimRight(c.api, "/")
	key, err := xperfPrivateRead(os.Getenv("SCARLETT_VERIFIER_KEY_FILE"), 4096)
	if err != nil {
		return c, errors.New("invalid_private_key_file")
	}
	c.key = strings.TrimSpace(string(key))
	if c.key == "" || strings.ContainsAny(c.key, "\r\n") {
		return c, errors.New("invalid_private_key_file")
	}
	if err := xperfPrivateDirectory(c.output); err != nil {
		return c, err
	}
	return c, nil
}

func xperfNetworkDelay(profile string) (int, bool) {
	switch profile {
	case "direct", "simulated-rtt0":
		return 0, true
	case "simulated-rtt20":
		return 10, true
	case "simulated-rtt80":
		return 40, true
	case "simulated-rtt160":
		return 80, true
	default:
		return 0, false
	}
}

func xperfWorkloadAllowed(v string) bool {
	return v == "search" || v == "empty" || v == "profile" || v == "post" || v == "pagination" || v == "batch"
}

func xperfPrivateDirectory(path string) error {
	i, err := os.Lstat(path)
	if err != nil || !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return errors.New("output_directory_must_be_private")
	}
	return nil
}

func xperfPrivateRead(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("private_file_unavailable")
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() > max {
		return nil, errors.New("private_file_unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, errors.New("private_file_unavailable")
	}
	return b, nil
}

// The captured request remains private. Only its typed, credential-free
// GraphQL specification is sent to the verifier's authenticated control API.
type xperfCapture struct {
	bootstrap  bool
	base       http.RoundTripper
	request    *http.Request
	replaySpec *xSpec
	replayBody []byte
}

// A single account's x-go client remains shared; mutable capture/replay state
// belongs to the individual job context and cannot cross concurrent jobs.
type xperfCaptureKey struct{}
type xperfRouter struct{ bootstrap *xperfCapture }

func (r *xperfRouter) RoundTrip(req *http.Request) (*http.Response, error) {
	if capture, ok := req.Context().Value(xperfCaptureKey{}).(*xperfCapture); ok {
		return capture.RoundTrip(req)
	}
	if r.bootstrap != nil && r.bootstrap.bootstrap {
		return r.bootstrap.RoundTrip(req)
	}
	return nil, errors.New("request_capture_failed")
}

var errXPerfCaptured = errors.New("xperf_request_captured")

func (c *xperfCapture) RoundTrip(r *http.Request) (*http.Response, error) {
	if c.bootstrap {
		b := xBoundTransport{bootstrap: true, base: c.base}
		return b.RoundTrip(r)
	}
	s, err := xperfSpec(r)
	if err != nil {
		return nil, err
	}
	if c.replaySpec != nil {
		if !reflect.DeepEqual(s, *c.replaySpec) {
			return nil, errors.New("parser_request_mismatch")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(c.replayBody)), Request: r}, nil
	}
	c.request = r.Clone(r.Context())
	c.request.Header = r.Header.Clone()
	return nil, errXPerfCaptured
}

func xperfSpec(r *http.Request) (xSpec, error) {
	var s xSpec
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "x.com" || r.URL.User != nil || r.URL.Fragment != "" {
		return s, errors.New("request_policy")
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/i/api/graphql/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/i/api/graphql/") || len(parts) != 2 || !validID(parts[0], 64) {
		return s, errors.New("request_policy")
	}
	s.QueryID, s.Operation = parts[0], parts[1]
	if s.Operation != "SearchTimeline" && s.Operation != "UserByScreenName" && s.Operation != "TweetResultByRestId" {
		return s, errors.New("request_policy")
	}
	q := r.URL.Query()
	for k, v := range q {
		if len(v) != 1 || k != "variables" && k != "features" && k != "fieldToggles" {
			return s, errors.New("request_policy")
		}
	}
	for _, p := range []struct {
		name     string
		out      *map[string]any
		optional bool
	}{{"variables", &s.Variables, false}, {"features", &s.Features, false}, {"fieldToggles", &s.FieldToggles, true}} {
		if q.Get(p.name) == "" && p.optional {
			continue
		}
		v, err := uniqueJSON([]byte(q.Get(p.name)))
		var ok bool
		*p.out, ok = v.(map[string]any)
		if err != nil || !ok {
			return s, errors.New("request_policy")
		}
	}
	return s, nil
}

type xperfParsed struct {
	items  int
	cursor string
}

func xperfRead(ctx context.Context, c *x.Client, workload, cursor string) (xperfParsed, error) {
	switch workload {
	case "profile":
		u, err := c.GetProfile(ctx, "jack")
		if err == nil && (u.ID != "12" || !strings.EqualFold(u.ScreenName, "jack")) {
			return xperfParsed{}, errors.New("profile_identity_mismatch")
		}
		if err != nil {
			return xperfParsed{}, err
		}
		return xperfParsed{items: 1}, nil
	case "post":
		p, err := c.GetTweet(ctx, "20")
		if err == nil && p.ID != "20" {
			return xperfParsed{}, errors.New("post_identity_mismatch")
		}
		if err != nil {
			return xperfParsed{}, err
		}
		return xperfParsed{items: 1}, nil
	default:
		query := "solana"
		if workload == "empty" {
			query = "scarlettcanarynevermatch7fbea4519fd1484185d772aef090fe29"
		}
		p, err := c.SearchTweetsPage(ctx, query, 20, cursor, x.WithSearchType(x.SearchLatest))
		if err != nil {
			return xperfParsed{}, err
		}
		if workload == "empty" && len(p.Tweets) != 0 {
			return xperfParsed{}, errors.New("empty_fixture_not_empty")
		}
		return xperfParsed{items: len(p.Tweets), cursor: p.NextCursor}, nil
	}
}

func xperfPlan(ctx context.Context, client *x.Client, capture *xperfCapture, workload string) ([]xSpec, *http.Request, error) {
	capture.request, capture.replaySpec = nil, nil
	_, _ = xperfRead(ctx, client, workload, "")
	if capture.request == nil {
		return nil, nil, errors.New("request_capture_failed")
	}
	s, err := xperfSpec(capture.request)
	if err != nil {
		return nil, nil, err
	}
	specs := []xSpec{s}
	if workload == "pagination" {
		second := s
		second.Variables = make(map[string]any, len(s.Variables))
		for k, v := range s.Variables {
			second.Variables[k] = v
		}
		zero := 0
		second.CursorFrom = &zero
		specs = append(specs, second)
	}
	return specs, capture.request, nil
}

func xperfBatchPlan(ctx context.Context, client *x.Client, capture *xperfCapture) ([]xSpec, []*http.Request, error) {
	var specs []xSpec
	var requests []*http.Request
	for _, workload := range []string{"profile", "post"} {
		capture.request, capture.replaySpec = nil, nil
		_, _ = xperfRead(ctx, client, workload, "")
		if capture.request == nil {
			return nil, nil, errors.New("request_capture_failed")
		}
		spec, err := xperfSpec(capture.request)
		if err != nil {
			return nil, nil, err
		}
		specs, requests = append(specs, spec), append(requests, capture.request)
	}
	return specs, requests, nil
}

func xperfPayload(specs []xSpec, mode string) map[string]any {
	p := map[string]any{"type": "x.read", "exchanges": specs, "max_attempts": len(specs)}
	if mode == "proxy" {
		p["proof_mode"], p["proof_policy"] = "proxy", "x-proxy-experimental-v1"
	}
	if mode == "batch" {
		p["proof_mode"], p["proof_policy"] = "mpc", "x-mpc-batch-experimental-v1"
	}
	return p
}

func xperfProverInput(c xperfConfig, token string, req *http.Request) ([]byte, int, error) {
	return xperfRequestsInput(c, token, []*http.Request{req})
}

func xperfRequestsInput(c xperfConfig, token string, requests []*http.Request) ([]byte, int, error) {
	if len(requests) != 1 && (len(requests) != 2 || c.batchReads != 2 || c.mode != "mpc") || c.batchReads == 2 && len(requests) != 2 {
		return nil, 0, errors.New("request_policy")
	}
	var raw bytes.Buffer
	for i, req := range requests {
		if _, err := xperfSpec(req); err != nil {
			return nil, 0, err
		}
		r := req.Clone(req.Context())
		r.Header = req.Header.Clone()
		r.Header.Del("Connection")
		r.Close = i == len(requests)-1
		if !r.Close {
			r.Header.Set("Connection", "keep-alive")
		}
		r.Header.Set("Accept-Encoding", "gzip")
		if c.headers == "minimal" {
			for _, h := range []string{"Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Accept-Language", "X-Twitter-Client-Language", "Referer"} {
				r.Header.Del(h)
			}
		}
		if err := r.Write(&raw); err != nil {
			return nil, 0, errors.New("request_serialization")
		}
	}
	if raw.Len() > 16<<10 {
		return nil, 0, errors.New("request_policy")
	}

	p := map[string]any{"verifier": c.verifier, "token": token, "request": base64.StdEncoding.EncodeToString(raw.Bytes()), "proof_mode": c.mode}
	if c.serverName != "" {
		p["verifier_server_name"] = c.serverName
	}
	if c.batchReads == 2 {
		p["batch_reads"] = 2
	}
	if c.ca != "" {
		p["verifier_ca_file"] = c.ca
	}
	if c.maxRecv != 0 {
		p["max_recv"] = c.maxRecv
	}
	if c.sentRecords != 0 {
		p["max_sent_records"] = c.sentRecords
	}
	if c.recvRecords != 0 {
		p["max_recv_records_online"] = c.recvRecords
	}
	if c.prepareHoldMS != 0 {
		p["prepare_hold_ms"] = c.prepareHoldMS
	}
	if c.mode == "mpc" && c.mpcNetwork != "" {
		p["mpc_network"] = c.mpcNetwork
	}
	if c.responseReady {
		p["response_ready_event"] = true
	}
	b, err := json.Marshal(p)
	return b, raw.Len(), err
}

type xperfSummary struct {
	MpcNetwork         string            `json:"mpc_network"`
	Status             string            `json:"status"`
	Mode               string            `json:"proof_mode"`
	Response           string            `json:"response"`
	SentBytes          uint64            `json:"sent_bytes"`
	ReceivedBytes      uint64            `json:"received_bytes"`
	DurationMS         uint64            `json:"duration_ms"`
	ExecutionMS        *uint64           `json:"execution_ms"`
	VerifierSent       *uint64           `json:"verifier_sent_bytes"`
	VerifierReceived   *uint64           `json:"verifier_received_bytes"`
	TransportLayer     string            `json:"verifier_transport_layer"`
	TransportSaturated bool              `json:"verifier_bytes_saturated"`
	Timings            map[string]uint64 `json:"timings_ms"`
	BatchExchanges     []struct {
		Response      string `json:"response"`
		SentBytes     uint64 `json:"sent_bytes"`
		ReceivedBytes uint64 `json:"received_bytes"`
	} `json:"batch_exchanges"`
}

type xperfObserved struct {
	spec                                                xSpec
	bodyHash                                            [32]byte
	bodyBytes, items, httpStatus                        int
	summary                                             xperfSummary
	helperMS                                            int64
	userCPUSeconds, systemCPUSeconds                    float64
	peakRSSBytes                                        int64
	provisionalMS                                       *uint64
	rateLimit, rateRemaining, rateReset                 *uint64
	receiptObserved, receiptBound, receiptComplete      bool
	receiptPending, receiptRemaining, receiptRejections int
	sharedConnection                                    bool
}

func xperfProve(ctx context.Context, c xperfConfig, token string, req *http.Request, diagnostic string) (xperfObserved, []byte, error) {
	input, _, err := xperfProverInput(c, token, req)
	if err != nil {
		return xperfObserved{}, nil, err
	}
	o, err := xperfExecute(ctx, c, input, diagnostic)
	o.spec, _ = xperfSpec(req)
	if err != nil {
		return o, nil, err
	}
	return xperfDecodeResponse(o, req, o.summary.Response)
}

func xperfExecute(ctx context.Context, c xperfConfig, input []byte, diagnostic string) (xperfObserved, error) {
	var o xperfObserved

	cmd := exec.CommandContext(ctx, c.prover, "prove-x")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = 4<<20, 16384
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	started := time.Now()
	err := cmd.Run()
	o.helperMS = time.Since(started).Milliseconds()
	if state := cmd.ProcessState; state != nil {
		o.userCPUSeconds, o.systemCPUSeconds = state.UserTime().Seconds(), state.SystemTime().Seconds()
		if ru, ok := state.SysUsage().(*syscall.Rusage); ok {
			o.peakRSSBytes = ru.Maxrss
			if runtime.GOOS != "darwin" {
				o.peakRSSBytes *= 1024
			}
		}
	}
	if len(stderr.Bytes()) > 0 {
		f, e := os.OpenFile(diagnostic, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
		if e != nil {
			return o, errors.New("private_diagnostic_write_failed")
		}
		_, e = f.Write(stderr.Bytes())
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return o, errors.New("private_diagnostic_write_failed")
		}
		o.provisionalMS = xperfProvisional(stderr.Bytes())
	}
	if err != nil {
		return o, errors.New("helper_failed")
	}
	if json.Unmarshal(stdout.Bytes(), &o.summary) != nil || o.summary.Status != "proof_sent" || o.summary.Mode != c.mode {
		return o, errors.New("helper_summary_invalid")
	}
	if c.mpcNetwork == "reduce_roundtrips" && o.summary.MpcNetwork != c.mpcNetwork {
		return o, errors.New("helper_summary_invalid")
	}
	return o, nil
}

func xperfDecodeResponse(o xperfObserved, req *http.Request, encoded string) (xperfObserved, []byte, error) {
	var err error
	o.spec, err = xperfSpec(req)
	if err != nil {
		return o, nil, err
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return o, nil, errors.New("helper_response_invalid")
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req)
	if err != nil {
		return o, nil, errors.New("helper_response_invalid")
	}
	defer resp.Body.Close()
	o.httpStatus = resp.StatusCode
	o.rateLimit = xperfNumericHeader(resp.Header, "X-Rate-Limit-Limit")
	o.rateRemaining = xperfNumericHeader(resp.Header, "X-Rate-Limit-Remaining")
	o.rateReset = xperfNumericHeader(resp.Header, "X-Rate-Limit-Reset")
	var reader io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		z, err := gzip.NewReader(resp.Body)
		if err != nil {
			return o, nil, errors.New("helper_response_invalid")
		}
		defer z.Close()
		reader = z
	}
	body, err := io.ReadAll(io.LimitReader(reader, (8<<20)+1))
	if err != nil || len(body) > 8<<20 {
		return o, nil, errors.New("helper_response_invalid")
	}
	o.bodyHash, o.bodyBytes = sha256.Sum256(body), len(body)
	if resp.StatusCode == 429 {
		return o, nil, errors.New("provider_rate_limited")
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return o, nil, errors.New("provider_auth_failed")
	}
	if resp.StatusCode != 200 {
		return o, nil, errors.New("provider_http_failed")
	}
	return o, body, nil
}

func xperfNumericHeader(h http.Header, name string) *uint64 {
	v := h.Values(name)
	if len(v) != 1 || len(v[0]) == 0 || len(v[0]) > 20 {
		return nil
	}
	for _, b := range v[0] {
		if b < '0' || b > '9' {
			return nil
		}
	}
	n, err := strconv.ParseUint(v[0], 10, 64)
	if err != nil || n > 1e12 {
		return nil
	}
	return &n
}

func xperfBatchObservations(base xperfObserved, requests []*http.Request, sent int) ([]xperfObserved, [][]byte, error) {
	if len(requests) != 2 || len(base.summary.BatchExchanges) != 2 {
		return nil, nil, errors.New("helper_summary_invalid")
	}
	complete, err := base64.StdEncoding.DecodeString(base.summary.Response)
	if err != nil || len(complete) > 256<<10 {
		return nil, nil, errors.New("helper_response_invalid")
	}
	var joined []byte
	var totalSent, totalReceived uint64
	for _, exchange := range base.summary.BatchExchanges {
		raw, err := base64.StdEncoding.DecodeString(exchange.Response)
		if err != nil || uint64(len(raw)) != exchange.ReceivedBytes || exchange.SentBytes == 0 || exchange.SentBytes > 16<<10 || exchange.ReceivedBytes > 256<<10 {
			return nil, nil, errors.New("helper_summary_invalid")
		}
		joined = append(joined, raw...)
		totalSent += exchange.SentBytes
		totalReceived += exchange.ReceivedBytes
	}
	if !bytes.Equal(joined, complete) || totalSent != uint64(sent) || totalSent != base.summary.SentBytes || totalReceived != base.summary.ReceivedBytes {
		return nil, nil, errors.New("helper_summary_invalid")
	}
	var observations []xperfObserved
	var bodies [][]byte
	var failure error
	for i, exchange := range base.summary.BatchExchanges {
		o := base
		if i > 0 {
			o = xperfObserved{summary: base.summary, sharedConnection: true}
		}
		o.summary.SentBytes, o.summary.ReceivedBytes = exchange.SentBytes, exchange.ReceivedBytes
		o, body, err := xperfDecodeResponse(o, requests[i], exchange.Response)
		observations, bodies = append(observations, o), append(bodies, body)
		if failure == nil && err != nil {
			failure = err
		}
	}
	return observations, bodies, failure
}

func xperfProveBatch(ctx context.Context, c xperfConfig, token string, requests []*http.Request, diagnostic string) ([]xperfObserved, [][]byte, error) {
	input, sent, err := xperfRequestsInput(c, token, requests)
	if err != nil {
		return nil, nil, err
	}
	base, err := xperfExecute(ctx, c, input, diagnostic)
	if err != nil {
		return []xperfObserved{base, {sharedConnection: true}}, nil, err
	}
	observations, bodies, err := xperfBatchObservations(base, requests, sent)
	if observations == nil {
		observations = []xperfObserved{base, {sharedConnection: true}}
	}
	return observations, bodies, err
}

func xperfProvisional(raw []byte) *uint64 {
	for _, line := range bytes.Split(raw, []byte("\n")) {
		var v struct {
			Phase   string  `json:"phase"`
			Elapsed *uint64 `json:"elapsed_ms"`
		}
		if json.Unmarshal(line, &v) == nil && v.Phase == "response_ready" && v.Elapsed != nil && *v.Elapsed <= 600000 {
			return v.Elapsed
		}
	}
	return nil
}

type xperfReceipt struct {
	Status     string   `json:"status"`
	Mode       string   `json:"proof_mode"`
	Policy     string   `json:"proof_policy"`
	JobID      string   `json:"job_id"`
	Attempt    string   `json:"attempt"`
	Fence      string   `json:"fence"`
	ExpiresMS  int64    `json:"expires_at_ms"`
	RequestSHA string   `json:"request_sha256"`
	Complete   bool     `json:"complete"`
	Pending    []int    `json:"pending"`
	Remaining  int      `json:"remaining_attempts"`
	Rejections []string `json:"rejections"`
	Exchanges  []struct {
		Index         int            `json:"index"`
		Fulfilled     bool           `json:"fulfilled"`
		Operation     string         `json:"operation"`
		QueryID       string         `json:"query_id"`
		Variables     map[string]any `json:"variables"`
		Features      map[string]any `json:"features"`
		FieldToggles  map[string]any `json:"field_toggles"`
		HTTPStatus    int            `json:"http_status"`
		Body          string         `json:"body"`
		SentBytes     uint64         `json:"sent_bytes"`
		ReceivedBytes uint64         `json:"received_bytes"`
		DurationMS    uint64         `json:"duration_ms"`
	} `json:"exchanges"`
}

type xperfBinding struct {
	job, fence, requestSHA string
	expiresMS              int64
}

func xperfRegistration(job string, specs []xSpec, mode string, now time.Time) (map[string]any, xperfBinding, error) {
	payload := xperfPayload(specs, mode)
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, xperfBinding{}, errors.New("control_request_invalid")
	}
	// The verifier hashes serde_json::Value, whose object keys are ordered.
	// Convert nested Go structs to maps before reproducing that canonical JSON.
	var canonical any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&canonical) != nil {
		return nil, xperfBinding{}, errors.New("control_request_invalid")
	}
	raw, err = json.Marshal(canonical)
	if err != nil {
		return nil, xperfBinding{}, errors.New("control_request_invalid")
	}
	hash := sha256.Sum256(raw)
	b := xperfBinding{job: job, fence: "fence-" + job, requestSHA: hex.EncodeToString(hash[:]), expiresMS: now.Add(300 * time.Second).UnixMilli()}
	return map[string]any{"job_id": job, "attempt": "1", "fence": b.fence, "expires_at_ms": b.expiresMS, "payload": payload}, b, nil
}

func xperfCheckBinding(r xperfReceipt, b xperfBinding) error {
	if r.JobID != b.job || r.Attempt != "1" || r.Fence != b.fence || r.ExpiresMS != b.expiresMS || r.RequestSHA != b.requestSHA {
		return errors.New("receipt_binding_mismatch")
	}
	return nil
}

func xperfCheckReceipt(r xperfReceipt, observations []xperfObserved, mode string) error {
	if mode == "batch" && (r.Mode != "mpc" || r.Policy != "x-mpc-batch-experimental-v1") || mode == "proxy" && (r.Mode != "proxy" || r.Policy != "x-proxy-experimental-v1") || mode == "mpc" && (r.Mode != "" && r.Mode != "mpc" || r.Policy != "") {
		return errors.New("receipt_proof_mode_mismatch")
	}
	if r.Status != "x_read" || !r.Complete || len(r.Pending) != 0 || r.Remaining != 0 || len(r.Rejections) != 0 || len(r.Exchanges) != len(observations) || len(observations) == 0 {
		return errors.New("receipt_incomplete_or_rejected")
	}
	for i, e := range r.Exchanges {
		o := observations[i]
		s := xSpec{Operation: e.Operation, QueryID: e.QueryID, Variables: e.Variables, Features: e.Features, FieldToggles: e.FieldToggles}
		if e.Index != i || !e.Fulfilled || e.HTTPStatus != 200 || o.httpStatus != 200 || !reflect.DeepEqual(s, o.spec) || sha256.Sum256([]byte(e.Body)) != o.bodyHash || e.SentBytes != o.summary.SentBytes || e.ReceivedBytes != o.summary.ReceivedBytes {
			return errors.New("receipt_mismatch")
		}
	}
	return nil
}

func xperfAPI(ctx context.Context, client *http.Client, c xperfConfig, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return errors.New("control_request_invalid")
		}
		body = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, c.api+path, body)
	if err != nil {
		return errors.New("control_request_invalid")
	}
	r.Header.Set("Authorization", "Bearer "+c.key)
	r.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(r)
	if err != nil {
		return errors.New("control_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New("control_rejected")
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 16<<20))
	d.UseNumber()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("control_response_invalid")
	}
	return nil
}

func xperfWait(ctx context.Context, client *http.Client, c xperfConfig, job string, attempted int) (xperfReceipt, error) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		var r xperfReceipt
		err := xperfAPI(ctx, client, c, http.MethodGet, "/v1/sessions/"+job+"/1", nil, &r)
		if err != nil {
			return r, err
		}
		if r.Status != "x_read" || len(r.Exchanges)+len(r.Rejections) >= attempted || time.Now().After(deadline) {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return r, errors.New("receipt_timeout")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Metrics contain fixed labels and numbers only. Raw provider identifiers,
// request data, response data, control tokens and diagnostic text cannot enter.
type xperfMetric struct {
	MpcNetwork         string            `json:"mpc_network,omitempty"`
	Schema             int               `json:"schema"`
	Sample             int               `json:"sample"`
	Mode               string            `json:"mode"`
	Headers            string            `json:"headers"`
	Workload           string            `json:"workload"`
	Status             string            `json:"status"`
	Verified           bool              `json:"verified"`
	StartNS            int64             `json:"start_unix_ns"`
	FinishNS           int64             `json:"finish_unix_ns"`
	DurationMS         int64             `json:"duration_ms"`
	ReceiptWaitMS      int64             `json:"receipt_wait_ms"`
	Exchanges          int               `json:"exchanges"`
	Items              int               `json:"items"`
	MaxRecv            int               `json:"max_recv"`
	SentRecords        int               `json:"max_sent_records"`
	RecvRecords        int               `json:"max_recv_records_online"`
	PrepareHoldMS      int               `json:"prepare_hold_ms"`
	BatchReads         int               `json:"batch_reads"`
	VerifierSent       uint64            `json:"verifier_sent_bytes"`
	VerifierReceived   uint64            `json:"verifier_received_bytes"`
	TransportComplete  bool              `json:"verifier_telemetry_complete"`
	TranscriptSent     uint64            `json:"transcript_sent_bytes"`
	TranscriptReceived uint64            `json:"transcript_received_bytes"`
	BodyBytes          int               `json:"decoded_body_bytes"`
	HelperMS           int64             `json:"helper_wall_ms"`
	ExecutionMS        *uint64           `json:"helper_execution_ms,omitempty"`
	ProvisionalMS      *uint64           `json:"response_ready_ms,omitempty"`
	UserCPUSeconds     float64           `json:"helper_user_cpu_seconds"`
	SystemCPUSeconds   float64           `json:"helper_system_cpu_seconds"`
	PeakRSSBytes       int64             `json:"helper_peak_rss_bytes"`
	Timings            map[string]uint64 `json:"timings_ms"`
	Concurrency        int               `json:"concurrency"`
	AccountCapacity    int               `json:"account_capacity"`
	ReceiptCapacity    int               `json:"receipt_capacity"`
	RealAccounts       int               `json:"real_accounts"`
	QueueWaitMS        int64             `json:"queue_wait_ms"`
	RunStartNS         int64             `json:"run_start_unix_ns"`
	RunFinishNS        int64             `json:"run_finish_unix_ns"`
	SustainedSeconds   int               `json:"sustained_seconds"`
	NetworkProfile     string            `json:"network_profile"`
	SimulatedDelayMS   int               `json:"simulated_one_way_delay_ms"`
	Bandwidth          int               `json:"bandwidth_bytes_second"`
	RateLimit          *uint64           `json:"rate_limit_limit,omitempty"`
	RateRemaining      *uint64           `json:"rate_limit_remaining,omitempty"`
	RateReset          *uint64           `json:"rate_limit_reset_epoch_seconds,omitempty"`
	ReceiptObserved    bool              `json:"receipt_observed"`
	ReceiptBound       bool              `json:"receipt_bound"`
	ReceiptComplete    bool              `json:"receipt_complete"`
	ReceiptPending     int               `json:"receipt_pending"`
	ReceiptRemaining   int               `json:"receipt_remaining_attempts"`
	ReceiptRejections  int               `json:"receipt_rejections"`
}

func xperfMeasurement(c xperfConfig, sample int, started time.Time, observations []xperfObserved, receiptMS int64, failure string) xperfMetric {
	now := time.Now()
	m := xperfMetric{Schema: 1, Sample: sample, Mode: c.mode, Headers: c.headers, Workload: c.workload, Status: "verified", Verified: failure == "", StartNS: started.UnixNano(), FinishNS: now.UnixNano(), DurationMS: now.Sub(started).Milliseconds(), ReceiptWaitMS: receiptMS, Exchanges: len(observations), MaxRecv: c.maxRecv, SentRecords: c.sentRecords, RecvRecords: c.recvRecords, PrepareHoldMS: c.prepareHoldMS, BatchReads: c.batchReads, TransportComplete: len(observations) > 0, Timings: map[string]uint64{}}
	m.MpcNetwork = c.mpcNetwork
	m.Concurrency, m.AccountCapacity, m.ReceiptCapacity = c.concurrency, c.accountCapacity, c.receiptCapacity
	m.RealAccounts, m.SustainedSeconds = 1, c.sustainedSeconds
	m.NetworkProfile, m.SimulatedDelayMS, m.Bandwidth = c.networkProfile, c.simulatedDelayMS, c.bandwidth
	if m.NetworkProfile == "" {
		m.NetworkProfile = "direct"
	}
	if m.Concurrency == 0 {
		m.Concurrency = 1
	}
	if m.AccountCapacity == 0 {
		m.AccountCapacity = 1
	}
	if m.ReceiptCapacity == 0 {
		m.ReceiptCapacity = 1
	}
	if failure != "" {
		m.Status = xperfFailureLabel(failure)
	}
	for _, o := range observations {
		s := o.summary
		if o.receiptObserved {
			m.ReceiptObserved, m.ReceiptBound, m.ReceiptComplete = true, o.receiptBound, o.receiptComplete
			m.ReceiptPending, m.ReceiptRemaining, m.ReceiptRejections = o.receiptPending, o.receiptRemaining, o.receiptRejections
		}
		if o.rateLimit != nil {
			m.RateLimit = o.rateLimit
		}
		if o.rateRemaining != nil && (c.batchReads != 2 || m.RateRemaining == nil || *o.rateRemaining < *m.RateRemaining) {
			m.RateRemaining = o.rateRemaining
		}
		if o.rateReset != nil && (c.batchReads != 2 || m.RateReset == nil || *o.rateReset > *m.RateReset) {
			m.RateReset = o.rateReset
		}
		m.TranscriptSent += s.SentBytes
		m.TranscriptReceived += s.ReceivedBytes
		m.BodyBytes += o.bodyBytes
		m.Items += o.items
		if o.sharedConnection {
			continue
		}
		if s.Status != "proof_sent" || s.Mode != c.mode || s.VerifierSent == nil || s.VerifierReceived == nil || s.TransportLayer != "tcp_payload" || s.TransportSaturated || s.VerifierSent != nil && *s.VerifierSent > 1<<40 || s.VerifierReceived != nil && *s.VerifierReceived > 1<<40 {
			m.TransportComplete = false
		} else {
			m.VerifierSent += *s.VerifierSent
			m.VerifierReceived += *s.VerifierReceived
		}
		m.HelperMS += o.helperMS
		m.UserCPUSeconds += o.userCPUSeconds
		m.SystemCPUSeconds += o.systemCPUSeconds
		if o.peakRSSBytes > m.PeakRSSBytes {
			m.PeakRSSBytes = o.peakRSSBytes
		}
		if s.ExecutionMS != nil {
			if m.ExecutionMS == nil {
				m.ExecutionMS = new(uint64)
			}
			*m.ExecutionMS += *s.ExecutionMS
		}
		if len(observations) == 1 || c.batchReads == 2 {
			m.ProvisionalMS = o.provisionalMS
		}
		for _, phase := range []string{"control_connect", "commit", "request_write", "response_read", "tls_finish", "prove", "finalize", "total"} {
			if n, ok := s.Timings[phase]; ok && n <= 600000 {
				m.Timings[phase] += n
			}
		}
	}
	return m
}

func xperfFailureLabel(failure string) string {
	switch failure {
	case "bootstrap_failed", "request_capture_failed", "request_policy", "request_serialization", "random_source_failed", "control_request_invalid", "control_unavailable", "control_rejected", "control_response_invalid", "control_token_invalid", "private_diagnostic_write_failed", "helper_failed", "helper_summary_invalid", "helper_response_invalid", "provider_rate_limited", "provider_auth_failed", "provider_http_failed", "typed_result_parse_failed", "pagination_cursor_missing_or_stuck", "receipt_timeout", "receipt_incomplete_or_rejected", "receipt_mismatch", "receipt_proof_mode_mismatch", "receipt_binding_mismatch", "provider_quota_exhausted", "account_backpressure", "experiment_window_expired", "metrics_write_failed":
		return failure
	default:
		return "experiment_failed"
	}
}

func TestXPerformance(t *testing.T) {
	if os.Getenv("SCARLETT_XPERF") != "1" {
		t.Skip("real-provider experiments require SCARLETT_XPERF=1")
	}
	c, err := xperfConfiguration()
	if err != nil {
		t.Fatal(err.Error())
	}
	session, err := readXSession(c.session)
	if err != nil {
		t.Fatal("private_session_invalid")
	}
	metrics, err := os.OpenFile(filepath.Join(c.output, "metrics.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal("metrics_file_must_be_new")
	}
	defer metrics.Close()
	enc := json.NewEncoder(metrics)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.samples)*6*time.Minute+2*time.Minute)
	defer cancel()
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	defer base.CloseIdleConnections()
	control := &http.Client{Transport: base, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	capture := &xperfCapture{bootstrap: true, base: base}
	router := &xperfRouter{bootstrap: capture}
	client, err := session.NewClient(ctx, x.WithHTTPClient(&http.Client{Timeout: 2 * time.Minute, Transport: router}), x.WithRetry(1, time.Millisecond), x.WithMinRequestGap(0))
	if err != nil {
		_ = enc.Encode(xperfMeasurement(c, 0, time.Now(), nil, 0, "bootstrap_failed"))
		_ = metrics.Sync()
		t.Fatal("bootstrap_failed; no proof was attempted")
	}
	capture.bootstrap = false
	var runStartNS int64
	results, failure := xperfRun(ctx, c, func(jobCtx context.Context, sample int) xperfMetric {
		started := time.Now()
		capture := &xperfCapture{}
		jobCtx = context.WithValue(jobCtx, xperfCaptureKey{}, capture)
		observations, receiptMS, failed := xperfSample(jobCtx, c, sample, control, client, capture)
		return xperfMeasurement(c, sample, started, observations, receiptMS, failed)
	}, func(m xperfMetric) error {
		if runStartNS == 0 {
			runStartNS = m.RunStartNS
		}
		if err := enc.Encode(m); err != nil {
			return err
		}
		return metrics.Sync()
	})
	runSummary, summaryErr := os.OpenFile(filepath.Join(c.output, "run-summary.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if summaryErr != nil {
		t.Fatal("run_summary_write_failed")
	}
	summaryErr = json.NewEncoder(runSummary).Encode(map[string]any{"schema": 1, "start_unix_ns": runStartNS, "finish_unix_ns": time.Now().UnixNano(), "attempted_jobs": results, "sample_ceiling": c.samples, "sustained_seconds": c.sustainedSeconds, "stopped": failure != "", "status": func() string {
		if failure == "" {
			return "complete"
		}
		return xperfFailureLabel(failure)
	}()})
	syncErr, closeErr := runSummary.Sync(), runSummary.Close()
	if summaryErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal("run_summary_write_failed")
	}
	if failure != "" {
		t.Fatalf("%s; stopped without retrying provider work; recorded attempts=%d", xperfFailureLabel(failure), results)
	}

}

func xperfSample(parent context.Context, c xperfConfig, sample int, control *http.Client, client *x.Client, capture *xperfCapture) ([]xperfObserved, int64, string) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	if xperfStopped(ctx) {
		return nil, 0, "account_backpressure"
	}
	var specs []xSpec
	var request *http.Request
	var requests []*http.Request
	var err error
	receiptMode := c.mode
	if c.batchReads == 2 {
		specs, requests, err = xperfBatchPlan(ctx, client, capture)
		receiptMode = "batch"
	} else {
		specs, request, err = xperfPlan(ctx, client, capture, c.workload)
	}
	if err != nil {
		return nil, 0, err.Error()
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, 0, "random_source_failed"
	}
	job := "xperf-" + hex.EncodeToString(random[:])
	registration, binding, err := xperfRegistration(job, specs, receiptMode, time.Now())
	if err != nil {
		return nil, 0, err.Error()
	}
	var created struct {
		Token   string `json:"token"`
		Durable bool   `json:"durable"`
	}
	if xperfStopped(ctx) {
		return nil, 0, "account_backpressure"
	}
	if err := xperfAPI(ctx, control, c, http.MethodPost, "/v1/sessions", registration, &created); err != nil {
		return nil, 0, err.Error()
	}
	if len(created.Token) != 64 || !isHex(created.Token) {
		return nil, 0, "control_token_invalid"
	}
	if c.batchReads == 2 && !created.Durable {
		return nil, 0, "control_rejected"
	}
	observations := make([]xperfObserved, 0, len(specs))
	failure, cursor := "", ""
	if c.batchReads == 2 && xperfStopped(ctx) {
		failure = "account_backpressure"
	} else if c.batchReads == 2 {
		var bodies [][]byte
		observations, bodies, err = xperfProveBatch(ctx, c, created.Token, requests, filepath.Join(c.output, fmt.Sprintf("sample-%03d-batch.stderr", sample)))
		if err != nil {
			failure = err.Error()
			xperfStopNow(ctx)
		}
		for _, o := range observations {
			if o.rateRemaining != nil && *o.rateRemaining == 0 {
				xperfStopNow(ctx)
			}
		}
		if len(observations) == 2 && len(bodies) == 2 {
			for i, workload := range []string{"profile", "post"} {
				if observations[i].httpStatus != 200 || bodies[i] == nil {
					continue
				}
				capture.replaySpec, capture.replayBody = &observations[i].spec, bodies[i]
				parsed, parseErr := xperfRead(ctx, client, workload, "")
				capture.replaySpec, capture.replayBody = nil, nil
				if parseErr != nil {
					if failure == "" {
						failure = "typed_result_parse_failed"
					}
					continue
				}
				observations[i].items = parsed.items
			}
		}
	} else {
		for i := range specs {
			if xperfStopped(ctx) {
				failure = "account_backpressure"
				break
			}
			if i > 0 {
				capture.replaySpec, capture.request = nil, nil
				_, _ = xperfRead(ctx, client, c.workload, cursor)
				if capture.request == nil {
					failure = "request_capture_failed"
					break
				}
				request = capture.request
			}
			o, body, err := xperfProve(ctx, c, created.Token, request, filepath.Join(c.output, fmt.Sprintf("sample-%03d-exchange-%d.stderr", sample, i)))
			observations = append(observations, o)
			if err != nil {
				failure = err.Error()
				xperfStopNow(ctx)
				break
			}
			if o.rateRemaining != nil && *o.rateRemaining == 0 {
				xperfStopNow(ctx)
			}
			capture.replaySpec, capture.replayBody = &o.spec, body
			parsed, err := xperfRead(ctx, client, c.workload, cursor)
			capture.replaySpec, capture.replayBody = nil, nil
			if err != nil {
				failure = "typed_result_parse_failed"
				break
			}
			observations[len(observations)-1].items = parsed.items
			if i < len(specs)-1 && (parsed.cursor == "" || parsed.cursor == cursor) {
				failure = "pagination_cursor_missing_or_stuck"
				break
			}
			cursor = parsed.cursor
		}
	}
	started := time.Now()
	r, err := xperfWait(ctx, control, c, job, len(observations))
	receiptMS := time.Since(started).Milliseconds()
	if len(observations) > 0 && err == nil {
		last := &observations[len(observations)-1]
		last.receiptObserved, last.receiptBound = true, xperfCheckBinding(r, binding) == nil
		last.receiptComplete = r.Complete && len(r.Pending) == 0 && r.Remaining == 0
		last.receiptPending, last.receiptRemaining, last.receiptRejections = len(r.Pending), r.Remaining, len(r.Rejections)
	}
	if failure == "" {
		if err != nil {
			failure = err.Error()
		} else if err := xperfCheckBinding(r, binding); err != nil {
			failure = err.Error()
		} else if err := xperfCheckReceipt(r, observations, receiptMode); err != nil {
			failure = err.Error()
		}
	}
	return observations, receiptMS, failure
}

func TestXPerfCaptureAndVariantInput(t *testing.T) {
	r := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/SearchTimeline?variables=%7B%22rawQuery%22%3A%22solana%22%2C%22count%22%3A20%7D&features=%7B%22enabled%22%3Atrue%7D")
	r.Header.Set("Cookie", "auth_token=PRIVATECOOKIE; ct0=PRIVATECSRF")
	r.Header.Set("X-Csrf-Token", "PRIVATECSRF")
	r.Header.Set("Authorization", "Bearer PRIVATEBEARER")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	capture := &xperfCapture{}
	if _, err := capture.RoundTrip(r); !errors.Is(err, errXPerfCaptured) {
		t.Fatal("offline capture failed")
	}
	spec, err := xperfSpec(capture.request)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(xperfPayload([]xSpec{spec}, "mpc"))
	if strings.Contains(string(payload), "PRIVATE") || strings.Contains(string(payload), "proof_mode") {
		t.Fatal("payload leaked credentials or experimental fields")
	}
	payload, _ = json.Marshal(xperfPayload([]xSpec{spec}, "proxy"))
	if !strings.Contains(string(payload), `"proof_policy":"x-proxy-experimental-v1"`) {
		t.Fatal("proxy policy is not server-bound")
	}
	input, _, err := xperfProverInput(xperfConfig{mode: "mpc", headers: "minimal", verifier: "verifier:7047", sentRecords: 3, recvRecords: 3, prepareHoldMS: 10, responseReady: true, mpcNetwork: "reduce_roundtrips"}, strings.Repeat("ab", 32), r)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(input, &p)
	raw, _ := base64.StdEncoding.DecodeString(p["request"].(string))
	if bytes.Contains(raw, []byte("Sec-Fetch-Dest")) || !bytes.Contains(raw, []byte("PRIVATECOOKIE")) || !bytes.Contains(raw, []byte("Connection: close")) || !bytes.Contains(raw, []byte("Accept-Encoding: gzip")) || p["max_sent_records"] != float64(3) || p["max_recv_records_online"] != float64(3) || p["response_ready_event"] != true || p["mpc_network"] != "reduce_roundtrips" {
		t.Fatal("candidate changed required transport or credentials")
	}
	if r.Header.Get("Sec-Fetch-Dest") == "" || r.Close {
		t.Fatal("candidate mutated original request")
	}
}

func TestXPerfRejectsIncompleteAndAlteredReceipts(t *testing.T) {
	spec := xSpec{Operation: "SearchTimeline", QueryID: "q", Variables: map[string]any{"count": json.Number("20")}, Features: map[string]any{}}
	o := xperfObserved{spec: spec, bodyHash: sha256.Sum256([]byte(`{"data":{}}`)), httpStatus: 200, summary: xperfSummary{SentBytes: 20, ReceivedBytes: 30}}
	raw := `{"status":"x_read","complete":true,"pending":[],"remaining_attempts":0,"rejections":[],"exchanges":[{"index":0,"fulfilled":true,"operation":"SearchTimeline","query_id":"q","variables":{"count":20},"features":{},"http_status":200,"body":"{\"data\":{}}","sent_bytes":20,"received_bytes":30}]}`
	decode := func() xperfReceipt {
		var r xperfReceipt
		d := json.NewDecoder(strings.NewReader(raw))
		d.UseNumber()
		if err := d.Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if err := xperfCheckReceipt(decode(), []xperfObserved{o}, "mpc"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*xperfReceipt){
		func(r *xperfReceipt) { r.Complete = false }, func(r *xperfReceipt) { r.Pending = []int{0} }, func(r *xperfReceipt) { r.Remaining = 1 }, func(r *xperfReceipt) { r.Rejections = []string{"PRIVATE_DIAGNOSTIC"} },
		func(r *xperfReceipt) { r.Exchanges[0].Fulfilled = false }, func(r *xperfReceipt) { r.Exchanges[0].Body += " " }, func(r *xperfReceipt) { r.Exchanges[0].Variables["count"] = json.Number("21") }, func(r *xperfReceipt) { r.Exchanges[0].ReceivedBytes++ }, func(r *xperfReceipt) { r.Exchanges[0].Index = 1 },
	} {
		r := decode()
		mutate(&r)
		if xperfCheckReceipt(r, []xperfObserved{o}, "mpc") == nil {
			t.Fatal("invalid receipt counted verified")
		}
	}
	proxy := decode()
	if xperfCheckReceipt(proxy, []xperfObserved{o}, "proxy") == nil {
		t.Fatal("MPC receipt counted as proxy proof")
	}
	proxy.Mode, proxy.Policy = "proxy", "x-proxy-experimental-v1"
	if xperfCheckReceipt(proxy, []xperfObserved{o}, "proxy") != nil {
		t.Fatal("valid experimental receipt rejected")
	}
	if xperfCheckReceipt(proxy, []xperfObserved{o}, "mpc") == nil {
		t.Fatal("proxy receipt counted as MPC proof")
	}
}

func TestXPerfMetricsCannotCarryProviderContent(t *testing.T) {
	n := uint64(100)
	o := xperfObserved{summary: xperfSummary{Status: "proof_sent", Response: "PRIVATE_RESPONSE", Mode: "mpc", VerifierSent: &n, VerifierReceived: &n, TransportLayer: "tcp_payload", Timings: map[string]uint64{"PRIVATE_PHASE": 1, "prove": 10}}, bodyBytes: 8}
	m := xperfMeasurement(xperfConfig{mode: "mpc", headers: "normal", workload: "search"}, 1, time.Now(), []xperfObserved{o}, 1, "")
	raw, err := json.Marshal(m)
	if err != nil || strings.Contains(string(raw), "PRIVATE") || !m.TransportComplete {
		t.Fatal("metrics leaked provider data or lost telemetry")
	}
	o.summary.VerifierReceived = nil
	if xperfMeasurement(xperfConfig{}, 1, time.Now(), []xperfObserved{o}, 0, "").TransportComplete {
		t.Fatal("missing counter became zero-byte evidence")
	}
	if xperfProvisional([]byte(`{"phase":"SECRET","elapsed_ms":4}`)) != nil {
		t.Fatal("untrusted phase escaped whitelist")
	}
	if xperfFailureLabel("PRIVATE_COOKIE") != "experiment_failed" {
		t.Fatal("untrusted failure text escaped whitelist")
	}
}

func TestXPerfPrivateFileAndDirectory(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := xperfPrivateRead(path, 10); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := xperfPrivateRead(filepath.Join(dir, "link"), 10); err == nil {
		t.Fatal("symlink accepted")
	}
	_ = os.Chmod(path, 0644)
	if _, err := xperfPrivateRead(path, 10); err == nil {
		t.Fatal("public key file accepted")
	}
	_ = os.Chmod(dir, 0755)
	if xperfPrivateDirectory(dir) == nil {
		t.Fatal("public run directory accepted")
	}
}

func TestXPerfDurableRegistrationFenceAndExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	spec := xSpec{Operation: "SearchTimeline", QueryID: "q", Variables: map[string]any{"count": json.Number("20")}, Features: map[string]any{}}
	registration, binding, err := xperfRegistration("xperf-synthetic", []xSpec{spec}, "mpc", now)
	if err != nil {
		t.Fatal(err)
	}
	if registration["expires_at_ms"] != int64(1700000300000) || registration["fence"] != "fence-xperf-synthetic" || registration["attempt"] != "1" {
		t.Fatal("durable registration missing bounded synthetic fence/expiry")
	}
	canonical := `{"exchanges":[{"features":{},"operation":"SearchTimeline","query_id":"q","variables":{"count":20}}],"max_attempts":1,"type":"x.read"}`
	hash := sha256.Sum256([]byte(canonical))
	if binding.requestSHA != hex.EncodeToString(hash[:]) {
		t.Fatal("payload hash does not match verifier canonical JSON")
	}
	r := xperfReceipt{JobID: binding.job, Attempt: "1", Fence: binding.fence, ExpiresMS: binding.expiresMS, RequestSHA: binding.requestSHA}
	if xperfCheckBinding(r, binding) != nil {
		t.Fatal("valid binding rejected")
	}
	r.ExpiresMS++
	if xperfCheckBinding(r, binding) == nil {
		t.Fatal("altered expiry accepted")
	}
}

// Admission state is experiment-only. Production service/account ownership stays
// in the existing servicePool; live xperf supplies exactly one local account.
type xperfAccount struct {
	capacity, inFlight int
	next, cooldown     time.Time
	authBlocked        bool
}
type xperfAdmission struct {
	accounts                                []xperfAccount
	hostCapacity, receiptCapacity, inFlight int
	gap                                     time.Duration
	stopped                                 bool
}

func (a *xperfAdmission) acquire(now time.Time) (int, time.Time) {
	if a.stopped || a.inFlight >= a.hostCapacity || a.inFlight >= a.receiptCapacity {
		return -1, time.Time{}
	}
	var wake time.Time
	for i := range a.accounts {
		account := &a.accounts[i]
		if account.authBlocked || account.inFlight >= account.capacity {
			continue
		}
		next := account.next
		if account.cooldown.After(next) {
			next = account.cooldown
		}
		if next.After(now) {
			if wake.IsZero() || next.Before(wake) {
				wake = next
			}
			continue
		}
		account.inFlight++
		a.inFlight++
		account.next = now.Add(a.gap)
		return i, time.Time{}
	}
	return -1, wake
}
func (a *xperfAdmission) finish(index int, now time.Time, m xperfMetric) {
	account := &a.accounts[index]
	account.inFlight--
	a.inFlight--
	quota := m.Status == "provider_rate_limited" || m.RateRemaining != nil && *m.RateRemaining == 0
	if quota {
		account.cooldown = now.Add(30 * time.Second)
		if m.RateReset != nil && *m.RateReset <= 1e12 {
			reset := time.Unix(int64(*m.RateReset), 0)
			if reset.After(account.cooldown) {
				account.cooldown = reset
			}
		}
	}
	if m.Status == "provider_auth_failed" {
		account.authBlocked = true
	}
	// Any failure stops the whole experiment. Even synthetic independent
	// accounts cannot be selected to continue around an authoritative limit.
	if !m.Verified || quota {
		a.stopped = true
	}
}

type xperfStop struct {
	mu      sync.Mutex
	stopped bool
}
type xperfStopKey struct{}

func (s *xperfStop) stop()           { s.mu.Lock(); s.stopped = true; s.mu.Unlock() }
func (s *xperfStop) isStopped() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.stopped }
func xperfStopped(ctx context.Context) bool {
	stop, _ := ctx.Value(xperfStopKey{}).(*xperfStop)
	return stop != nil && stop.isStopped()
}
func xperfStopNow(ctx context.Context) {
	if stop, _ := ctx.Value(xperfStopKey{}).(*xperfStop); stop != nil {
		stop.stop()
	}
}

// The dispatcher owns admission and output. Workers publish stop before their
// result enters the channel, then already-started work drains to its receipt.
// An ambiguous provider attempt is never resubmitted.
func xperfRun(ctx context.Context, c xperfConfig, perform func(context.Context, int) xperfMetric, record func(xperfMetric) error) (int, string) {
	started := time.Now()
	deadline := time.Time{}
	if c.sustainedSeconds > 0 {
		deadline = started.Add(time.Duration(c.sustainedSeconds) * time.Second)
	}
	admission := xperfAdmission{accounts: []xperfAccount{{capacity: c.accountCapacity}}, hostCapacity: c.concurrency, receiptCapacity: c.receiptCapacity, gap: time.Duration(c.minGapMS) * time.Millisecond}
	stop := &xperfStop{}
	ctx = context.WithValue(ctx, xperfStopKey{}, stop)
	type result struct {
		account int
		metric  xperfMetric
	}
	done := make(chan result, c.concurrency)
	next, recorded, failure := 1, 0, ""
	queued := started
	for {
		now := time.Now()
		withinWindow := deadline.IsZero() || now.Before(deadline)
		var wake time.Time
		for next <= c.samples && withinWindow && ctx.Err() == nil && !stop.isStopped() {
			account, later := admission.acquire(time.Now())
			if account < 0 {
				wake = later
				break
			}
			sample, queueWait := next, time.Since(queued).Milliseconds()
			next++
			queued = time.Now()
			go func() {
				m := perform(ctx, sample)
				m.QueueWaitMS, m.RunStartNS = queueWait, started.UnixNano()
				if !m.Verified || m.RateRemaining != nil && *m.RateRemaining == 0 {
					stop.stop()
				}
				done <- result{account: account, metric: m}
			}()
			now = time.Now()
			withinWindow = deadline.IsZero() || now.Before(deadline)
		}
		if admission.inFlight == 0 && (next > c.samples || !withinWindow || ctx.Err() != nil || stop.isStopped() || admission.stopped) {
			break
		}
		if ctx.Err() != nil {
			stop.stop()
			if failure == "" {
				failure = "experiment_window_expired"
			}
		}
		// Wake for an admission gap or the measured window. Completed workers
		// also wake the dispatcher; no polling or unbounded queue is needed.
		if !deadline.IsZero() && withinWindow && (wake.IsZero() || deadline.Before(wake)) {
			wake = deadline
		}
		var timer *time.Timer
		var timerC <-chan time.Time
		if !wake.IsZero() {
			timer = time.NewTimer(time.Until(wake))
			timerC = timer.C
		}
		select {
		case r := <-done:
			if timer != nil {
				timer.Stop()
			}
			r.metric.RunFinishNS = time.Now().UnixNano()
			admission.finish(r.account, time.Now(), r.metric)
			recorded++
			if err := record(r.metric); err != nil {
				stop.stop()
				if failure == "" {
					failure = "metrics_write_failed"
				}
			}
			if !r.metric.Verified && failure == "" {
				failure = r.metric.Status
			}
			if r.metric.RateRemaining != nil && *r.metric.RateRemaining == 0 && failure == "" {
				failure = "provider_quota_exhausted"
			}
		case <-timerC:
		}
	}
	return recorded, failure
}

func TestXPerfAdmissionAccountCooldownAndBackpressure(t *testing.T) {
	now := time.Unix(1700000000, 0)
	a := xperfAdmission{accounts: []xperfAccount{{capacity: 1}, {capacity: 1}}, hostCapacity: 4, receiptCapacity: 2, gap: time.Second}
	first, _ := a.acquire(now)
	second, _ := a.acquire(now)
	if first != 0 || second != 1 {
		t.Fatal("independent synthetic accounts not selected")
	}
	if next, _ := a.acquire(now); next != -1 {
		t.Fatal("capacity exceeded")
	}
	a.finish(first, now, xperfMetric{Verified: true})
	if next, wake := a.acquire(now); next != -1 || !wake.Equal(now.Add(time.Second)) {
		t.Fatal("account gap bypassed")
	}
	reset, remaining := uint64(now.Add(90*time.Second).Unix()), uint64(0)
	a.finish(second, now, xperfMetric{Status: "provider_rate_limited", RateReset: &reset, RateRemaining: &remaining})
	if !a.accounts[second].cooldown.Equal(time.Unix(int64(reset), 0)) || !a.stopped {
		t.Fatal("authoritative cooldown lost")
	}
	if next, _ := a.acquire(now.Add(100 * time.Second)); next != -1 {
		t.Fatal("experiment rotated account after rate limit")
	}
	a = xperfAdmission{accounts: []xperfAccount{{capacity: 4}}, hostCapacity: 4, receiptCapacity: 1}
	first, _ = a.acquire(now)
	if first != 0 {
		t.Fatal("single account unavailable")
	}
	if next, _ := a.acquire(now); next != -1 {
		t.Fatal("receipt backpressure bypassed")
	}
	a.finish(first, now, xperfMetric{Status: "provider_auth_failed"})
	if !a.accounts[0].authBlocked {
		t.Fatal("authentication failure did not block account")
	}
}

func TestXPerfConcurrentStopAndDrain(t *testing.T) {
	c := xperfConfig{concurrency: 4, accountCapacity: 2, receiptCapacity: 4, samples: 20}
	var mu sync.Mutex
	active, peak, attempts := 0, 0, 0
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	finished := make(chan struct{})
	failurePublished := make(chan struct{})
	var rows []xperfMetric
	go func() {
		n, failure := xperfRun(context.Background(), c, func(ctx context.Context, sample int) xperfMetric {
			mu.Lock()
			active++
			attempts++
			if active > peak {
				peak = active
			}
			mu.Unlock()
			entered <- struct{}{}
			<-release
			mu.Lock()
			active--
			mu.Unlock()
			if sample == 1 {
				xperfStopNow(ctx)
				close(failurePublished)
				return xperfMetric{Sample: sample, Status: "provider_rate_limited"}
			}
			<-failurePublished
			return xperfMetric{Sample: sample, Status: "verified", Verified: true}
		}, func(m xperfMetric) error { rows = append(rows, m); return nil })
		if n != 2 || failure != "provider_rate_limited" {
			t.Errorf("unexpected drained attempts=%d status=%s", n, failure)
		}
		close(finished)
	}()
	<-entered
	<-entered
	// The failing worker must publish its stop before either result is consumed.
	close(release)
	<-finished
	mu.Lock()
	defer mu.Unlock()
	if peak != 2 || attempts != 2 || len(rows) != 2 {
		t.Fatal("single account capacity or stop fence bypassed")
	}
	for _, row := range rows {
		if row.RunStartNS <= 0 || row.RunFinishNS < row.RunStartNS || row.QueueWaitMS < 0 {
			t.Fatal("invalid concurrent window telemetry")
		}
	}
}

func TestXPerfConcurrentCaptureIsBoundToContext(t *testing.T) {
	router := &xperfRouter{}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			capture := &xperfCapture{}
			req, err := http.NewRequestWithContext(context.WithValue(context.Background(), xperfCaptureKey{}, capture), http.MethodGet, fmt.Sprintf("https://x.com/i/api/graphql/q/SearchTimeline?variables=%%7B%%22count%%22%%3A%d%%7D&features=%%7B%%7D", index+1), nil)
			if err != nil {
				t.Error("fixture invalid")
				return
			}
			if _, err := router.RoundTrip(req); !errors.Is(err, errXPerfCaptured) || capture.request != nil && capture.request.URL.String() != req.URL.String() {
				t.Error("capture crossed job context")
			}
			spec, err := xperfSpec(capture.request)
			if err != nil || spec.Variables["count"] != json.Number(strconv.Itoa(index+1)) {
				t.Error("capture crossed job context")
			}
		}(i)
	}
	wg.Wait()
}

func TestXPerfQuotaTelemetryIsNumericAndBounded(t *testing.T) {
	h := http.Header{"X-Rate-Limit-Limit": {"50"}, "X-Rate-Limit-Remaining": {"0"}, "X-Rate-Limit-Reset": {"1700000100"}}
	if v := xperfNumericHeader(h, "X-Rate-Limit-Remaining"); v == nil || *v != 0 {
		t.Fatal("zero remaining lost")
	}
	for _, value := range []string{"SECRET", "-1", "1.5", "18446744073709551615", " 2"} {
		h.Set("X-Rate-Limit-Remaining", value)
		if xperfNumericHeader(h, "X-Rate-Limit-Remaining") != nil {
			t.Fatal("unsafe header accepted")
		}
	}
	h["X-Rate-Limit-Remaining"] = []string{"0", "1"}
	if xperfNumericHeader(h, "X-Rate-Limit-Remaining") != nil {
		t.Fatal("ambiguous header accepted")
	}
}

func TestXPerfProvenRateHeadersSurvive429Failure(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "fixture-helper")
	raw := "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 2\r\nX-Rate-Limit-Limit: 50\r\nX-Rate-Limit-Remaining: 0\r\nX-Rate-Limit-Reset: 1700000100\r\n\r\n{}"
	summary, err := json.Marshal(xperfSummary{Status: "proof_sent", Mode: "mpc", Response: base64.StdEncoding.EncodeToString([]byte(raw))})
	if err != nil {
		t.Fatal(err)
	}
	// The executable reads no credentials and makes no network requests.
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' '"+string(summary)+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	req := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/SearchTimeline?variables=%7B%22count%22%3A20%7D&features=%7B%7D")
	o, _, err := xperfProve(context.Background(), xperfConfig{prover: helper, mode: "mpc", headers: "normal", verifier: "127.0.0.1:1"}, strings.Repeat("ab", 32), req, filepath.Join(dir, "fixture.stderr"))
	if err == nil || err.Error() != "provider_rate_limited" || o.rateLimit == nil || *o.rateLimit != 50 || o.rateRemaining == nil || *o.rateRemaining != 0 || o.rateReset == nil || *o.rateReset != 1700000100 {
		t.Fatal("proven quota telemetry lost at failure")
	}
	m := xperfMeasurement(xperfConfig{mode: "mpc", headers: "normal", workload: "search"}, 1, time.Now(), []xperfObserved{o}, 0, err.Error())
	if m.Verified || m.Status != "provider_rate_limited" || m.RateRemaining == nil || *m.RateRemaining != 0 {
		t.Fatal("failed quota response counted verified or lost telemetry")
	}
}

func TestXPerfConfigurationCapacityAndRelayBinding(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	key := filepath.Join(dir, "fixture-key")
	if err := os.WriteFile(key, []byte("SYNTHETIC_CONTROL_KEY"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SCARLETT_XPERF_MODE", "SCARLETT_XPERF_HEADERS", "SCARLETT_XPERF_WORKLOAD", "SCARLETT_XPERF_BATCH_READS", "SCARLETT_XPERF_SAMPLES", "SCARLETT_XPERF_MAX_RECV", "SCARLETT_XPERF_SENT_RECORDS", "SCARLETT_XPERF_RECV_RECORDS", "SCARLETT_XPERF_PREPARE_HOLD_MS", "SCARLETT_XPERF_RESPONSE_READY", "SCARLETT_XPERF_CONCURRENCY", "SCARLETT_XPERF_ACCOUNT_CAPACITY", "SCARLETT_XPERF_RECEIPT_CAPACITY", "SCARLETT_XPERF_MIN_GAP_MS", "SCARLETT_XPERF_SUSTAINED_SECONDS", "SCARLETT_XPERF_NETWORK_PROFILE", "SCARLETT_XPERF_BANDWIDTH_BYTES_SECOND", "SCARLETT_XPERF_VERIFIER_SERVER_NAME"} {
		t.Setenv(name, "")
	}
	for name, value := range map[string]string{"SCARLETT_X_SESSION": "fixture-not-read", "SCARLETT_PROVER": "fixture-not-executed", "SCARLETT_VERIFIER": "127.0.0.1:7047", "SCARLETT_VERIFIER_API": "http://127.0.0.1:7070", "SCARLETT_XPERF_OUTPUT": dir, "SCARLETT_VERIFIER_KEY_FILE": key} {
		t.Setenv(name, value)
	}
	c, err := xperfConfiguration()
	if err != nil || c.concurrency != 1 || c.accountCapacity != 1 || c.receiptCapacity != 1 || c.minGapMS != 1000 || c.networkProfile != "direct" {
		t.Fatal("unsafe experiment defaults")
	}
	for _, variant := range []struct{ name, value string }{{"SCARLETT_XPERF_CONCURRENCY", "3"}, {"SCARLETT_XPERF_SUSTAINED_SECONDS", "59"}, {"SCARLETT_XPERF_NETWORK_PROFILE", "PRIVATE_REGION"}, {"SCARLETT_XPERF_BANDWIDTH_BYTES_SECOND", "1"}} {
		t.Setenv(variant.name, variant.value)
		if _, err := xperfConfiguration(); err == nil {
			t.Fatal("unsupported experiment option accepted")
		}
		t.Setenv(variant.name, "")
	}
	t.Setenv("SCARLETT_XPERF_NETWORK_PROFILE", "simulated-rtt80")
	if _, err := xperfConfiguration(); err == nil || err.Error() != "simulated_shaper_binding_missing" {
		t.Fatal("simulation label accepted without bound relay")
	}
	ready := filepath.Join(dir, "shaper-ready.json")
	if err := os.WriteFile(ready, []byte(`{"schema":1,"listen":"127.0.0.1:7047","topology":"simulated_loopback_tcp_tls","profile":"simulated-rtt80","simulated_one_way_delay_ms":40,"bandwidth_bytes_second":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCARLETT_XPERF_VERIFIER_SERVER_NAME", "verifier.fixture.invalid")
	if _, err := xperfConfiguration(); err != nil {
		t.Fatal("bound relay rejected")
	}
	t.Setenv("SCARLETT_VERIFIER", "verifier.fixture.invalid:7047")
	if _, err := xperfConfiguration(); err == nil || err.Error() != "unsafe_verifier_server_name" {
		t.Fatal("nonloopback TLS identity override accepted")
	}
}

func TestXPerfConcurrentBindingsCannotCrossJobs(t *testing.T) {
	var bindings []xperfBinding
	var receipts []xperfReceipt
	for i := 0; i < 4; i++ {
		spec := xSpec{Operation: "SearchTimeline", QueryID: "q", Variables: map[string]any{"count": json.Number(strconv.Itoa(i + 1))}, Features: map[string]any{}}
		_, b, err := xperfRegistration(fmt.Sprintf("xperf-fixture-%d", i), []xSpec{spec}, "mpc", time.Unix(1700000000, 0))
		if err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, b)
		receipts = append(receipts, xperfReceipt{JobID: b.job, Attempt: "1", Fence: b.fence, ExpiresMS: b.expiresMS, RequestSHA: b.requestSHA})
	}
	for i, b := range bindings {
		for j, r := range receipts {
			if (xperfCheckBinding(r, b) == nil) != (i == j) {
				t.Fatal("concurrent receipt matched another job")
			}
		}
	}
}

func TestXPerfBatchUsesTwoPinnedRequestsAndOneHelperMeasurement(t *testing.T) {
	requests := []*http.Request{
		mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/profile/UserByScreenName?features=%7B%7D&variables=%7B%22screen_name%22%3A%22jack%22%7D"),
		mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/post/TweetResultByRestId?features=%7B%7D&variables=%7B%22tweetId%22%3A%2220%22%7D"),
	}
	for _, r := range requests {
		r.Header.Set("Cookie", "auth_token=SYNTHETIC_AUTH; ct0=SYNTHETIC_CSRF")
		r.Header.Set("X-Csrf-Token", "SYNTHETIC_CSRF")
	}
	c := xperfConfig{mode: "mpc", headers: "normal", workload: "batch", batchReads: 2, verifier: "127.0.0.1:1"}
	input, sent, err := xperfRequestsInput(c, strings.Repeat("ab", 32), requests)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Request    string `json:"request"`
		BatchReads int    `json:"batch_reads"`
	}
	if json.Unmarshal(input, &payload) != nil || payload.BatchReads != 2 {
		t.Fatal("batch helper setting missing")
	}
	raw, _ := base64.StdEncoding.DecodeString(payload.Request)
	if bytes.Count(raw, []byte("Host: x.com")) != 2 || bytes.Count(raw, []byte("Connection: keep-alive")) != 1 || bytes.Count(raw, []byte("Connection: close")) != 1 || bytes.Count(raw, []byte("SYNTHETIC_AUTH")) != 2 {
		t.Fatal("pipeline requests changed")
	}
	specs := make([]xSpec, 2)
	for i, r := range requests {
		specs[i], _ = xperfSpec(r)
		if r.Close || r.Header.Get("Connection") != "" {
			t.Fatal("original request mutated")
		}
	}
	registration, _, err := xperfRegistration("xperf-synthetic-batch", specs, "batch", time.Now())
	registered, _ := json.Marshal(registration)
	if err != nil || bytes.Contains(registered, []byte("SYNTHETIC")) || !bytes.Contains(registered, []byte("x-mpc-batch-experimental-v1")) {
		t.Fatal("batch registration leaked credentials or missed policy")
	}
	if _, _, err := xperfRequestsInput(c, "synthetic", requests[:1]); err == nil {
		t.Fatal("partial pipeline accepted")
	}
	count := uint64(123)
	body := `{"data":{}}`
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n" + body)
	base := xperfObserved{helperMS: 10, userCPUSeconds: 2, summary: xperfSummary{Status: "proof_sent", Mode: "mpc", Response: base64.StdEncoding.EncodeToString(append(append([]byte(nil), response...), response...)), SentBytes: uint64(sent), ReceivedBytes: uint64(2 * len(response)), VerifierSent: &count, VerifierReceived: &count, TransportLayer: "tcp_payload", Timings: map[string]uint64{"commit": 5}}}
	for i := range requests {
		base.summary.BatchExchanges = append(base.summary.BatchExchanges, struct {
			Response      string `json:"response"`
			SentBytes     uint64 `json:"sent_bytes"`
			ReceivedBytes uint64 `json:"received_bytes"`
		}{base64.StdEncoding.EncodeToString(response), uint64(sent/2 + i*(sent%2)), uint64(len(response))})
	}
	observations, bodies, err := xperfBatchObservations(base, requests, sent)
	if err != nil || len(bodies) != 2 || len(observations) != 2 {
		t.Fatal("batch decode failed")
	}
	m := xperfMeasurement(c, 1, time.Now(), observations, 1, "")
	if m.HelperMS != 10 || m.UserCPUSeconds != 2 || m.VerifierSent != 123 || m.TranscriptSent != uint64(sent) || m.BodyBytes != 22 || m.Timings["commit"] != 5 || !m.TransportComplete {
		t.Fatal("shared connection resource costs counted twice or per-read bytes lost")
	}
	makeReceipt := func() xperfReceipt {
		records := make([]map[string]any, 2)
		for i, o := range observations {
			records[i] = map[string]any{"index": i, "fulfilled": true, "operation": o.spec.Operation, "query_id": o.spec.QueryID, "variables": o.spec.Variables, "features": o.spec.Features, "http_status": 200, "body": body, "sent_bytes": o.summary.SentBytes, "received_bytes": o.summary.ReceivedBytes}
		}
		raw, _ := json.Marshal(map[string]any{"status": "x_read", "proof_mode": "mpc", "proof_policy": "x-mpc-batch-experimental-v1", "complete": true, "remaining_attempts": 0, "pending": []int{}, "rejections": []string{}, "exchanges": records})
		var receipt xperfReceipt
		if json.Unmarshal(raw, &receipt) != nil {
			t.Fatal("fixture receipt invalid")
		}
		return receipt
	}
	r := makeReceipt()
	if xperfCheckReceipt(r, observations, "batch") != nil || xperfCheckReceipt(r, observations, "mpc") == nil {
		t.Fatal("batch receipt policy mismatch")
	}
	r.Exchanges[1].Body = "fabricated"
	if xperfCheckReceipt(r, observations, "batch") == nil {
		t.Fatal("altered second body accepted")
	}
	r = makeReceipt()
	r.Exchanges[1].ReceivedBytes++
	if xperfCheckReceipt(r, observations, "batch") == nil {
		t.Fatal("second read byte mismatch accepted")
	}
	r = makeReceipt()
	r.Exchanges = r.Exchanges[:1]
	if xperfCheckReceipt(r, observations, "batch") == nil {
		t.Fatal("partial receipt accepted")
	}
	base.summary.BatchExchanges[1].ReceivedBytes++
	if _, _, err := xperfBatchObservations(base, requests, sent); err == nil {
		t.Fatal("inconsistent split summary accepted")
	}
}
