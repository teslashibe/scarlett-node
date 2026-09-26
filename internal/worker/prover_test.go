package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// TestMain doubles as a fake scarlett-prover when SCARLETT_FAKE_PROVER is set.
func TestMain(m *testing.M) {
	mode := os.Getenv("SCARLETT_FAKE_PROVER")
	if mode == "" {
		os.Exit(m.Run())
	}
	var in struct {
		Verifier string          `json:"verifier"`
		Token    string          `json:"token"`
		Payload  json.RawMessage `json:"payload"`
	}
	data, _ := io.ReadAll(os.Stdin)
	if len(os.Args) != 2 || os.Args[1] != "prove" || json.Unmarshal(data, &in) != nil || in.Verifier != "verifier:7047" || len(in.Token) != 64 || len(in.Payload) == 0 {
		fmt.Fprintln(os.Stderr, "bad prover input")
		os.Exit(1)
	}
	switch mode {
	case "ok":
		fmt.Println(`{"status":"proof_sent","codex_ms":1,"sent_bytes":1,"received_bytes":1}`)
	case "fail":
		fmt.Fprintln(os.Stderr, "Codex returned \"error\"")
		os.Exit(1)
	case "garbage":
		fmt.Println("not json")
	}
	os.Exit(0)
}

func TestProverRun(t *testing.T) {
	c := config.Config{Executor: config.ExecutorCodexTLSN, Verifier: "verifier:7047", Prover: os.Args[0], Model: "model-a", Profile: "standard", MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 5 * time.Second}
	payload := func(model, prompt string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"type":"response.create","model":%q,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":%q}]}]}`, model, prompt))
	}
	lease := func() coordinator.Lease {
		return coordinator.Lease{Version: coordinator.Version, JobID: "job", SignedJobID: "job", Profile: c.Profile, ModelID: c.Model, Prompt: "hello", MaxInputTokens: 100, MaxOutputTokens: 20, InputSHA256: SHA("hello"), Attempt: "1", Fence: "f", LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute), CodexPayload: payload("model-a", "hello"), VerifierToken: strings.Repeat("ab", 32)}
	}
	cases := []struct {
		name, mode string
		edit       func(*coordinator.Lease)
		code       string
	}{
		{"proof sent", "ok", func(*coordinator.Lease) {}, ""},
		{"prover failure", "fail", func(*coordinator.Lease) {}, "prover_error"},
		{"unexpected output", "garbage", func(*coordinator.Lease) {}, "prover_error"},
		{"payload for another model", "ok", func(l *coordinator.Lease) { l.CodexPayload = payload("model-b", "hello") }, "invalid_lease"},
		{"payload with another prompt", "ok", func(l *coordinator.Lease) { l.CodexPayload = payload("model-a", "spend more") }, "invalid_lease"},
		{"missing payload", "ok", func(l *coordinator.Lease) { l.CodexPayload = nil }, "invalid_lease"},
		{"bad token", "ok", func(l *coordinator.Lease) { l.VerifierToken = "short" }, "invalid_lease"},
		{"expired", "ok", func(l *coordinator.Lease) { l.LeaseDeadline = time.Now().Add(-time.Second) }, "expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SCARLETT_FAKE_PROVER", tc.mode)
			l := lease()
			tc.edit(&l)
			code, detail := Prover{Config: c}.Run(context.Background(), l)
			if code != tc.code {
				t.Fatalf("code %q want %q (%s)", code, tc.code, detail)
			}
		})
	}
}
