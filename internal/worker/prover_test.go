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
	if marker := os.Getenv("SCARLETT_FAKE_PROVER_MARKER"); marker != "" {
		if err := os.WriteFile(marker, []byte("synthetic helper invoked"), 0600); err != nil {
			os.Exit(1)
		}
	}
	if strings.HasPrefix(mode, "x") {
		fakeXProver(mode)
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
	case "traffic":
		fmt.Println(`{"status":"proof_sent","verifier_sent_bytes":0,"verifier_received_bytes":23,"verifier_transport_layer":"tcp_payload"}`)
	case "auth":
		fmt.Fprintln(os.Stderr, "Error: Codex provider error: unauthenticated")
		os.Exit(1)
	case "authdiag":
		fmt.Fprintln(os.Stderr, `SCARLETT_DIAGNOSTICS={"version":1,"duration_ms":4,"outcome":"error","spans":[{"phase":"proof_finalize","start_ms":0,"duration_ms":4,"outcome":"error"}]}`)
		fmt.Fprintln(os.Stderr, "Error: Codex provider error: unauthenticated")
		os.Exit(1)
	case "quota":
		fmt.Fprintln(os.Stderr, "Error: Codex provider error: rate_limited")
		os.Exit(1)
	case "raw-quota":
		fmt.Fprintln(os.Stderr, "Error: Codex provider error: rate_limited SECRET_PRIVATE_ERROR")
		os.Exit(1)
	case "fail":
		fmt.Fprintln(os.Stderr, "Codex returned \"error\"")
		os.Exit(1)
	case "garbage":
		fmt.Println("not json")
	}
	os.Exit(0)
}

func TestProverRun(t *testing.T) {
	c := config.Config{Executor: config.ExecutorCodexTLSN, Verifier: "verifier:7047", Prover: os.Args[0], Profile: "standard", MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 5 * time.Second}
	payload := func(model, prompt string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"type":"response.create","model":%q,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":%q}]}]}`, model, prompt))
	}
	lease := func() coordinator.Lease {
		return coordinator.Lease{Version: coordinator.Version, JobID: "job", SignedJobID: "job", Profile: c.Profile, ModelID: "gpt-5.6-luna", Prompt: "hello", MaxInputTokens: 100, MaxOutputTokens: 20, InputSHA256: SHA("hello"), Attempt: "1", Fence: "f", LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute), CodexPayload: payload("gpt-5.6-luna", "hello"), VerifierToken: strings.Repeat("ab", 32)}
	}
	cases := []struct {
		name, mode string
		edit       func(*coordinator.Lease)
		code       string
	}{
		{"proof sent", "ok", func(*coordinator.Lease) {}, ""},
		{"prover failure", "fail", func(*coordinator.Lease) {}, "prover_error"},
		{"safe authentication failure", "auth", func(*coordinator.Lease) {}, "auth_required"},
		{"authentication failure with optional diagnostics", "authdiag", func(*coordinator.Lease) {}, "auth_required"},
		{"safe rate-limit failure", "quota", func(*coordinator.Lease) {}, "capacity_unavailable"},
		{"unrecognized error cannot claim quota", "raw-quota", func(*coordinator.Lease) {}, "prover_error"},
		{"unexpected output", "garbage", func(*coordinator.Lease) {}, "prover_error"},
		{"payload for another model", "ok", func(l *coordinator.Lease) { l.CodexPayload = payload("gpt-5.6-terra", "hello") }, "invalid_lease"},
		{"payload with another prompt", "ok", func(l *coordinator.Lease) { l.CodexPayload = payload("gpt-5.6-luna", "spend more") }, "invalid_lease"},
		{"effort variant", "ok", func(l *coordinator.Lease) {
			l.ModelID = "model-a-high"
			l.CodexPayload = payload("model-a-high", "hello")
		}, "invalid_lease"},
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

func TestTypedCodexPayloadRejectsToolsOverridesAndAmbiguousJSON(t *testing.T) {
	l := coordinator.Lease{ServiceType: "codex", ModelID: "gpt-5.6-luna", Prompt: "synthetic"}
	good := map[string]any{"type": "response.create", "model": l.ModelID, "instructions": "You are a helpful assistant.", "input": []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": l.Prompt}}}}, "stream": true, "store": false, "reasoning": map[string]any{"effort": "low"}, "text": map[string]any{"verbosity": "low"}}
	l.CodexPayload, _ = json.Marshal(good)
	if !validPayload(l) {
		t.Fatal("canonical payload rejected")
	}
	for name, edit := range map[string]func(map[string]any){"tools": func(p map[string]any) { p["tools"] = []any{map[string]any{"type": "web_search"}} }, "instructions": func(p map[string]any) { p["instructions"] = "other work" }, "tier": func(p map[string]any) { p["service_tier"] = "priority" }, "retention": func(p map[string]any) { p["store"] = true }, "role": func(p map[string]any) { p["input"].([]any)[0].(map[string]any)["role"] = "system" }, "effort": func(p map[string]any) { p["reasoning"] = map[string]any{"effort": "high"} }} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(good)
			var p map[string]any
			json.Unmarshal(raw, &p)
			edit(p)
			l.CodexPayload, _ = json.Marshal(p)
			if validPayload(l) {
				t.Fatal("unsafe typed payload accepted")
			}
		})
	}
	l.CodexPayload = json.RawMessage(`{"type":"response.create","type":"response.create"}`)
	if validPayload(l) {
		t.Fatal("ambiguous payload accepted")
	}
}

func TestCurrentCodexBaseLeasesBindExactPayloadBeforeProof(t *testing.T) {
	c := config.Config{Executor: config.ExecutorCodexTLSN, Verifier: "verifier:7047", Prover: os.Args[0], Profile: "standard", MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 5 * time.Second}
	t.Setenv("SCARLETT_FAKE_PROVER", "ok")
	for _, model := range config.AvailableModelsAt(time.Now()) {
		t.Run(model, func(t *testing.T) {
			l := coordinator.Lease{Version: coordinator.Version, ServiceType: "codex", JobID: "synthetic-job", SignedJobID: "synthetic-job", Profile: c.Profile, ModelID: model, Prompt: "synthetic", MaxInputTokens: 100, MaxOutputTokens: 20, InputSHA256: SHA("synthetic"), Attempt: "1", Fence: "synthetic-fence", LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute), VerifierToken: strings.Repeat("ab", 32)}
			payload := map[string]any{"type": "response.create", "model": model, "instructions": "You are a helpful assistant.", "input": []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": l.Prompt}}}}, "stream": true, "store": false, "reasoning": map[string]any{"effort": "low"}, "text": map[string]any{"verbosity": "low"}}
			l.CodexPayload, _ = json.Marshal(payload)
			if code, detail := (Prover{Config: c}).Run(context.Background(), l); code != "" {
				t.Fatalf("reviewed base rejected: %s %s", code, detail)
			}
			payload["model"] = "gpt-6-astra"
			if model == "gpt-6-astra" {
				payload["model"] = "gpt-6-sol"
			}
			l.CodexPayload, _ = json.Marshal(payload)
			if code, _ := (Prover{Config: c}).Run(context.Background(), l); code != "invalid_lease" {
				t.Fatal("another reviewed model escaped the lease binding")
			}
			payload["model"] = model
			payload["reasoning"] = map[string]any{"effort": "ultra"}
			l.CodexPayload, _ = json.Marshal(payload)
			if code, _ := (Prover{Config: c}).Run(context.Background(), l); code != "invalid_lease" {
				t.Fatal("inventory effort metadata enabled unbound execution")
			}
		})
	}
}
