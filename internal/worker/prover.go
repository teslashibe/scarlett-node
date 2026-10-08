package worker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
	"github.com/teslashibe/scarlett-node/internal/process"
)

// Prover runs a Codex job through scarlett-prover, which proves OpenAI's
// response to the locally configured verifier. The node never submits the
// answer itself; the coordinator reads it from the verifier.
type Prover struct {
	Config config.Config
}

// Run returns an empty failure code once the proof was sent, plus a short
// diagnostic for local logs.
func (p Prover) Run(ctx context.Context, l coordinator.Lease) (code, detail string) {
	c := p.Config
	deadline, code := checkLease(c, l)
	if code != "" {
		return code, ""
	}
	// The proof policy does not yet bind reasoning effort or service tier,
	// so only base-model leases are proven.
	if base, _ := config.Serves(l.ModelID); base != l.ModelID || !validPayload(l) || len(l.VerifierToken) != 64 || !isHex(l.VerifierToken) {
		return "invalid_lease", ""
	}
	endEncode := diagnostics.Start(ctx, "request_encode", 1)
	input, err := json.Marshal(struct {
		Verifier         string          `json:"verifier"`
		VerifierCA       string          `json:"verifier_ca_file,omitempty"`
		PlaintextFixture bool            `json:"plaintext_fixture,omitempty"`
		Token            string          `json:"token"`
		Payload          json.RawMessage `json:"payload"`
	}{c.Verifier, c.VerifierCA, c.VerifierPlaintextFixture, l.VerifierToken, l.CodexPayload})
	endEncode(diagnosticOutcome(ctx, err))
	if err != nil {
		return "invalid_lease", ""
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Prover, "prove")
	if c.CodexHome != "" {
		cmd.Env = append(os.Environ(), "CODEX_HOME="+c.CodexHome)
	}
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = 16<<10, 16<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	observe, err := beginProofObservation(ctx)
	if err != nil {
		return "prover_error", "proof traffic journal unavailable"
	}
	helperOK := false
	defer func() { observe(stdout.Bytes(), helperOK) }()
	endHelper := diagnostics.Start(ctx, "helper_wall", 1)
	err = process.Run(cmd)
	endHelper(diagnosticOutcome(ctx, err))
	diagnostic := helperStderr(ctx, 1, stderr.String())
	if err != nil {
		if ctx.Err() != nil {
			return "expired", "prover timed out"
		}
		switch diagnostic {
		case "Error: Codex provider error: unauthenticated":
			return "auth_required", "Codex authentication required"
		case "Error: Codex provider error: rate_limited":
			return "capacity_unavailable", "Codex capacity unavailable"
		}
		return "prover_error", diagnostic
	}
	helperOK = true
	helperDiagnostics(ctx, 1, stdout.Bytes())
	endDecode := diagnostics.Start(ctx, "helper_stdout_decode", 1)
	var summary struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(stdout.Bytes(), &summary) != nil || summary.Status != "proof_sent" {
		endDecode("error")
		return "prover_error", "unexpected prover output"
	}
	endDecode("success")
	return "", fmt.Sprintf("proof sent for job %s", l.JobID)
}

// validPayload accepts only a single-turn Codex request for this lease's
// model and prompt, so a coordinator cannot spend the subscription on
// different work than the lease describes.
func validPayload(l coordinator.Lease) bool {
	if len(l.CodexPayload) == 0 || len(l.CodexPayload) > 65536 {
		return false
	}
	if l.ServiceType == "codex" {
		value, err := uniqueJSON(l.CodexPayload)
		if err != nil {
			return false
		}
		p, ok := value.(map[string]any)
		if !ok || len(p) != 8 || p["instructions"] != "You are a helpful assistant." || p["stream"] != true || p["store"] != false {
			return false
		}
		reasoning, ok := p["reasoning"].(map[string]any)
		if !ok || len(reasoning) != 1 || reasoning["effort"] != "low" {
			return false
		}
		text, ok := p["text"].(map[string]any)
		if !ok || len(text) != 1 || text["verbosity"] != "low" {
			return false
		}
		input, ok := p["input"].([]any)
		if !ok || len(input) != 1 {
			return false
		}
		message, ok := input[0].(map[string]any)
		if !ok || len(message) != 3 || message["type"] != "message" || message["role"] != "user" {
			return false
		}
		content, ok := message["content"].([]any)
		if !ok || len(content) != 1 {
			return false
		}
		item, ok := content[0].(map[string]any)
		if !ok || len(item) != 2 || item["type"] != "input_text" || item["text"] != l.Prompt {
			return false
		}
	}
	var p struct {
		Type  string `json:"type"`
		Model string `json:"model"`
		Input []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"input"`
	}
	if json.Unmarshal(l.CodexPayload, &p) != nil {
		return false
	}
	return p.Type == "response.create" && p.Model == l.ModelID && len(p.Input) == 1 &&
		len(p.Input[0].Content) == 1 && p.Input[0].Content[0].Type == "input_text" && p.Input[0].Content[0].Text == l.Prompt
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// limitedBuffer keeps the first max bytes written to it and records whether
// any were dropped.
type limitedBuffer struct {
	bytes.Buffer
	max     int
	dropped bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	kept := p
	if room := max(b.max-b.Len(), 0); len(p) > room {
		b.dropped = true
		kept = p[:room]
	}
	b.Buffer.Write(kept)
	return len(p), nil
}

// ReadFrom shadows the embedded bytes.Buffer's. io.Copy, and so os/exec for a
// helper's stdout and stderr, prefers ReadFrom and would otherwise bypass the
// limit entirely.
func (b *limitedBuffer) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	chunk := make([]byte, 32<<10)
	for {
		n, err := r.Read(chunk)
		b.Write(chunk[:n])
		total += int64(n)
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
