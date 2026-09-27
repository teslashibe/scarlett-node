package worker

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
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
	input, err := json.Marshal(struct {
		Verifier string          `json:"verifier"`
		Token    string          `json:"token"`
		Payload  json.RawMessage `json:"payload"`
	}{c.Verifier, l.VerifierToken, l.CodexPayload})
	if err != nil {
		return "invalid_lease", ""
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Prover, "prove")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = 4096, 4096
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "expired", "prover timed out"
		}
		return "prover_error", strings.TrimSpace(stderr.String())
	}
	var summary struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(stdout.Bytes(), &summary) != nil || summary.Status != "proof_sent" {
		return "prover_error", "unexpected prover output"
	}
	return "", fmt.Sprintf("proof sent for job %s", l.JobID)
}

// validPayload accepts only a single-turn Codex request for this lease's
// model and prompt, so a coordinator cannot spend the subscription on
// different work than the lease describes.
func validPayload(l coordinator.Lease) bool {
	if len(l.CodexPayload) == 0 || len(l.CodexPayload) > 65536 {
		return false
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

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}
