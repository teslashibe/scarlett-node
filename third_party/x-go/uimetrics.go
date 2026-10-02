package x

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ui_metrics proof-of-work solver for the LoginJsInstrumentationSubtask.
//
// X's onboarding/login flow serves a JS instrumentation challenge whose
// js_instrumentation.url returns a script that defines a handful of 64-hex
// variables, applies a sequence of bitwise/arithmetic operations to them, and
// returns an object like {"rf":{...},"s":"..."}. The server expects the
// solved object echoed back as the subtask's js_instrumentation.response.
//
// Rather than running a JS engine, we parse the deterministic script and
// evaluate the operations directly. Ported from the regex-POW approach in
// post04/twitter-POW-golang-parser and glizzykingdreko/x-twitter-ui-metrics,
// hardened to return errors instead of panicking (a malformed/!changed script
// must not crash the login flow — it returns an error so the caller can fall
// back to a signer sidecar). No JS engine required.

var (
	reUIInitialNumbers = regexp.MustCompile(`var [A-Za-z0-9]{64}=[0-9]+`)
	reUIMathBasic      = regexp.MustCompile(`[a-z0-9]{64}=(~|\^|\||&|[A-Za-z0-9]{64})`)
	reUIFuncEnding     = regexp.MustCompile(`}\([a-z0-9]{64},[a-z0-9]{64},[a-z0-9]{64}\)`)
)

// SolveUIMetrics parses the X ui_metrics instrumentation script and returns
// the JSON object string to send back as js_instrumentation.response.
//
// It is deterministic and offline. If the script shape has drifted (X ships a
// new variant) it returns an error so the caller can fall back to the signer
// sidecar rather than submitting a wrong answer.
func SolveUIMetrics(script string) (string, error) {
	// The payload lives on the 3rd CRLF-delimited line in the historical
	// layout; fall back to the whole script if that split doesn't apply so a
	// minor formatting change doesn't immediately fail.
	body := script
	if lines := strings.Split(script, "\r\n"); len(lines) > 2 {
		body = lines[2]
	}
	scriptParts := strings.Split(body, ";")

	answers := make(map[string]int, 4)
	var (
		out                  string
		inWeirdFunc          bool
		weirdFuncAnswer      string
		inWeirdMathOperation bool
		weirdMathOpAnswer    string
	)

	for _, part := range scriptParts {
		// Initial integer assignments: `var <64hex>=<int>`.
		if reUIInitialNumbers.MatchString(part) {
			matched := reUIInitialNumbers.FindString(part)
			kv := strings.SplitN(matched, "=", 2)
			if len(kv) != 2 {
				return "", fmt.Errorf("ui_metrics: malformed initial assignment %q", part)
			}
			intValue, err := strconv.Atoi(kv[1])
			if err != nil {
				return "", fmt.Errorf("ui_metrics: bad initial int %q: %w", kv[1], err)
			}
			nameFields := strings.Fields(kv[0])
			if len(nameFields) < 2 {
				return "", fmt.Errorf("ui_metrics: malformed var name %q", kv[0])
			}
			answers[nameFields[1]] = intValue
		}

		// Basic bitwise math (excluding the date variant handled below).
		if reUIMathBasic.MatchString(part) && !strings.Contains(part, "new Date") {
			signChange := false
			operationDone := false
			if strings.Contains(part, "~") {
				rhs := strings.SplitN(part, "=", 2)
				if len(rhs) != 2 {
					return "", fmt.Errorf("ui_metrics: malformed ~ op %q", part)
				}
				v := rhs[1]
				if strings.Contains(part, "(") {
					if len(v) < 3 {
						return "", fmt.Errorf("ui_metrics: malformed ~( op %q", part)
					}
					v = v[2 : len(v)-1]
				} else {
					if len(v) < 1 {
						return "", fmt.Errorf("ui_metrics: malformed ~ op %q", part)
					}
					v = v[1:]
				}
				part = rhs[0] + "=" + v
				signChange = true
			}

			parts := strings.SplitN(part, "=", 2)
			if len(parts) != 2 {
				return "", fmt.Errorf("ui_metrics: malformed math op %q", part)
			}
			lhs, rhs := parts[0], parts[1]
			switch {
			case strings.Contains(rhs, "^"):
				m := strings.SplitN(rhs, "^", 2)
				answers[lhs] = answers[m[0]] ^ answers[m[1]]
				operationDone = true
			case strings.Contains(rhs, "|"):
				m := strings.SplitN(rhs, "|", 2)
				answers[lhs] = answers[m[0]] | answers[m[1]]
				operationDone = true
			case strings.Contains(rhs, "&"):
				m := strings.SplitN(rhs, "&", 2)
				answers[lhs] = answers[m[0]] & answers[m[1]]
				operationDone = true
			}
			if signChange {
				if operationDone {
					answers[lhs] = -(answers[lhs] + 1)
				} else {
					answers[lhs] = -(answers[rhs] + 1)
				}
			}
		}

		// Date XOR variant: `<lhs>=<a>^(new Date(<b>*...)).get...`
		if strings.Contains(part, "new Date") {
			parts := strings.SplitN(part, "=", 2)
			if len(parts) != 2 {
				return "", fmt.Errorf("ui_metrics: malformed date op %q", part)
			}
			opParts := strings.SplitN(parts[1], "^", 2)
			if len(opParts) != 2 {
				return "", fmt.Errorf("ui_metrics: malformed date xor %q", part)
			}
			inner := strings.SplitN(opParts[1], "*", 2)
			openParen := strings.SplitN(inner[0], "(", 2)
			if len(openParen) != 2 {
				return "", fmt.Errorf("ui_metrics: malformed date inner %q", part)
			}
			key := openParen[1]
			day := time.UnixMilli(int64(answers[key]) * 10000000000).UTC().Day()
			answers[parts[0]] = answers[opParts[0]] ^ day
		}

		// Start of the div-building accumulator function.
		if strings.Contains(part, "document.createElement('div')") && !inWeirdFunc {
			inWeirdFunc = true
			weirdFuncAnswer = strings.SplitN(part, "=function", 2)[0]
		}
		if reUIFuncEnding.MatchString(part) && inWeirdFunc {
			inWeirdFunc = false
			things := strings.Split(part[2:len(part)-1], ",")
			if len(things) >= 3 {
				answers[weirdFuncAnswer] = uiAccumulate([3]int{answers[things[0]], answers[things[1]], answers[things[2]]})
			}
			weirdFuncAnswer = ""
		}

		// Start of the `function(){return this.…}` math operation.
		if strings.Contains(part, "function(){return this.") && !inWeirdMathOperation {
			inWeirdMathOperation = true
			weirdMathOpAnswer = strings.SplitN(part, "=", 2)[0]
		}
		if reUIFuncEnding.MatchString(part) && inWeirdMathOperation {
			inWeirdMathOperation = false
			things := strings.Split(part[2:len(part)-1], ",")
			if len(things) >= 3 {
				answers[weirdMathOpAnswer] = answers[things[1]] ^ answers[things[0]] | (answers[things[1]] ^ answers[things[2]])
			}
			weirdMathOpAnswer = ""
		}

		// Final output: `return {'rf':{...},'s':'...'}`.
		if strings.HasPrefix(part, "return {'rf") {
			out = strings.ReplaceAll(part, "'", `"`)
			fields := strings.SplitN(out, " ", 2)
			if len(fields) != 2 {
				return "", fmt.Errorf("ui_metrics: malformed return %q", part)
			}
			out = fields[1]
			for name, val := range answers {
				out = strings.ReplaceAll(out, ":"+name, ":"+strconv.Itoa(val))
			}
			break
		}
	}

	if out == "" {
		return "", fmt.Errorf("ui_metrics: no rf output found (script shape drifted)")
	}
	return out, nil
}

// uiAccumulate ports the div-accumulator helper: for each of three inputs,
// walk the low 8 bits adding the running value whenever the LSB is 0, then
// reduce mod 256.
func uiAccumulate(numbers [3]int) int {
	num := 0
	for _, number := range numbers {
		c := uiAbs(number)
		if c > 1 {
			start := number
			i := 0
			for c > 1 && i < 8 {
				i++
				if (start & 1) == 0 {
					num += start
				}
				start >>= 1
				c = uiAbs(start)
			}
		}
	}
	return num % 256
}

func uiAbs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}
