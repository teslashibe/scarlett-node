package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// Local clock skew and acceptance overhead must not consume the token lifetime
// reserved for an unchanged offer. This is a validity guard, not entitlement or
// signature verification; the provider and verifier still authenticate the job.
const codexAdmissionClockMargin = 30 * time.Second

// codexLocalAuthExpired is a node-local result, never reported to the
// coordinator: the selected credential failed the admission guard before
// acceptance. finishAccount records it as local expiry that renewal may repair.
const codexLocalAuthExpired = "local_auth_expired"

func codexAdmissionValid(home string, deadline time.Time) bool {
	if !filepath.IsAbs(home) || deadline.IsZero() {
		return false
	}
	f, err := localfs.OpenPrivate(filepath.Join(home, "auth.json"))
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) == 0 || len(data) > 65536 {
		return false
	}
	expires, ok := codexAuthExpiry(data)
	return ok && expires.After(deadline.Add(codexAdmissionClockMargin))
}

func codexAdmissionWindow(now time.Time) time.Time {
	return now.Add(coordinator.MaxOfferLifetime)
}

// Official CLI 0.159.2 token_data.rs defines managed access_token as a JWT and
// parses its standard exp claim. Older CLI auth files need no expires_at field.
// A gateway-persisted expires_at can shorten the guard, never extend JWT expiry.
// Opaque credentials or missing/ambiguous expiry cannot establish paid admission.
func codexAuthExpiry(data []byte) (time.Time, bool) {
	file, ok := uniqueAuthObject(data)
	if !ok {
		return time.Time{}, false
	}
	tokens, ok := uniqueAuthObject(file["tokens"])
	if !ok {
		return time.Time{}, false
	}
	var access, account string
	if json.Unmarshal(tokens["access_token"], &access) != nil || json.Unmarshal(tokens["account_id"], &account) != nil || strings.TrimSpace(account) == "" {
		return time.Time{}, false
	}
	parts := strings.Split(access, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	claims, ok := uniqueAuthObject(payload)
	if !ok {
		return time.Time{}, false
	}
	var exp int64
	if json.Unmarshal(claims["exp"], &exp) != nil || exp <= 0 {
		return time.Time{}, false
	}
	if raw, present := tokens["expires_at"]; present {
		var persisted int64
		if json.Unmarshal(raw, &persisted) != nil || persisted <= 0 {
			return time.Time{}, false
		}
		if persisted < exp {
			exp = persisted
		}
	}
	expires := time.Unix(exp, 0)
	return expires, expires.Year() <= 9999
}

// Auth and JWT claims must not choose between duplicate security fields.
func uniqueAuthObject(data []byte) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, exists := fields[key]; exists {
			return nil, false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, false
		}
		fields[key] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return nil, false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, false
	}
	return fields, true
}
