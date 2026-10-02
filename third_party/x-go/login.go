package x

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

// Credential login for X (#268).
//
// X gates the web login behind the new jfapi onboarding flow, but the classic
// api.x.com/1.1/onboarding/task.json subtask state machine still authenticates
// API clients and is what we drive here. The flow:
//
//  1. Mint a guest token (guest/activate.json) using the public web bearer.
//  2. POST onboarding/task.json?flow_name=login to start the flow.
//  3. Walk the returned subtasks, responding to each:
//     - LoginJsInstrumentationSubtask -> solve the ui_metrics POW (uimetrics.go)
//     - LoginEnterUserIdentifierSSO   -> submit username
//     - LoginEnterPassword            -> submit password
//     - LoginTwoFactorAuthChallenge   -> submit a TOTP/one-time code
//     - AccountDuplicationCheck       -> acknowledge
//     - LoginSuccessSubtask           -> terminal; auth_token + ct0 are set
//  4. Read auth_token, ct0, twid from the cookie jar.
//
// The minted cookies feed straight into New(Cookies{...}).

const (
	apiBase      = "https://api.x.com"
	guestActURL  = apiBase + "/1.1/guest/activate.json"
	onboardURL   = apiBase + "/1.1/onboarding/task.json"
	loginFlowURL = onboardURL + "?flow_name=login"
)

// LoginParams holds X credentials. TOTPSecret (preferred) or OTP is only needed
// when the account has two-factor auth enabled.
type LoginParams struct {
	Username string
	Password string
	// TOTPSecret is the base32 authenticator seed; when set, Login generates a
	// fresh 2FA code on demand (enables unattended re-login). Preferred over OTP.
	TOTPSecret string
	// OTP is a single 2FA/backup code, used when no TOTPSecret is available.
	OTP string
	// UserAgent overrides the browser UA used for the login + minted client.
	UserAgent string
	// ProxyURL routes the login through an HTTP/S proxy (residential egress).
	ProxyURL string
	// SidecarURL, when set, delegates the login to the headless-browser
	// social-login sidecar (Playwright drives x.com/i/flow/login). X's
	// onboarding edge fingerprints browser-only behavioral signals (HTTP/2
	// frame order, ui_metrics execution, Arkose) that a pure-Go client can't
	// reproduce — it 399s the credential step ("Could not log you in now")
	// even with correct payloads + Chrome JA3. A real browser emits those
	// signals natively, so the sidecar is the reliable path; the pure-Go flow
	// below stays as a fallback. Mirrors instagram-go / tiktok-go.
	SidecarURL string
}

// LoginResult is the minted session, ready for New.
type LoginResult struct {
	Cookies   Cookies
	UserAgent string
}

// Login authenticates with a username + password and returns minted session
// cookies (auth_token, ct0, twid). It does not require pre-existing cookies.
func Login(ctx context.Context, p LoginParams) (*LoginResult, error) {
	if strings.TrimSpace(p.Username) == "" || p.Password == "" {
		return nil, fmt.Errorf("x: username and password are required")
	}
	ua := p.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}

	// Preferred path: drive the real web login through the headless-browser
	// social-login sidecar (beats X's behavioral anti-bot, which 399s the
	// pure-Go onboarding flow at the credential step).
	if strings.TrimSpace(p.SidecarURL) != "" {
		return loginViaSidecar(ctx, p)
	}

	jar, _ := cookiejar.New(nil)
	// X's onboarding edge fingerprints the TLS ClientHello (JA3) + HTTP stack
	// and 399s ("Could not log you in now") plain-Go clients at the credential
	// step, even when the subtask payloads are correct. Present Chrome's
	// ClientHello via the shared impersonate transport — the same posture
	// reddit-go's login uses to clear its JA3 block.
	// Pure-Go fallback transport. The sidecar path above is the reliable one
	// for X; this onboarding flow is kept for completeness and is 399'd by X's
	// behavioral anti-bot at the credential step (no browser signals). No JA3
	// impersonation here on purpose: it doesn't clear the block and would add a
	// private dependency that the module's CI can't resolve.
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	if p.ProxyURL != "" {
		if parsed, err := url.Parse(p.ProxyURL); err == nil {
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.Proxy = http.ProxyURL(parsed)
			hc.Transport = tr
		}
	}

	fl := &loginFlow{hc: hc, ua: ua, params: p, debug: strings.TrimSpace(os.Getenv("X_LOGIN_DEBUG")) != ""}

	guest, err := fl.guestToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("x: guest token: %w", err)
	}
	fl.guest = guest

	// Bootstrap the X-Client-Transaction-Id generator (same machinery the
	// authenticated client uses); the onboarding edge validates this header to
	// reject automation. Best-effort: an init failure just omits the header.
	txc := &Client{httpClient: hc, userAgent: ua}
	if terr := txc.initTransaction(ctx); terr == nil {
		fl.txc = txc
	} else {
		fl.logf("transaction init failed (omitting x-client-transaction-id): %v", terr)
	}

	// Start the login flow.
	flowToken, subtasks, err := fl.task(ctx, loginFlowURL, loginInitBody())
	if err != nil {
		return nil, fmt.Errorf("x: start login flow: %w", err)
	}

	// Walk the subtask state machine until login succeeds or we run dry.
	for i := 0; i < 12; i++ {
		if len(subtasks) == 0 {
			break
		}
		input, done, serr := fl.respond(ctx, subtasks)
		if serr != nil {
			return nil, serr
		}
		if done {
			break
		}
		// Pace between subtasks: the real web client has human-scale gaps
		// between onboarding steps, and a burst of rapid task.json POSTs is
		// itself an automation signal that can trigger extra challenges.
		fl.pace(ctx)
		flowToken, subtasks, err = fl.task(ctx, onboardURL, taskBody(flowToken, input))
		if err != nil {
			return nil, fmt.Errorf("x: subtask step: %w", err)
		}
	}

	cookies := collectXCookies(jar)
	if cookies.AuthToken == "" || cookies.CT0 == "" {
		return nil, fmt.Errorf("%w: login did not establish a session (auth_token/ct0 missing)", ErrUnauthorized)
	}
	return &LoginResult{Cookies: cookies, UserAgent: ua}, nil
}

// --- social-login sidecar path -------------------------------------------

type sidecarLoginRequest struct {
	Platform   string `json:"platform"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	TOTPSecret string `json:"totpSecret,omitempty"`
	ProxyURL   string `json:"proxyUrl,omitempty"`
}

type sidecarLoginResponse struct {
	OK       bool              `json:"ok"`
	FinalURL string            `json:"finalUrl"`
	Cookies  map[string]string `json:"cookies"`
	Hints    []string          `json:"hints"`
	Error    string            `json:"error"`
}

// loginViaSidecar delegates the login to the headless-browser social-login
// sidecar and maps the returned session cookies onto a LoginResult.
func loginViaSidecar(ctx context.Context, p LoginParams) (*LoginResult, error) {
	endpoint := strings.TrimRight(p.SidecarURL, "/") + "/login"
	payload, err := json.Marshal(sidecarLoginRequest{
		Platform:   "x",
		Username:   p.Username,
		Password:   p.Password,
		TOTPSecret: firstNonEmptyLogin(p.TOTPSecret, p.OTP),
		ProxyURL:   p.ProxyURL,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	hc := &http.Client{Timeout: 180 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("x: social-login sidecar: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out sidecarLoginResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("x: social-login sidecar: bad response (status %d): %s", resp.StatusCode, truncateLogin(string(raw), 200))
	}
	if !out.OK {
		detail := out.Error
		if detail == "" && len(out.Hints) > 0 {
			detail = strings.Join(out.Hints, "; ")
		}
		if detail == "" {
			detail = "login failed"
		}
		return nil, fmt.Errorf("%w: %s", ErrUnauthorized, detail)
	}
	cookies := Cookies{
		AuthToken: out.Cookies["auth_token"],
		CT0:       out.Cookies["ct0"],
		Twid:      out.Cookies["twid"],
		KDT:       out.Cookies["kdt"],
	}
	if cookies.AuthToken == "" || cookies.CT0 == "" {
		return nil, fmt.Errorf("%w: sidecar returned no session (auth_token/ct0 missing)", ErrUnauthorized)
	}
	return &LoginResult{Cookies: cookies, UserAgent: p.UserAgent}, nil
}

func firstNonEmptyLogin(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

type loginFlow struct {
	hc     *http.Client
	ua     string
	guest  string
	att    string
	txc    *Client
	params LoginParams
	debug  bool
}

func (f *loginFlow) logf(format string, args ...interface{}) {
	if f.debug {
		fmt.Fprintf(os.Stderr, "[x-login-debug] "+format+"\n", args...)
	}
}

// pace sleeps a short, jittered interval between onboarding steps so the flow
// has human-scale gaps rather than a rapid POST burst. Honors ctx cancellation.
func (f *loginFlow) pace(ctx context.Context) {
	d := 700*time.Millisecond + time.Duration(rand.Intn(1100))*time.Millisecond
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// guestToken mints a guest token via the public web bearer.
func (f *loginFlow) guestToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, guestActURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("User-Agent", f.ua)
	resp, err := f.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("guest activate status %d: %s", resp.StatusCode, truncateLogin(string(body), 200))
	}
	var out struct {
		GuestToken string `json:"guest_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.GuestToken == "" {
		return "", fmt.Errorf("empty guest token")
	}
	return out.GuestToken, nil
}

// task posts an onboarding task step and returns the next flow_token + subtasks.
func (f *loginFlow) task(ctx context.Context, target string, body []byte) (string, []subtask, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", f.ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("X-Guest-Token", f.guest)
	req.Header.Set("X-Twitter-Active-User", "yes")
	req.Header.Set("X-Twitter-Client-Language", "en")
	// Browser-fidelity headers: the onboarding edge 399s requests that don't
	// look like the web client's XHR. The real client always sends Origin +
	// Referer of x.com and the Sec-Fetch-* triple on these task.json POSTs.
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Referer", baseURL+"/")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	// ct0 cookie doubles as the CSRF header once set.
	if u, _ := url.Parse(apiBase); u != nil {
		for _, ck := range f.hc.Jar.Cookies(u) {
			if ck.Name == "ct0" {
				req.Header.Set("X-Csrf-Token", ck.Value)
			}
		}
	}
	// X issues an `att` token (cookie + header) on the first onboarding
	// response that must be echoed on every subsequent step, or the flow 399s.
	if f.att != "" {
		req.Header.Set("att", f.att)
	}
	// X-Client-Transaction-Id: the onboarding edge validates this to reject
	// non-browser clients (the main 399 cause for the classic flow).
	tidSet := false
	if f.txc != nil {
		if u, err := url.Parse(target); err == nil {
			if tid := f.txc.generateTransactionID(http.MethodPost, u.Path); tid != "" {
				req.Header.Set("X-Client-Transaction-Id", tid)
				tidSet = true
			}
		}
	}
	f.logf("POST %s att=%v ct0=%v tid=%v", target, f.att != "", req.Header.Get("X-Csrf-Token") != "", tidSet)

	resp, err := f.hc.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	// X issues the att anti-automation token on the first onboarding response
	// and expects it echoed on every subsequent step. On api.x.com it arrives
	// as a Set-Cookie (not a response header); the browser echoes it back as
	// the `att` request header. Capture it from either place.
	if a := resp.Header.Get("att"); a != "" {
		f.att = a
	} else {
		for _, ck := range resp.Cookies() {
			if ck.Name == "att" && ck.Value != "" {
				f.att = ck.Value
			}
		}
	}
	if f.debug {
		setCookies := make([]string, 0)
		for _, ck := range resp.Cookies() {
			setCookies = append(setCookies, ck.Name)
		}
		f.logf("  <- status=%d att_hdr=%v set-cookie=%v", resp.StatusCode, resp.Header.Get("att") != "", setCookies)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("task status %d: %s", resp.StatusCode, truncateLogin(string(raw), 300))
	}
	var out struct {
		FlowToken string    `json:"flow_token"`
		Subtasks  []subtask `json:"subtasks"`
		Errors    []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", nil, fmt.Errorf("decode task: %w", err)
	}
	if len(out.Errors) > 0 {
		return "", nil, fmt.Errorf("x: %s", out.Errors[0].Message)
	}
	ids := make([]string, 0, len(out.Subtasks))
	for _, s := range out.Subtasks {
		ids = append(ids, s.SubtaskID)
	}
	f.logf("flow_token=%s subtasks=%v", truncateLogin(out.FlowToken, 12), ids)
	return out.FlowToken, out.Subtasks, nil
}

type subtask struct {
	SubtaskID         string `json:"subtask_id"`
	JSInstrumentation *struct {
		URL string `json:"url"`
	} `json:"js_instrumentation,omitempty"`
}

// respond builds the subtask_input for the first actionable subtask and reports
// whether the flow has reached a terminal (success) state.
func (f *loginFlow) respond(ctx context.Context, subtasks []subtask) (json.RawMessage, bool, error) {
	for _, s := range subtasks {
		switch s.SubtaskID {
		case "LoginJsInstrumentationSubtask":
			resp := "{}"
			hasURL := s.JSInstrumentation != nil && s.JSInstrumentation.URL != ""
			if hasURL {
				if solved, err := f.solveInstrumentation(ctx, s.JSInstrumentation.URL); err == nil {
					resp = solved
				} else {
					f.logf("ui_metrics solve failed, sending empty: %v", err)
				}
			}
			f.logf("js_instrumentation hasURL=%v responseLen=%d", hasURL, len(resp))
			return mustJSON(map[string]any{
				"subtask_id":         s.SubtaskID,
				"js_instrumentation": map[string]any{"response": resp, "link": "next_link"},
			}), false, nil
		case "LoginEnterUserIdentifierSSO":
			return mustJSON(map[string]any{
				"subtask_id": s.SubtaskID,
				"settings_list": map[string]any{
					"setting_responses": []any{map[string]any{
						"key":           "user_identifier",
						"response_data": map[string]any{"text_data": map[string]any{"result": f.params.Username}},
					}},
					"link": "next_link",
				},
			}), false, nil
		case "LoginEnterPassword":
			return mustJSON(map[string]any{
				"subtask_id":     s.SubtaskID,
				"enter_password": map[string]any{"password": f.params.Password, "link": "next_link"},
			}), false, nil
		case "LoginEnterAlternateIdentifierSubtask":
			return mustJSON(map[string]any{
				"subtask_id": s.SubtaskID,
				"enter_text": map[string]any{"text": f.params.Username, "link": "next_link"},
			}), false, nil
		case "LoginTwoFactorAuthChallenge":
			code, err := f.twoFactorCode()
			if err != nil {
				return nil, false, err
			}
			return mustJSON(map[string]any{
				"subtask_id": s.SubtaskID,
				"enter_text": map[string]any{"text": code, "link": "next_link"},
			}), false, nil
		case "LoginAcid":
			// Email/phone verification challenge — needs a code we don't have.
			return nil, false, fmt.Errorf("%w: account verification (LoginAcid) required; supply OTP", ErrUnauthorized)
		case "AccountDuplicationCheck":
			return mustJSON(map[string]any{
				"subtask_id":              s.SubtaskID,
				"check_logged_in_account": map[string]any{"link": "AccountDuplicationCheck_false"},
			}), false, nil
		case "LoginSuccessSubtask", "AccountState":
			return nil, true, nil
		case "DenyLoginSubtask":
			return nil, false, fmt.Errorf("%w: login denied by X", ErrUnauthorized)
		}
	}
	// No actionable subtask recognized; treat as terminal so we can check cookies.
	return nil, true, nil
}

func (f *loginFlow) twoFactorCode() (string, error) {
	if otp := strings.TrimSpace(f.params.OTP); otp != "" {
		return otp, nil
	}
	if secret := strings.TrimSpace(f.params.TOTPSecret); secret != "" {
		return totpNow(secret)
	}
	return "", fmt.Errorf("%w: two-factor required; set LoginParams.TOTPSecret or OTP", ErrUnauthorized)
}

// solveInstrumentation fetches the js_instrumentation script and solves the
// ui_metrics POW (uimetrics.go).
func (f *loginFlow) solveInstrumentation(ctx context.Context, scriptURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", f.ua)
	resp, err := f.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return SolveUIMetrics(string(body))
}

func collectXCookies(jar http.CookieJar) Cookies {
	out := Cookies{}
	for _, host := range []string{"https://x.com", "https://twitter.com", apiBase} {
		u, err := url.Parse(host)
		if err != nil {
			continue
		}
		for _, ck := range jar.Cookies(u) {
			switch ck.Name {
			case "auth_token":
				if ck.Value != "" {
					out.AuthToken = ck.Value
				}
			case "ct0":
				if ck.Value != "" {
					out.CT0 = ck.Value
				}
			case "twid":
				if ck.Value != "" {
					out.Twid = ck.Value
				}
			case "kdt":
				if ck.Value != "" {
					out.KDT = ck.Value
				}
			}
		}
	}
	return out
}

func loginInitBody() []byte {
	return mustJSON(map[string]any{
		"input_flow_data": map[string]any{
			"flow_context": map[string]any{
				"debug_overrides": map[string]any{},
				"start_location":  map[string]any{"location": "splash_screen"},
			},
		},
		"subtask_versions": map[string]any{
			"action_list":                          2,
			"alert_dialog":                         1,
			"app_download_cta":                     1,
			"check_logged_in_account":              1,
			"choice_selection":                     3,
			"contacts_live_sync_permission_prompt": 0,
			"cta":                                  7,
			"email_verification":                   2,
			"end_flow":                             1,
			"enter_date":                           1,
			"enter_email":                          2,
			"enter_password":                       5,
			"enter_phone":                          2,
			"enter_recaptcha":                      1,
			"enter_text":                           5,
			"enter_username":                       2,
			"generic_urt":                          3,
			"in_app_notification":                  1,
			"interest_picker":                      3,
			"js_instrumentation":                   1,
			"menu_dialog":                          1,
			"notifications_permission_prompt":      2,
			"open_account":                         2,
			"open_home_timeline":                   1,
			"open_link":                            1,
			"phone_verification":                   4,
			"privacy_options":                      1,
			"security_key":                         3,
			"select_avatar":                        4,
			"select_banner":                        2,
			"settings_list":                        7,
			"show_code":                            1,
			"sign_up":                              2,
			"sign_up_review":                       4,
			"tweet_selection_urt":                  1,
			"update_users":                         1,
			"upload_media":                         1,
			"user_recommendations_list":            4,
			"user_recommendations_urt":             1,
			"wait_spinner":                         3,
			"web_modal":                            1,
		},
	})
}

func taskBody(flowToken string, input json.RawMessage) []byte {
	return mustJSON(map[string]any{
		"flow_token":     flowToken,
		"subtask_inputs": []json.RawMessage{input},
	})
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func truncateLogin(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
