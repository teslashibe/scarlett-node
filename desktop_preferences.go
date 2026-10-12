package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// Preferences contain only non-secret device settings. Admission still requires
// current authenticated account health and coordinator acceptance.
type desktopPreferences struct {
	Schema       int  `json:"schema"`
	LocalAPIPort int  `json:"local_api_port"`
	Background   bool `json:"background"`
	XConcurrency int  `json:"x_concurrency"`
	// Updates is "notify" (the default: report updates, install on request)
	// or "automatic" (install when accepted jobs finish). ResumeServing starts
	// the node when the app opens; it follows the operator's last Start/Stop.
	Updates       string `json:"updates"`
	ResumeServing bool   `json:"resume_serving"`
	// ServeWeb serves web pages as well. It is on unless the operator turned
	// it off, so a device that never chose serves web after updating.
	ServeWeb bool `json:"serve_web"`
	// WebConcurrency is "Web pages at once": 0 is Auto, the node's adaptive
	// limit (SCARLETT_WEB_CONCURRENCY=auto); 1-16 is a fixed number of pages.
	// It applies when the node next starts.
	WebConcurrency int `json:"web_concurrency"`
}

// desktopWebConcurrencyMax bounds the desktop setting below the node's own
// limit of 32 until the coordinator shares the verifier's web sessions out
// between nodes.
const desktopWebConcurrencyMax = 16

func validDesktopWebConcurrency(n int) bool {
	return n >= 0 && n <= desktopWebConcurrencyMax
}

func (p desktopPreferences) valid() bool {
	return p.Schema == 1 && p.LocalAPIPort >= 1024 && p.LocalAPIPort <= 65535 && p.XConcurrency >= 1 && p.XConcurrency <= 8 && (p.Updates == "notify" || p.Updates == "automatic") && validDesktopWebConcurrency(p.WebConcurrency)
}

func desktopPreferencesCommand(action, path string, input io.Reader, out io.Writer) error {
	fail := errors.New("desktop preferences unavailable")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "preferences.json" || localfs.CheckDir(filepath.Dir(path)) != nil {
		return fail
	}
	lock, err := localfs.LockPrivate(path + ".lock")
	if err != nil {
		return fail
	}
	defer lock.Close()
	p := desktopPreferences{Schema: 1, LocalAPIPort: 8088, XConcurrency: 2, Updates: "notify", ServeWeb: true}
	throughputPath := filepath.Join(filepath.Dir(path), "throughput-preferences-v1.json")
	throughput, err := readDesktopThroughputPreferences(throughputPath)
	if err != nil {
		return fail
	}
	lifecyclePath := filepath.Join(filepath.Dir(path), "lifecycle-preferences-v1.json")
	lifecycle, err := readDesktopLifecyclePreferences(lifecyclePath)
	if err != nil {
		return fail
	}
	webPath := filepath.Join(filepath.Dir(path), "web-preferences-v1.json")
	serveWeb, err := readDesktopWebPreference(webPath)
	if err != nil {
		return fail
	}
	webCapacityPath := filepath.Join(filepath.Dir(path), "web-capacity-preferences-v1.json")
	webConcurrency, err := readDesktopWebConcurrency(webCapacityPath)
	if err != nil {
		return fail
	}
	p.XConcurrency = throughput.XConcurrency
	p.Updates, p.ResumeServing = lifecycle.Updates, lifecycle.ResumeServing
	p.ServeWeb, p.WebConcurrency = serveWeb, webConcurrency
	switch action {
	case "preferences-get":
		f, err := localfs.OpenPrivate(path)
		if err == nil {
			defer f.Close()
			if !decodeDesktopPreferences(f, &p) {
				return fail
			}
			p.XConcurrency = throughput.XConcurrency
			p.Updates, p.ResumeServing = lifecycle.Updates, lifecycle.ResumeServing
			p.ServeWeb, p.WebConcurrency = serveWeb, webConcurrency
		} else if !os.IsNotExist(err) {
			return fail
		}
	case "preferences-set":
		if input == nil || !decodeDesktopPreferences(input, &p) {
			return fail
		}
		// Keep the original representation readable by desktop 0.1.3 on rollback.
		// New capacity settings have their own private, versioned extension file.
		raw, err := json.Marshal(struct {
			Schema       int  `json:"schema"`
			LocalAPIPort int  `json:"local_api_port"`
			Background   bool `json:"background"`
		}{p.Schema, p.LocalAPIPort, p.Background})
		extension, extensionErr := json.Marshal(desktopThroughputPreferences{Schema: 1, XConcurrency: p.XConcurrency})
		lifecycleRaw, lifecycleErr := json.Marshal(desktopLifecyclePreferences{Schema: 1, Updates: p.Updates, ResumeServing: p.ResumeServing})
		webRaw, webErr := json.Marshal(desktopWebPreferences{Schema: 1, ServeWeb: &p.ServeWeb})
		webCapacityRaw, webCapacityErr := json.Marshal(desktopWebCapacityPreferences{Schema: 1, WebConcurrency: &p.WebConcurrency})
		if err != nil || extensionErr != nil || lifecycleErr != nil || webErr != nil || webCapacityErr != nil || localfs.WriteAtomic(throughputPath, extension, true) != nil ||
			localfs.WriteAtomic(lifecyclePath, lifecycleRaw, true) != nil || localfs.WriteAtomic(webPath, webRaw, true) != nil ||
			localfs.WriteAtomic(webCapacityPath, webCapacityRaw, true) != nil || localfs.WriteAtomic(path, raw, true) != nil {
			return fail
		}
	default:
		return fail
	}
	return json.NewEncoder(out).Encode(p)
}

func decodeDesktopPreferences(input io.Reader, p *desktopPreferences) bool {
	raw, err := io.ReadAll(io.LimitReader(input, 1025))
	if err != nil || len(raw) > 1024 {
		return false
	}
	// Existing schema-1 files have no X concurrency, lifecycle or web settings.
	// Normalize the defaults on reads without writing or changing any account.
	// Web pages at once defaults to Auto (zero).
	*p = desktopPreferences{XConcurrency: 2, Updates: "notify", ServeWeb: true}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(p) == nil && p.valid() && d.Decode(&struct{}{}) == io.EOF
}

// A separate extension lets an older installer read its device preferences.
// The existing preference lock serializes both private files.
type desktopThroughputPreferences struct {
	Schema       int `json:"schema"`
	XConcurrency int `json:"x_concurrency"`
}

func readDesktopThroughputPreferences(path string) (desktopThroughputPreferences, error) {
	p := desktopThroughputPreferences{Schema: 1, XConcurrency: 2}
	f, err := localfs.OpenPrivate(path)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(raw) > 1024 {
		return p, errors.New("invalid throughput preferences")
	}
	p = desktopThroughputPreferences{}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(&struct{}{}) != io.EOF || p.Schema != 1 || p.XConcurrency < 1 || p.XConcurrency > 8 {
		return p, errors.New("invalid throughput preferences")
	}
	return p, nil
}

// Update and resume-on-launch settings, in their own extension file so that
// earlier releases (0.1.3-0.1.12) still read preferences.json on rollback.
type desktopLifecyclePreferences struct {
	Schema        int    `json:"schema"`
	Updates       string `json:"updates"`
	ResumeServing bool   `json:"resume_serving"`
}

func readDesktopLifecyclePreferences(path string) (desktopLifecyclePreferences, error) {
	p := desktopLifecyclePreferences{Schema: 1, Updates: "notify"}
	f, err := localfs.OpenPrivate(path)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(raw) > 1024 {
		return p, errors.New("invalid lifecycle preferences")
	}
	p = desktopLifecyclePreferences{}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(&struct{}{}) != io.EOF || p.Schema != 1 || (p.Updates != "notify" && p.Updates != "automatic") {
		return p, errors.New("invalid lifecycle preferences")
	}
	return p, nil
}

// Serving web pages, in its own extension file: desktop 0.1.13 and earlier
// decode preferences.json and the other extensions strictly, so a new field in
// any of them would stop the previous release starting after a rollback. They
// never open this file. Absent, web is on.
type desktopWebPreferences struct {
	Schema   int   `json:"schema"`
	ServeWeb *bool `json:"serve_web"`
}

func readDesktopWebPreference(path string) (bool, error) {
	f, err := localfs.OpenPrivate(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(raw) > 1024 {
		return false, errors.New("invalid web preferences")
	}
	var p desktopWebPreferences
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(&struct{}{}) != io.EOF || p.Schema != 1 || p.ServeWeb == nil {
		return false, errors.New("invalid web preferences")
	}
	return *p.ServeWeb, nil
}

// "Web pages at once", in its own extension file for the same reason as the
// web setting: every earlier release decodes its own files strictly and never
// opens this one, so a rollback still starts. Absent, it is Auto (zero).
type desktopWebCapacityPreferences struct {
	Schema         int  `json:"schema"`
	WebConcurrency *int `json:"web_concurrency"`
}

func readDesktopWebConcurrency(path string) (int, error) {
	f, err := localfs.OpenPrivate(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(raw) > 1024 {
		return 0, errors.New("invalid web capacity preferences")
	}
	var p desktopWebCapacityPreferences
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(&struct{}{}) != io.EOF || p.Schema != 1 || p.WebConcurrency == nil || !validDesktopWebConcurrency(*p.WebConcurrency) {
		return 0, errors.New("invalid web capacity preferences")
	}
	return *p.WebConcurrency, nil
}
