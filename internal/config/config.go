package config

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Coordinator      string
	Gateway          string
	Model            string
	Profile          string
	StateDir         string
	GatewayKey       string
	LocalFixture     bool
	InferenceTimeout time.Duration
	MaxInputBytes    int
	MaxOutputTokens  int
}

func Load() (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, err
	}
	c := Config{Coordinator: os.Getenv("SCARLETT_COORDINATOR"), Gateway: os.Getenv("SCARLETT_GATEWAY"), Model: os.Getenv("SCARLETT_MODEL"), Profile: os.Getenv("SCARLETT_PROFILE"), StateDir: os.Getenv("SCARLETT_STATE_DIR"), GatewayKey: os.Getenv("SCARLETT_GATEWAY_KEY"), LocalFixture: os.Getenv("SCARLETT_LOCAL_FIXTURE") == "1", InferenceTimeout: 45 * time.Second, MaxInputBytes: 32768, MaxOutputTokens: 2048}
	if c.StateDir == "" {
		c.StateDir = filepath.Join(home, ".local", "state", "scarlett-node")
	}
	if s := os.Getenv("SCARLETT_INFERENCE_TIMEOUT_SECONDS"); s != "" {
		v, e := strconv.Atoi(s)
		if e != nil || v < 1 || v > 300 {
			return c, errors.New("invalid inference timeout")
		}
		c.InferenceTimeout = time.Duration(v) * time.Second
	}
	if s := os.Getenv("SCARLETT_MAX_INPUT_BYTES"); s != "" {
		v, e := strconv.Atoi(s)
		if e != nil || v < 1 || v > 65536 {
			return c, errors.New("invalid max input bytes")
		}
		c.MaxInputBytes = v
	}
	if s := os.Getenv("SCARLETT_MAX_OUTPUT_TOKENS"); s != "" {
		v, e := strconv.Atoi(s)
		if e != nil || v < 1 || v > 8192 {
			return c, errors.New("invalid max output tokens")
		}
		c.MaxOutputTokens = v
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.Model == "" || c.Profile == "" || strings.ContainsAny(c.Model+c.Profile, " \n\r\t") || len(c.Model) > 128 || len(c.Profile) > 128 {
		return errors.New("SCARLETT_MODEL and SCARLETT_PROFILE required")
	}
	if c.LocalFixture && c.Profile != "local-fixture" {
		return errors.New("local fixture requires local-fixture profile")
	}
	if c.LocalFixture && (len(c.GatewayKey) < 32 || strings.Trim(c.GatewayKey, " ") == "") {
		return errors.New("local fixture requires SCARLETT_GATEWAY_KEY with at least 32 characters")
	}
	if c.LocalFixture && (c.Coordinator != "http://host.docker.internal:8091" || c.Gateway != "http://agent1-gateway:8088" && c.Gateway != "http://agent2-gateway:8088" || c.Model != "gpt-5.6-terra" && c.Model != "gpt-5.6-sol" || c.Model == "gpt-5.6-terra" && c.Gateway != "http://agent1-gateway:8088" || c.Model == "gpt-5.6-sol" && c.Gateway != "http://agent2-gateway:8088") {
		return errors.New("local fixture requires pinned Docker services and models")
	}
	if c.InferenceTimeout < time.Second || c.InferenceTimeout > 300*time.Second || c.MaxInputBytes < 1 || c.MaxInputBytes > 65536 || c.MaxOutputTokens < 1 || c.MaxOutputTokens > 8192 {
		return errors.New("invalid limits")
	}
	u, e := url.Parse(c.Coordinator)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("SCARLETT_COORDINATOR must be an origin")
	}
	if u.Scheme != "https" && !(c.LocalFixture && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "host.docker.internal" || net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback())) {
		return errors.New("SCARLETT_COORDINATOR must be HTTPS or explicit local fixture HTTP")
	}
	g, e := url.Parse(c.Gateway)
	if e != nil || g.Host == "" || g.User != nil || g.RawQuery != "" || g.Fragment != "" || g.Path != "" {
		return errors.New("SCARLETT_GATEWAY must be a gateway origin")
	}
	if g.Scheme != "https" {
		if g.Scheme != "http" {
			return errors.New("gateway must use HTTP or HTTPS")
		}
		host, _, e := net.SplitHostPort(g.Host)
		if e != nil {
			host = g.Host
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) && !(c.LocalFixture && (host == "agent1-gateway" || host == "agent2-gateway")) {
			return errors.New("HTTP gateway must be loopback or explicit local Docker fixture")
		}
	}
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return errors.New("state directory must be absolute")
	}
	return nil
}
