//go:build webbrowser_live && unix

package webruntime

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// browserArgv is the live argv of the browser process (no --type=) in tree.
func browserArgv(t *testing.T, m *Manager, tree []procInfo) []string {
	t.Helper()
	for _, p := range tree {
		var argv []string
		if m.browser.Executable == "" {
			break
		}
		switch runtimeGOOS() {
		case "linux":
			raw, err := os.ReadFile("/proc/" + strconv.Itoa(p.PID) + "/cmdline")
			if err != nil {
				continue
			}
			argv = strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		default:
			out, err := exec.Command("/bin/ps", "-ww", "-o", "command=", "-p", strconv.Itoa(p.PID)).Output()
			if err != nil {
				continue
			}
			line := strings.TrimSpace(string(out))
			if !strings.HasPrefix(line, m.browser.Executable) {
				continue
			}
			argv = append([]string{m.browser.Executable}, strings.Fields(strings.TrimPrefix(line, m.browser.Executable))...)
		}
		if len(argv) == 0 || argv[0] != m.browser.Executable {
			continue
		}
		isBrowser := true
		for _, a := range argv {
			if strings.HasPrefix(a, "--type=") {
				isBrowser = false
			}
		}
		if isBrowser {
			return argv
		}
	}
	t.Fatal("browser process not found in the helper tree")
	return nil
}

// ownBytes is one process's memory by the measure treeBytes sums (darwin RSS,
// linux Pss).
func ownBytes(pid int) uint64 {
	table, err := processTable()
	if err != nil {
		return 0
	}
	for _, row := range table {
		if row.PID == pid {
			return treeMemory([]procInfo{row})
		}
	}
	return 0
}

// checkSockets: no connected non-loopback socket and no UDP 5353 in the tree.
// Unconnected wildcard UDP binds are counted and reported, not failed.
func checkSockets(t *testing.T, tree []procInfo) {
	t.Helper()
	var bad []string
	unconnectedUDP := 0
	if runtimeGOOS() == "linux" {
		bad, unconnectedUDP = linuxSockets(tree)
	} else {
		pids := make([]string, 0, len(tree))
		for _, p := range tree {
			pids = append(pids, strconv.Itoa(p.PID))
		}
		out, _ := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-i", "-p", strings.Join(pids, ",")).Output()
		for _, line := range strings.Split(string(out), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 9 {
				continue
			}
			name := strings.Join(f[8:], " ")
			if strings.Contains(name, ":5353") {
				bad = append(bad, "mDNS "+f[7])
			}
			if !strings.Contains(name, "->") {
				if f[7] == "UDP" && !loopbackEnd(strings.Fields(name)[0]) {
					unconnectedUDP++
				}
				continue
			}
			ends := strings.Split(strings.Fields(name)[0], "->")
			if !loopbackEnd(ends[0]) || !loopbackEnd(ends[1]) {
				bad = append(bad, f[7]+" connected non-loopback")
			}
		}
	}
	if len(bad) > 0 {
		t.Fatalf("browser tree sockets: %v", bad)
	}
	t.Logf("unconnected wildcard UDP binds in the browser tree: %d", unconnectedUDP)
}

func loopbackEnd(end string) bool {
	return strings.HasPrefix(end, "127.") || strings.HasPrefix(end, "[::1]") || strings.HasPrefix(end, "localhost:")
}

func linuxSockets(tree []procInfo) (bad []string, unconnected int) {
	inodes := map[string]bool{}
	for _, p := range tree {
		entries, _ := os.ReadDir("/proc/" + strconv.Itoa(p.PID) + "/fd")
		for _, e := range entries {
			if target, err := os.Readlink("/proc/" + strconv.Itoa(p.PID) + "/fd/" + e.Name()); err == nil && strings.HasPrefix(target, "socket:[") {
				inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
			}
		}
	}
	for _, p := range tree {
		for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
			raw, err := os.ReadFile("/proc/" + strconv.Itoa(p.PID) + "/net/" + table)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(raw), "\n")[1:] {
				f := strings.Fields(line)
				if len(f) < 10 || !inodes[f[9]] {
					continue
				}
				local, remote := procAddr(f[1]), procAddr(f[2])
				if strings.HasSuffix(f[1], ":14E9") {
					bad = append(bad, "mDNS "+table)
				}
				if !remote.IsValid() || remote.Addr().IsUnspecified() {
					if strings.HasPrefix(table, "udp") && !local.Addr().IsLoopback() {
						unconnected++
					}
					continue
				}
				if !remote.Addr().IsLoopback() || !local.Addr().IsLoopback() {
					bad = append(bad, table+" connected non-loopback")
				}
			}
			delete(inodes, "") // tables are per network namespace; one pass is enough
		}
		break
	}
	return bad, unconnected
}

// procAddr decodes /proc/net "HEXADDR:HEXPORT" (little-endian words).
func procAddr(s string) netip.AddrPort {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return netip.AddrPort{}
	}
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	p, _ := strconv.ParseUint(port, 16, 16)
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(p))
}

type platformSnapshot struct{ front string }

func platformState(t *testing.T) platformSnapshot {
	if runtimeGOOS() != "darwin" {
		return platformSnapshot{}
	}
	out, _ := exec.Command("/usr/bin/lsappinfo", "front").Output()
	return platformSnapshot{front: strings.TrimSpace(string(out))}
}

// checkPlatform on macOS: every tree process LaunchServices knows is
// BackgroundOnly, the front app is unchanged and the tree owns no window.
func checkPlatform(t *testing.T, before platformSnapshot, h *helper, tree []procInfo) {
	t.Helper()
	if runtimeGOOS() != "darwin" {
		return
	}
	pids := map[int]bool{}
	for _, p := range tree {
		pids[p.PID] = true
	}
	out, _ := exec.Command("/usr/bin/lsappinfo", "list").Output()
	for _, block := range strings.Split(string(out), "\n") {
		block = strings.TrimSpace(block)
		if !strings.HasPrefix(block, "pid = ") {
			continue
		}
		f := strings.Fields(block)
		pid, _ := strconv.Atoi(f[2])
		if pids[pid] && !strings.Contains(block, `type="BackgroundOnly"`) {
			t.Fatalf("a browser process is registered as an app that is not BackgroundOnly: %s", block)
		}
	}
	if after, _ := exec.Command("/usr/bin/lsappinfo", "front").Output(); strings.TrimSpace(string(after)) != before.front {
		t.Logf("front app changed during the test (check by hand if nobody switched apps)")
	}
	script := `ObjC.import('CoreGraphics');var w=ObjC.deepUnwrap(ObjC.castRefToObject($.CGWindowListCopyWindowInfo($.kCGWindowListOptionAll,$.kCGNullWindowID)));JSON.stringify(w.map(function(d){return {pid:d.kCGWindowOwnerPID,owner:d.kCGWindowOwnerName||'',layer:d.kCGWindowLayer,onscreen:!!d.kCGWindowIsOnscreen,alpha:d.kCGWindowAlpha,b:d.kCGWindowBounds}}))`
	raw, err := exec.Command("/usr/bin/osascript", "-l", "JavaScript", "-e", script).Output()
	if err != nil {
		t.Logf("window list unavailable: %v", err)
		return
	}
	var windows []struct {
		PID      int            `json:"pid"`
		Owner    string         `json:"owner"`
		Layer    int            `json:"layer"`
		Onscreen bool           `json:"onscreen"`
		Alpha    float64        `json:"alpha"`
		Bounds   map[string]any `json:"b"`
	}
	if err := json.Unmarshal(raw, &windows); err != nil {
		t.Fatalf("window list unreadable: %v", err)
	}
	offscreen := 0
	for _, w := range windows {
		if !pids[w.PID] {
			continue
		}
		if w.Onscreen {
			t.Fatalf("browser tree owns an on-screen window: %+v", w)
		}
		offscreen++
		t.Logf("off-screen window record owned by the browser tree: layer %d alpha %v bounds %v", w.Layer, w.Alpha, w.Bounds)
	}
	t.Logf("off-screen window records owned by the browser tree: %d", offscreen)
	_ = h
}

// checkUnregistered: on macOS, LaunchServices keeps no record of the node's
// Chrome for Testing (or its nested helper apps) once the helper stopped.
func checkUnregistered(t *testing.T, state string) {
	t.Helper()
	if runtimeGOOS() != "darwin" {
		return
	}
	out, err := exec.Command("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister", "-dump").Output()
	if err != nil {
		t.Fatalf("lsregister -dump: %v", err)
	}
	if n := strings.Count(string(out), filepath.Join(state, "web-browser-bin")); n != 0 {
		t.Fatalf("%d LaunchServices records of the node's browser remain after the stop", n)
	}
}

// handlerApps, on macOS: for each external scheme the fixture pages try,
// the app LaunchServices would open and the process IDs it has now. A
// launch shows up as a new process ID (checkNoHandlerApp).
func handlerApps(t *testing.T) map[string][]string {
	t.Helper()
	if runtimeGOOS() != "darwin" {
		return nil
	}
	script := `ObjC.import('AppKit');var o={};['mailto:x@example.invalid','news:x'].forEach(function(u){` +
		`var a=$.NSWorkspace.sharedWorkspace.URLForApplicationToOpenURL($.NSURL.URLWithString(u));` +
		`if(a&&!a.isNil())o[u.split(':')[0]]=a.path.js});JSON.stringify(o)`
	raw, err := exec.Command("/usr/bin/osascript", "-l", "JavaScript", "-e", script).Output()
	var bundles map[string]string
	if err != nil || json.Unmarshal(raw, &bundles) != nil {
		t.Fatalf("default handler apps unreadable: %v", err)
	}
	apps := map[string][]string{}
	for _, bundle := range bundles {
		apps[bundle] = appPIDs(bundle)
	}
	t.Logf("handler apps watched: %d", len(apps))
	return apps
}

func appPIDs(bundle string) []string {
	out, _ := exec.Command("/usr/bin/pgrep", "-f", "--", filepath.Join(bundle, "Contents", "MacOS")+"/").Output()
	return strings.Fields(string(out))
}

func checkNoHandlerApp(t *testing.T, apps map[string][]string) {
	t.Helper()
	for bundle, before := range apps {
		for _, pid := range appPIDs(bundle) {
			if !slices.Contains(before, pid) {
				t.Fatalf("a fixture page opened %s (pid %s); quit it without saving", filepath.Base(bundle), pid)
			}
		}
	}
}
