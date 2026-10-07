//go:build webbrowser_live && windows

package webruntime

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func powershell(t *testing.T, script string) []byte {
	t.Helper()
	out, err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		t.Fatalf("powershell: %v", err)
	}
	return out
}

// browserArgv reads the browser process's command line through CIM.
func browserArgv(t *testing.T, m *Manager, tree []procInfo) []string {
	t.Helper()
	for _, p := range tree {
		line := strings.TrimSpace(string(powershell(t, "(Get-CimInstance Win32_Process -Filter 'ProcessId="+strconv.Itoa(p.PID)+"').CommandLine")))
		argv := splitCommandLine(line)
		if len(argv) == 0 || !strings.EqualFold(argv[0], m.browser.Executable) {
			continue
		}
		browser := true
		for _, a := range argv {
			if strings.HasPrefix(a, "--type=") {
				browser = false
			}
		}
		if browser {
			return argv
		}
	}
	t.Fatal("browser process not found in the Job")
	return nil
}

func splitCommandLine(line string) []string {
	if line == "" {
		return nil
	}
	ptr, err := windows.UTF16PtrFromString(line)
	if err != nil {
		return nil
	}
	var argc int32
	argv, err := windows.CommandLineToArgv(ptr, &argc)
	if err != nil {
		return nil
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(argv))))
	out := make([]string, argc)
	for i := range out {
		out[i] = windows.UTF16PtrToString(&argv[i][0])
	}
	return out
}

// checkSockets: no connected non-loopback TCP connection owned by a Job
// process; UDP endpoints (unconnected by definition) are counted.
func checkSockets(t *testing.T, tree []procInfo) {
	t.Helper()
	pids := make([]string, 0, len(tree))
	for _, p := range tree {
		pids = append(pids, strconv.Itoa(p.PID))
	}
	list := "@(" + strings.Join(pids, ",") + ")"
	raw := powershell(t, "@(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { "+list+" -contains $_.OwningProcess } | Select-Object LocalAddress,RemoteAddress,LocalPort,State) | ConvertTo-Json -Compress")
	var conns []struct {
		LocalAddress, RemoteAddress string
		LocalPort                   int
		State                       any
	}
	text := strings.TrimSpace(string(raw))
	if strings.HasPrefix(text, "{") {
		text = "[" + text + "]"
	}
	if text != "" {
		if err := json.Unmarshal([]byte(text), &conns); err != nil {
			t.Fatalf("TCP table unreadable: %v", err)
		}
	}
	loop := func(a string) bool { return strings.HasPrefix(a, "127.") || a == "::1" || a == "0.0.0.0" || a == "::" }
	for _, c := range conns {
		if !loop(c.RemoteAddress) || !(loop(c.LocalAddress)) {
			t.Fatalf("connected non-loopback socket in the Job: %+v", c)
		}
	}
	udp := strings.TrimSpace(string(powershell(t, "@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { "+list+" -contains $_.OwningProcess }).Count")))
	t.Logf("UDP endpoints in the Job: %s", udp)
	if strings.Contains(string(powershell(t, "@(Get-NetUDPEndpoint -LocalPort 5353 -ErrorAction SilentlyContinue | Where-Object { "+list+" -contains $_.OwningProcess }).Count")), "1") {
		t.Fatal("the Job bound UDP 5353")
	}
}

type platformSnapshot struct{}

func platformState(t *testing.T) platformSnapshot { return platformSnapshot{} }

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	procEnumWindows  = user32.NewProc("EnumWindows")
	procIsVisible    = user32.NewProc("IsWindowVisible")
	procWindowThread = user32.NewProc("GetWindowThreadProcessId")
)

// checkPlatform on Windows: no visible top-level window owned by a Job
// process, and every descendant of the helper is inside the Job.
func checkPlatform(t *testing.T, _ platformSnapshot, h *helper, tree []procInfo) {
	t.Helper()
	inJob := map[uint32]bool{}
	pids, err := h.p.jobPIDs()
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range pids {
		inJob[pid] = true
	}
	visible := 0
	callback := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var pid uint32
		procWindowThread.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if inJob[pid] {
			if r, _, _ := procIsVisible.Call(hwnd); r != 0 {
				visible++
			}
		}
		return 1
	})
	procEnumWindows.Call(callback, 0)
	if visible != 0 {
		t.Fatalf("%d visible top-level windows owned by Job processes", visible)
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(snapshot)
	parent := map[uint32]uint32{}
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		parent[entry.ProcessID] = entry.ParentProcessID
	}
	root := uint32(h.p.pid())
	for pid := range parent {
		for p, hops := pid, 0; p != 0 && hops < 64; p, hops = parent[p], hops+1 {
			if p == root {
				if !inJob[pid] {
					t.Fatalf("descendant %d of the helper is outside the Job", pid)
				}
				break
			}
		}
	}
}

func checkUnregistered(*testing.T, string) {}
