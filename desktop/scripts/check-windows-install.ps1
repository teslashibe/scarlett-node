# Runs only on a disposable native CI runner, never an operator's Windows profile
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
    [switch]$Preferences,
    [string]$BrowserFixture = '',
    [string]$UpgradeFixture = '',
    [string]$UpgradeInstaller = '',
    [string]$XLoginRuntimeFixture = $env:SCARLETT_X_LOGIN_RUNTIME_FIXTURE
)
$ErrorActionPreference = 'Stop'
$script:apiPort = 8088
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Installed UI acceptance requires a disposable Windows CI runner'
}
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Windows.Forms
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class ScarlettAcceptanceWindow {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr window, int command);
    [DllImport("user32.dll")] public static extern bool IsZoomed(IntPtr window);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int key);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] private static extern IntPtr GetThreadDpiAwarenessContext();
    [DllImport("user32.dll")] private static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll")] private static extern int GetAwarenessFromDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(IntPtr window);
    [DllImport("kernel32.dll")] private static extern void SetLastError(uint error);
    [StructLayout(LayoutKind.Sequential)] private struct ScreenPoint { public int x, y; }
    [DllImport("user32.dll")] private static extern IntPtr WindowFromPhysicalPoint(ScreenPoint point);
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromPoint(ScreenPoint point, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr window, uint flags);
    public enum NativeFailure { None, DesktopBounds, InputLayout, ModifierPressed, RejectedEvents }
    public static NativeFailure LastNativeFailure { get; private set; }
    public static uint LastInputExpected { get; private set; }
    public static uint LastInputAccepted { get; private set; }
    public static int LastInputError { get; private set; }
    public static void ResetInputDiagnostics() {
        LastNativeFailure = NativeFailure.None;
        LastInputExpected = LastInputAccepted = 0;
        LastInputError = 0;
    }
    public static int ThreadDpiAwareness() {
        return GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext());
    }
    public static uint WindowDpi(IntPtr window) { return GetDpiForWindow(window); }
    public static bool PointOwnedByWindow(IntPtr window, int x, int y) {
        ScreenPoint point = new ScreenPoint(); point.x = x; point.y = y;
        IntPtr owner = WindowFromPhysicalPoint(point);
        return owner != IntPtr.Zero && (owner == window || IsChild(window, owner));
    }
    public static bool PointInDesktop(int x, int y) {
        int left = GetSystemMetrics(76), top = GetSystemMetrics(77);
        int width = GetSystemMetrics(78), height = GetSystemMetrics(79);
        return width >= 2 && height >= 2 && x >= left && y >= top &&
            (long)x < (long)left + width && (long)y < (long)top + height;
    }
    public static bool[] PhysicalPointContext(IntPtr window, int x, int y) {
        // Compare physical UIA coordinates to real monitors without retaining
        // a change to the caller's context or injecting any input.
        bool[] state = new bool[4];
        IntPtr previous = SetThreadDpiAwarenessContext(new IntPtr(-4));
        if (previous == IntPtr.Zero) return state;
        try {
            ScreenPoint point = new ScreenPoint(); point.x = x; point.y = y;
            state[0] = true;
            state[1] = MonitorFromPoint(point, 0) != IntPtr.Zero;
            state[2] = MonitorFromWindow(window, 0) != IntPtr.Zero;
        } finally { state[3] = SetThreadDpiAwarenessContext(previous) != IntPtr.Zero; }
        return state;
    }
    [StructLayout(LayoutKind.Sequential)] private struct KeyboardInput {
        public ushort key, scan; public uint flags, time; public UIntPtr extra;
    }
    [StructLayout(LayoutKind.Sequential)] private struct MouseInput {
        public int x, y; public uint data, flags, time; public UIntPtr extra;
    }
    [StructLayout(LayoutKind.Explicit)] private struct InputUnion {
        [FieldOffset(0)] public KeyboardInput keyboard;
        [FieldOffset(0)] public MouseInput mouse;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Input {
        public uint type; public InputUnion value;
    }
    [DllImport("user32.dll", SetLastError = true)] private static extern uint SendInput(uint count, Input[] inputs, int size);
    private static Input Key(ushort key, bool up) {
        Input input = new Input(); input.type = 1;
        input.value.keyboard.key = key; input.value.keyboard.flags = up ? 2u : 0u;
        return input;
    }
    public static bool ModifiersReleased() {
        foreach (int key in new int[] { 0x10, 0x11, 0x12, 0x5B, 0x5C })
            if ((GetAsyncKeyState(key) & 0x8000) != 0) return false;
        return true;
    }
    public static int InputSize() { return Marshal.SizeOf(typeof(Input)); }
    private static void Send(Input[] inputs) {
        ResetInputDiagnostics();
        if (InputSize() != (IntPtr.Size == 8 ? 40 : 28)) {
            LastNativeFailure = NativeFailure.InputLayout;
            throw new InvalidOperationException("Native input layout mismatch");
        }
        if (!ModifiersReleased()) {
            LastNativeFailure = NativeFailure.ModifierPressed;
            throw new InvalidOperationException("CI keyboard modifier was already pressed");
        }
        LastInputExpected = (uint)inputs.Length;
        int size = Marshal.SizeOf(typeof(Input));
        // .NET Framework preserves native last-error across P/Invokes. SendInput
        // can reject events without setting it, so clear stale error information.
        SetLastError(0);
        LastInputAccepted = SendInput(LastInputExpected, inputs, size);
        int error = Marshal.GetLastWin32Error();
        if (LastInputAccepted != LastInputExpected) {
            LastInputError = error;
            LastNativeFailure = NativeFailure.RejectedEvents;
            throw new InvalidOperationException("Native input stream rejected events");
        }
    }
    public static void UnicodeTextAndTab(string text) {
        // Disposable ASCII fixtures only. One stream preserves text/Tab order.
        if (String.IsNullOrEmpty(text) || text.Length > 512)
            throw new InvalidOperationException("Synthetic text exceeds its bound");
        Input[] inputs = new Input[text.Length * 2 + 2];
        for (int i = 0; i < text.Length; i++) {
            char c = text[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                throw new InvalidOperationException("Synthetic text contains unsupported characters");
            Input down = new Input(); down.type = 1;
            down.value.keyboard.scan = c; down.value.keyboard.flags = 4u;
            Input up = down; up.value.keyboard.flags = 6u;
            inputs[i * 2] = down; inputs[i * 2 + 1] = up;
        }
        inputs[inputs.Length - 2] = Key(0x09, false);
        inputs[inputs.Length - 1] = Key(0x09, true);
        Send(inputs);
    }
    public static void ControlKey(ushort key) {
        Send(new Input[] { Key(0x11, false), Key(key, false), Key(key, true), Key(0x11, true) });
    }
    public static void Escape() {
        Send(new Input[] { Key(0x1B, false), Key(0x1B, true) });
    }
    public static void Click(int x, int y) {
        ResetInputDiagnostics();
        int left = GetSystemMetrics(76), top = GetSystemMetrics(77);
        int width = GetSystemMetrics(78), height = GetSystemMetrics(79);
        if (width < 2 || height < 2 || x < left || y < top ||
            (long)x >= (long)left + width || (long)y >= (long)top + height) {
            LastNativeFailure = NativeFailure.DesktopBounds;
            throw new InvalidOperationException("Synthetic click outside desktop bounds");
        }
        Input move = new Input();
        move.value.mouse.x = (int)(((long)x - left) * 65535 / (width - 1));
        move.value.mouse.y = (int)(((long)y - top) * 65535 / (height - 1));
        move.value.mouse.flags = 0xC001;
        Input down = new Input(); down.value.mouse.flags = 2;
        Input up = new Input(); up.value.mouse.flags = 4;
        Send(new Input[] { move, down, up });
    }
    public static void SelectAllAndClear() {
        Send(new Input[] { Key(0x11, false), Key(0x41, false), Key(0x41, true), Key(0x11, true),
            Key(0x08, false), Key(0x08, true) });
    }
    [StructLayout(LayoutKind.Sequential)] private struct Bounds { public int left, top, right, bottom; }
    [StructLayout(LayoutKind.Sequential)] private struct GuiThreadInfo {
        public int size; public uint flags;
        public IntPtr active, focus, capture, menuOwner, moveSize, caret;
        public Bounds caretBounds;
    }
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll")] private static extern bool GetGUIThreadInfo(uint thread, ref GuiThreadInfo info);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassNameW(IntPtr window, System.Text.StringBuilder name, int size);
    [DllImport("user32.dll")] private static extern bool IsChild(IntPtr parent, IntPtr window);
    [DllImport("user32.dll")] private static extern IntPtr GetParent(IntPtr window);
    [DllImport("user32.dll")] private static extern IntPtr SetFocus(IntPtr window);
    [DllImport("user32.dll")] private static extern bool AttachThreadInput(uint attach, uint to, bool enable);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    private static string ClassOf(IntPtr window) {
        System.Text.StringBuilder name = new System.Text.StringBuilder(128);
        if (window == IntPtr.Zero || GetClassNameW(window, name, name.Capacity) == 0) return "";
        return name.ToString();
    }
    private static IntPtr KeyboardFocus(IntPtr window) {
        uint process;
        uint thread = GetWindowThreadProcessId(window, out process);
        GuiThreadInfo info = new GuiThreadInfo();
        info.size = Marshal.SizeOf(typeof(GuiThreadInfo));
        if (thread == 0 || !GetGUIThreadInfo(thread, ref info)) return IntPtr.Zero;
        return info.focus;
    }
    // UIA can report a WebView2 element focused while native keyboard focus is
    // on Chromium's accessibility-only Chrome_RenderWidgetHostHWND, which drops
    // every injected key. Input reaches the page only through this app window's
    // WebView2 input widget (Chrome_WidgetWin_*) in the msedgewebview2 process.
    private static bool IsWebViewInput(IntPtr window, IntPtr candidate) {
        if (candidate == IntPtr.Zero || !IsChild(window, candidate) ||
            !ClassOf(candidate).StartsWith("Chrome_WidgetWin_", StringComparison.Ordinal)) return false;
        uint process;
        GetWindowThreadProcessId(candidate, out process);
        try {
            using (System.Diagnostics.Process owner = System.Diagnostics.Process.GetProcessById((int)process))
                return String.Equals(owner.ProcessName, "msedgewebview2", StringComparison.OrdinalIgnoreCase);
        } catch (ArgumentException) { return false; } catch (InvalidOperationException) { return false; }
    }
    public static bool WebViewHasInputFocus(IntPtr window) { return IsWebViewInput(window, KeyboardFocus(window)); }
    public static bool AccessibilityWindowFocused(IntPtr window) {
        IntPtr focus = KeyboardFocus(window);
        return focus != IntPtr.Zero && IsChild(window, focus) && ClassOf(focus) == "Chrome_RenderWidgetHostHWND";
    }
    public static bool FocusInWindow(IntPtr window) {
        IntPtr focus = KeyboardFocus(window);
        return focus == window || (focus != IntPtr.Zero && IsChild(window, focus));
    }
    // Hand native focus from the accessibility window to the WebView2 input
    // widget that owns it, as Chromium's own pointer input does; from anywhere
    // else, focus the app window, whose WebView host moves focus into WebView2.
    public static void RestoreWebViewInputFocus(IntPtr window) {
        IntPtr target = window;
        if (AccessibilityWindowFocused(window)) {
            IntPtr owner = GetParent(KeyboardFocus(window));
            if (IsWebViewInput(window, owner)) target = owner;
        }
        uint process;
        uint thread = GetWindowThreadProcessId(target, out process);
        uint self = GetCurrentThreadId();
        if (thread == 0 || !AttachThreadInput(self, thread, true))
            throw new InvalidOperationException("Native input queue unavailable");
        try { SetFocus(target); } finally { AttachThreadInput(self, thread, false); }
    }
    public static void SelectAllClearAndTab() {
        Send(new Input[] { Key(0x11, false), Key(0x41, false), Key(0x41, true), Key(0x11, true),
            Key(0x08, false), Key(0x08, true), Key(0x09, false), Key(0x09, true) });
    }
}
'@

function Wait-Check([scriptblock]$Check, [int]$Seconds, [string]$Failure) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        if (& $Check) { return }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw $Failure
}
function Response-Status($Response) {
    try {
        $stream = $Response.GetResponseStream()
        if ($stream) {
            $buffer = New-Object byte[] 8192
            $received = 0
            while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $received += $count
                if ($received -gt 512 * 1024) { throw 'Local API status response exceeded its bound' }
            }
        }
        return [int]$Response.StatusCode
    } finally { $Response.Close() }
}
function Api-Status([string]$Path, [string]$Bearer = '') {
    $request = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$($script:apiPort)$Path")
    $request.Timeout = 2000
    $request.ReadWriteTimeout = 2000
    $request.KeepAlive = $false
    $request.AllowAutoRedirect = $false
    $request.Proxy = $null
    if ($Bearer) { $request.Headers['Authorization'] = "Bearer $Bearer" }
    try {
        $response = $request.GetResponse()
        return Response-Status $response
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
            return Response-Status $response
        }
        return 0
    }
}
function Find-Button([string]$Name) {
    $condition = [System.Windows.Automation.AndCondition]::new(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, $Name),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Button)
    )
    return $script:window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}
function Click-Button([string]$Name) {
    Wait-Check {
        $control = Find-Button $Name
        return $null -ne $control -and $control.Current.IsEnabled
    } 30 "UI control did not become available: $Name"
    $button = Find-Button $Name
    if (-not $button -or -not $button.Current.IsEnabled) { throw "UI control unavailable: $Name" }
    $scroll = $null
    if ($button.TryGetCurrentPattern([System.Windows.Automation.ScrollItemPattern]::Pattern, [ref]$scroll)) {
        $scroll.ScrollIntoView()
    }
    $invoke = $null
    if (-not $button.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$invoke)) {
        throw "UI invocation unavailable: $Name"
    }
    $invoke.Invoke()
}
function Find-Disclosure([string]$Name) {
    # A summary can share its name with a submit button. Its native expansion
    # pattern identifies the disclosure without relying on hidden form fields.
    $condition = [System.Windows.Automation.AndCondition]::new(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, $Name),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::IsExpandCollapsePatternAvailableProperty, $true)
    )
    return $script:window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}
function Open-Disclosure([string]$Name) {
    Wait-Check {
        $control = Find-Disclosure $Name
        return $null -ne $control -and $control.Current.IsEnabled
    } 30 "UI disclosure did not become available: $Name"
    $control = Find-Disclosure $Name
    $scroll = $null
    if ($control.TryGetCurrentPattern([System.Windows.Automation.ScrollItemPattern]::Pattern, [ref]$scroll)) {
        $scroll.ScrollIntoView()
    }
    $pattern = $null
    if (-not $control.TryGetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern, [ref]$pattern)) {
        throw "UI disclosure expansion unavailable: $Name"
    }
    if ($pattern.Current.ExpandCollapseState -eq [System.Windows.Automation.ExpandCollapseState]::Collapsed) {
        $pattern.Expand()
    }
    Wait-Check {
        return $pattern.Current.ExpandCollapseState -eq [System.Windows.Automation.ExpandCollapseState]::Expanded
    } 10 "UI disclosure did not open: $Name"
}
function Wait-AppWindow {
    Wait-Check {
        $condition = [System.Windows.Automation.AndCondition]::new(
            [System.Windows.Automation.PropertyCondition]::new(
                [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $script:application.Id),
            [System.Windows.Automation.PropertyCondition]::new(
                [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
                [System.Windows.Automation.ControlType]::Window)
        )
        $script:window = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst(
            [System.Windows.Automation.TreeScope]::Children, $condition)
        return $null -ne $script:window
    } 45 'Installed desktop window did not appear'
    $script:window.SetFocus()
    Wait-Check {
        $control = Find-Disclosure 'Add account'
        return $null -ne $control -and $control.Current.IsEnabled
    } 30 'Installed desktop account controls did not become available'
    Open-Disclosure 'Local model API'
    Wait-Check {
        $start = Find-Button 'Start local API'
        $stop = Find-Button 'Stop local API'
        # A background reopen retains its running API, so Start is disabled.
        # Either enabled lifecycle control proves the renderer is ready; each
        # subsequent operation still waits for its specific control/state.
        return ($null -ne $start -and $start.Current.IsEnabled) -or
            ($null -ne $stop -and $stop.Current.IsEnabled)
    } 30 'Installed desktop API controls did not become available'
}
function Start-App {
    $script:application = Start-Process -FilePath $script:executable -WorkingDirectory $script:install -PassThru
    Wait-AppWindow
}
function Wait-KeyboardTarget([System.Windows.Automation.AutomationElement]$Element, [IntPtr]$Handle, [string]$Failure) {
    # UIA focus selects the page element but can leave native keyboard focus on
    # the WebView's accessibility window, where every injected key is lost.
    # Let the element focus land first, then require WebView2 native input.
    try {
        Wait-Check { $Element.Current.HasKeyboardFocus } 10 $Failure
        if (-not [ScarlettAcceptanceWindow]::WebViewHasInputFocus($Handle)) {
            [ScarlettAcceptanceWindow]::RestoreWebViewInputFocus($Handle)
            $script:nativeFocusRestores++
        }
        Wait-Check {
            return $Element.Current.HasKeyboardFocus -and
                [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $Handle -and
                [ScarlettAcceptanceWindow]::WebViewHasInputFocus($Handle)
        } 10 $Failure
    } catch {
        $originalFailure = $_
        # Fixed booleans only: never UI text, values or window titles.
        $diagnostic = @{ elementFocused = $false; foregroundOwned = $false; webViewNativeInputFocus = $false
            accessibilityWindowNativeFocus = $false; nativeFocusInWindow = $false; realProviderJobs = 0 }
        try {
            $diagnostic.elementFocused = $Element.Current.HasKeyboardFocus
            $diagnostic.foregroundOwned = [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $Handle
            $diagnostic.webViewNativeInputFocus = [ScarlettAcceptanceWindow]::WebViewHasInputFocus($Handle)
            $diagnostic.accessibilityWindowNativeFocus = [ScarlettAcceptanceWindow]::AccessibilityWindowFocused($Handle)
            $diagnostic.nativeFocusInWindow = [ScarlettAcceptanceWindow]::FocusInWindow($Handle)
        } catch { }
        New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
        $diagnostic | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-native-focus-failure.json')
        Write-Output ($diagnostic | ConvertTo-Json -Compress)
        throw $originalFailure
    }
}
function Focus-QuitShortcut {
    Verify-KeyboardDelivery
    # UIA Invoke can operate a background window. SendKeys instead targets the
    # foreground input stream, so prove both the native host and WebView focus.
    $application.Refresh()
    $handle = $application.MainWindowHandle
    if ($handle -eq [IntPtr]::Zero) { throw 'Quit shortcut has no native window handle' }
    [ScarlettAcceptanceWindow]::ShowWindow($handle, 9) | Out-Null
    [ScarlettAcceptanceWindow]::SetForegroundWindow($handle) | Out-Null
    Wait-Check {
        return [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle
    } 10 'Installed desktop did not acquire foreground input for Quit'
    # API readiness precedes the renderer's status refresh; wait for its actual
    # control readiness rather than treating a temporarily busy UI as failure.
    Wait-Check {
        $control = Find-Button 'Stop local API'
        return $null -ne $control -and $control.Current.IsEnabled
    } 20 'Quit focus control did not become available'
    $target = Find-Button 'Stop local API'
    $scroll = $null
    if ($target.TryGetCurrentPattern([System.Windows.Automation.ScrollItemPattern]::Pattern, [ref]$scroll)) {
        $scroll.ScrollIntoView()
    }
    $target.SetFocus()
    Wait-KeyboardTarget $target $handle 'Installed desktop control did not acquire keyboard focus for Quit'
    Wait-Check {
        $focused = [System.Windows.Automation.AutomationElement]::FocusedElement
        return $null -ne $focused -and $focused.Current.ProcessId -eq $target.Current.ProcessId -and
            $target.Current.HasKeyboardFocus -and
            [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle -and
            [ScarlettAcceptanceWindow]::WebViewHasInputFocus($handle)
    } 10 'Installed desktop control did not acquire keyboard focus for Quit'
    Write-Output 'Installed acceptance: foreground and WebView keyboard focus verified'
}

function Check-QuitShortcut([string]$Failure) {
    # Inject one native key-down/key-up sequence; no retry or button fallback
    # can turn a failed shortcut into a pass.
    [ScarlettAcceptanceWindow]::ControlKey(0x51)
    if ($application.WaitForExit(135000)) { return }
    # Keep the shortcut failure, but distinguish missed input from a native
    # shutdown error. Capture only fixed classifications, never UI text or keys.
    $shutdownError = $false
    $focusMatches = $false
    $foregroundMatches = $false
    $nativeInput = $false
    $nativeAccessibilityFocus = $false
    try {
        $elements = $script:window.FindAll([System.Windows.Automation.TreeScope]::Descendants,
            [System.Windows.Automation.Condition]::TrueCondition)
        foreach ($element in $elements) {
            if ($element.Current.Name.StartsWith('Scarlett could not stop safely. ', [StringComparison]::Ordinal)) {
                $shutdownError = $true
            }
        }
        $target = Find-Button 'Stop local API'
        $focusMatches = $null -ne $target -and $target.Current.HasKeyboardFocus
        $application.Refresh()
        $foregroundMatches = [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $application.MainWindowHandle
        $nativeInput = [ScarlettAcceptanceWindow]::WebViewHasInputFocus($application.MainWindowHandle)
        $nativeAccessibilityFocus = [ScarlettAcceptanceWindow]::AccessibilityWindowFocused($application.MainWindowHandle)
    } catch { }
    $diagnostic = @{
        shortcutExited = $false; shutdownErrorVisible = $shutdownError
        stopControlKeyboardFocus = $focusMatches; foregroundOwnedWindow = $foregroundMatches
        webViewNativeInputFocus = $nativeInput; accessibilityWindowNativeFocus = $nativeAccessibilityFocus
        apiStatusBeforeButton = (Api-Status '/health'); quitButtonInvoked = $false
        quitButtonExited = $false; realProviderJobs = 0
    }
    try {
        Click-Button 'Quit Scarlett'
        $diagnostic.quitButtonInvoked = $true
        $diagnostic.quitButtonExited = $application.WaitForExit(135000)
    } catch { }
    $diagnostic.apiStatusAfterButton = Api-Status '/health'
    New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
    $diagnostic | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-quit-failure.json')
    Write-Output ($diagnostic | ConvertTo-Json -Compress)
    # A successful button quit is diagnostic evidence, never a passing shortcut.
    throw $Failure
}

function Verify-KeyboardDelivery {
    # UIA Invoke/SetFocus can succeed without an interactive input desktop.
    # Prove native text delivery reaches a harmless empty field before blaming a shortcut.
    Write-Output "Installed keyboard probe: interactive=$([Environment]::UserInteractive), session=$([System.Diagnostics.Process]::GetCurrentProcess().SessionId)"
    Open-Disclosure 'Add account'
    Open-Disclosure 'Sign in to X'
    # This fixed form pair is independent of browser profile discovery. Tab
    # skips hidden per-account capacity and reaches the reconnect checkbox.
    $name = 'Local account ID for X login'
    $nextName = 'Replace the session for an existing local account'
    $condition = [System.Windows.Automation.AndCondition]::new(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, $name),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Edit)
    )
    $targets = $script:window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
    if ($targets.Count -ne 1) { throw 'Keyboard probe requires one disposable account field' }
    $target = $targets[0]
    $value = $null
    if ($null -eq $target -or -not $target.Current.IsEnabled -or -not $target.Current.IsKeyboardFocusable -or
        $target.Current.IsPassword -or
        -not $target.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$value) -or
        $value.Current.Value -ne '') { throw 'Keyboard probe requires an empty disposable account field' }
    Wait-Check {
        $next = Find-Input $nextName
        return $null -ne $next -and $next.Current.IsEnabled -and
            $next.Current.ControlType -eq [System.Windows.Automation.ControlType]::CheckBox
    } 15 'Keyboard probe successor did not become ready'
    $next = Find-Input $nextName
    $toggle = $null
    if (-not $next.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$toggle)) {
        throw 'Keyboard probe successor has no checkbox state'
    }
    $toggleBefore = $toggle.Current.ToggleState
    $handle = $application.MainWindowHandle
    [ScarlettAcceptanceWindow]::ShowWindow($handle, 9) | Out-Null
    [ScarlettAcceptanceWindow]::SetForegroundWindow($handle) | Out-Null
    $target.SetFocus()
    Wait-KeyboardTarget $target $handle 'Keyboard probe did not acquire foreground and field focus'
    [ScarlettAcceptanceWindow]::UnicodeTextAndTab('keyboard-probe')
    Wait-InputAdvanced $name $nextName $handle $false 'Keyboard probe text was not acknowledged by successor focus'
    Wait-Check { $value.Current.Value -ceq 'keyboard-probe' } 10 'CI keyboard injection did not reach the editable control'
    $target.SetFocus()
    Wait-KeyboardTarget $target $handle 'Keyboard probe did not reacquire field focus'
    [ScarlettAcceptanceWindow]::SelectAllClearAndTab()
    Wait-InputAdvanced $name $nextName $handle $true 'Keyboard probe clear was not acknowledged by successor focus'
    Wait-Check { $value.Current.Value -ceq '' } 10 'Native control-key input did not clear the disposable field'
    if ($toggle.Current.ToggleState -ne $toggleBefore) { throw 'Keyboard probe changed the reconnect choice' }
    Write-Output 'Installed acceptance: text and native control-key delivery verified'
}


function Find-Input([string]$Name) {
    $condition = [System.Windows.Automation.AndCondition]::new(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, $Name),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::IsKeyboardFocusableProperty, $true)
    )
    return $script:window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}
function Set-Number([string]$Name, [int]$Value) {
    $inputControl = Find-Input $Name
    if (-not $inputControl -or -not $inputControl.Current.IsEnabled) { throw "Number input unavailable: $Name" }
    $pattern = $null
    if ($inputControl.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) {
        $pattern.SetValue([string]$Value)
    } elseif ($inputControl.TryGetCurrentPattern([System.Windows.Automation.RangeValuePattern]::Pattern, [ref]$pattern)) {
        $pattern.SetValue([double]$Value)
    } else { throw "Number input value pattern unavailable: $Name" }
}
function Checkbox-Is([string]$Name, [bool]$Enabled) {
    $control = Find-Input $Name
    if (-not $control -or -not $control.Current.IsEnabled) { return $false }
    $pattern = $null
    if (-not $control.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$pattern)) {
        throw "Checkbox toggle pattern unavailable: $Name"
    }
    $wanted = [System.Windows.Automation.ToggleState]::Off
    if ($Enabled) { $wanted = [System.Windows.Automation.ToggleState]::On }
    return $pattern.Current.ToggleState -eq $wanted
}
function Check-DefaultCheckbox([string]$Name, [string]$Failure) {
    try { Wait-Check { Checkbox-Is $Name $false } 15 $Failure }
    catch {
        $control = Find-Input $Name
        $pattern = $null
        $hasToggle = $null -ne $control -and $control.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$pattern)
        $runKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run')
        $runKeyExists = $null -ne $runKey
        if ($runKey) { $runKey.Dispose() }
        $diagnostic = @{ controlPresent = $null -ne $control; controlEnabled = $null -ne $control -and $control.Current.IsEnabled
            toggleSupported = $hasToggle; toggleOff = $hasToggle -and $pattern.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::Off
            runKeyExists = $runKeyExists; appRegistrationExists = $null -ne (Registered-Command)
            autostartErrorVisible = (UI-Contains 'Scarlett could not update the login setting')
            interactive = [Environment]::UserInteractive; realProviderJobs = 0 }
        New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
        $diagnostic | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-preference-default-failure.json')
        Write-Output ($diagnostic | ConvertTo-Json -Compress)
        throw
    }
}
function Set-Checkbox([string]$Name, [bool]$Enabled) {
    Wait-Check { (Find-Input $Name).Current.IsEnabled } 15 "Checkbox unavailable: $Name"
    if (Checkbox-Is $Name $Enabled) { return }
    $pattern = $null
    if (-not (Find-Input $Name).TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$pattern)) {
        throw "Checkbox toggle pattern unavailable: $Name"
    }
    $pattern.Toggle()
    Wait-Check { Checkbox-Is $Name $Enabled } 15 "Checkbox did not update: $Name"
}
function Saved-Preferences([int]$Port, [bool]$Background) {
    $path = Join-Path $state 'preferences.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
    $stream = $null
    $reader = $null
    try {
        # Observe one complete file without blocking the helper's atomic rename.
        $sharing = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $stream = [System.IO.FileStream]::new($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $sharing)
        $reader = [System.IO.StreamReader]::new($stream)
        $saved = $reader.ReadToEnd() | ConvertFrom-Json
    } catch {
        $failure = $_.Exception
        while (($failure -is [System.Management.Automation.MethodInvocationException] -or
            $failure -is [System.Reflection.TargetInvocationException]) -and $null -ne $failure.InnerException) {
            $failure = $failure.InnerException
        }
        # HRESULT_FROM_WIN32 for sharing/lock violations (32/33) alone defers
        # observation; the bounded wait still requires exact persisted values.
        if ($failure -is [System.IO.IOException] -and
            $failure.HResult -in @(-2147024864, -2147024863)) { return $false }
        throw
    } finally {
        try { if ($null -ne $reader) { $reader.Dispose() } }
        finally { if ($null -ne $stream) { $stream.Dispose() } }
    }
    return $saved.schema -eq 1 -and $saved.local_api_port -eq $Port -and $saved.background -eq $Background
}
function Close-Window {
    $pattern = $null
    if (-not $script:window.TryGetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern, [ref]$pattern)) {
        throw 'Native window close pattern unavailable'
    }
    $pattern.Close()
}
function Wait-PreferenceSave([int]$Port, [bool]$Background) {
    # A persisted file precedes the Rust in-memory update and IPC completion.
    # Close only after the app acknowledges the requested mode, not merely its file.
    Wait-Check { Saved-Preferences $Port $Background } 15 'Device preferences were not saved privately'
    $message = if ($Background) {
        'Preferences saved. Closing the window keeps Scarlett running'
    } else {
        'Preferences saved. Closing the window quits Scarlett'
    }
    Wait-Check {
        $condition = [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, $message)
        $acknowledgment = $script:window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        $save = Find-Button 'Save device preferences'
        return $null -ne $acknowledgment -and $null -ne $save -and $save.Current.IsEnabled
    } 15 'App did not acknowledge the completed preference save'
}
function Registered-Command {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run')
    if (-not $key) { return $null }
    try { return $key.GetValue('Scarlett Node', $null) } finally { $key.Dispose() }
}
function Check-Preferences {
    if ($null -ne (Registered-Command)) { throw 'Clean runner already has a Scarlett login registration' }
    Start-App
    Open-Disclosure 'Device settings'
    Check-DefaultCheckbox 'Keep running when the window closes' 'Background mode was not opt-in'
    Check-DefaultCheckbox 'Open Scarlett when I log in' 'Start at login was not opt-in'
    Set-Number 'Saved local API port' 18088
    Click-Button 'Save device preferences'
    Wait-PreferenceSave 18088 $false
    $script:apiPort = 18088
    if ((Api-Status '/health') -ne 0) { throw 'Preferences test port is already occupied' }
    Click-Button 'Start local API'
    Wait-Check { (Api-Status '/health') -eq 200 } 30 'Saved port did not start the local API'
    Close-Window
    if (-not $application.WaitForExit(135000)) { throw 'Default window close did not quit' }
    Wait-Check { (Api-Status '/health') -eq 0 } 30 'Default window close left the API running'
    Write-Output 'Installed preferences: default close drained and saved port passed'

    Start-App
    Open-Disclosure 'Device settings'
    if ((Api-Status '/health') -ne 0) { throw 'Opening the app automatically started the API' }
    # Enabling the actual OS registration must quote the installed path with
    # spaces and include no provider/node/API arguments.
    Set-Checkbox 'Open Scarlett when I log in' $true
    $script:ownsLoginRegistration = $true
    $expectedCommand = '"' + $executable + '"'
    Wait-Check { (Registered-Command) -ceq $expectedCommand } 15 'Windows login command was not one quoted app executable'
    Click-Button 'Start local API'
    Wait-Check { (Api-Status '/health') -eq 200 } 30 'Saved API port did not survive reopening'
    Focus-QuitShortcut
    Check-QuitShortcut 'Preferences app Quit did not exit'
    Wait-Check { (Api-Status '/health') -eq 0 } 30 'Preferences Quit left API running'
    Start-App
    Open-Disclosure 'Device settings'
    if (-not (Checkbox-Is 'Open Scarlett when I log in' $true)) { throw 'Native login registration did not survive app reopening' }
    if ((Api-Status '/health') -ne 0) { throw 'Registered app opening automatically started API' }
    Set-Checkbox 'Open Scarlett when I log in' $false
    Wait-Check { $null -eq (Registered-Command) } 15 'Disabling login left the native registration'
    $script:ownsLoginRegistration = $false
    Write-Output 'Installed preferences: quoted native login enable/read-back/disable passed'

    Set-Checkbox 'Keep running when the window closes' $true
    Click-Button 'Save device preferences'
    Wait-PreferenceSave 18088 $true
    Click-Button 'Start local API'
    Wait-Check { (Api-Status '/health') -eq 200 } 30 'Background test API did not start'
    $originalProcess = $application.Id
    Close-Window
    Start-Sleep -Seconds 3
    $application.Refresh()
    if ($application.HasExited -or (Api-Status '/health') -ne 200) { throw 'Background close stopped the app or API' }
    $reopen = Start-Process -FilePath $executable -WorkingDirectory $install -PassThru
    if (-not $reopen.WaitForExit(15000)) { $reopen.Kill(); throw 'Single-instance reopening launched a second desktop' }
    Wait-AppWindow
    Open-Disclosure 'Device settings'
    if ($application.Id -ne $originalProcess -or (Api-Status '/health') -ne 200) { throw 'Reopening did not retain the same background app and API' }
    Set-Checkbox 'Keep running when the window closes' $false
    Click-Button 'Save device preferences'
    Wait-PreferenceSave 18088 $false
    Close-Window
    if (-not $application.WaitForExit(135000)) { throw 'Restored default close did not exit' }
    Wait-Check { (Api-Status '/health') -eq 0 } 30 'Restored default close left API running'
    @{
        savedPort = 'passed'; defaultCloseDrain = 'passed'; backgroundClose = 'passed'
        singleInstanceReopen = 'passed'; quotedLoginCommand = 'passed'; nativeLoginRegistration = 'passed'
        loginReadBack = 'passed'; loginDisable = 'passed'; actualOSLogin = 'not tested'
        realProviderJobs = 0; backgroundRestored = $false; loginRestored = $false
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-preferences-ui.json')
}

function Click-Control([System.Windows.Automation.AutomationElement]$Control) {
    $handle = $application.MainWindowHandle
    $scroll = $null
    $click = @{ point = [System.Windows.Point]::new(0.0, 0.0); pointAvailable = $false; nativeAttempted = $false }
    $stage = 1
    [ScarlettAcceptanceWindow]::ResetInputDiagnostics()
    try {
        # A restored client window plus native chrome can exceed the runner's
        # work area. Normalize the owned window before scrolling its controls.
        [ScarlettAcceptanceWindow]::ShowWindow($handle, 3) | Out-Null
        [ScarlettAcceptanceWindow]::SetForegroundWindow($handle) | Out-Null
        Wait-Check {
            return [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle -and
                [ScarlettAcceptanceWindow]::IsZoomed($handle)
        } 10 'Installed control did not acquire a maximized foreground window'
        if ($Control.TryGetCurrentPattern([System.Windows.Automation.ScrollItemPattern]::Pattern, [ref]$scroll)) {
            $scroll.ScrollIntoView()
        }
        $Control.SetFocus()
        Wait-Check {
            return [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle
        } 10 'Installed control did not acquire foreground input'
        $stage = 2
        Wait-Check {
            if ([ScarlettAcceptanceWindow]::GetForegroundWindow() -ne $handle -or
                -not [ScarlettAcceptanceWindow]::IsZoomed($handle)) { return $false }
            $point = [System.Windows.Point]::new(0.0, 0.0)
            if (-not $Control.TryGetClickablePoint([ref]$point)) { return $false }
            $click.point = $point
            $click.pointAvailable = $true
            if ([double]::IsNaN($point.X) -or [double]::IsNaN($point.Y) -or
                [double]::IsInfinity($point.X) -or [double]::IsInfinity($point.Y)) { return $false }
            if (-not $Control.Current.IsEnabled -or $Control.Current.IsOffscreen -or
                -not $Control.Current.BoundingRectangle.Contains($point)) { return $false }
            $pointX, $pointY = [int]$point.X, [int]$point.Y
            if (-not [ScarlettAcceptanceWindow]::PointInDesktop($pointX, $pointY) -or
                -not [ScarlettAcceptanceWindow]::PointOwnedByWindow($handle, $pointX, $pointY)) { return $false }
            $physical = [ScarlettAcceptanceWindow]::PhysicalPointContext($handle, $pointX, $pointY)
            if ($physical[0] -and -not $physical[3]) { throw 'Native click did not restore caller DPI awareness' }
            if (-not $physical[0] -or -not $physical[1] -or -not $physical[2]) { return $false }
            return $true
        } 10 'Installed control did not expose an owned on-screen click point'
        $stage = 3
        $x, $y = [int]$click.point.X, [int]$click.point.Y
        $click.nativeAttempted = $true
        [ScarlettAcceptanceWindow]::Click($x, $y)
    } catch {
        $originalFailure = $_
        # Fixed enum, booleans and native counts only. Never coordinates, UI names,
        # values, window titles, exception messages or password readback.
        $diagnostic = @{ clickFailureStage = $stage; nativeFailure = [string][ScarlettAcceptanceWindow]::LastNativeFailure
            nativeClickAttempted = $click.nativeAttempted; inputExpectedCount = [ScarlettAcceptanceWindow]::LastInputExpected
            inputAcceptedCount = [ScarlettAcceptanceWindow]::LastInputAccepted; inputLastError = [ScarlettAcceptanceWindow]::LastInputError
            controlStateAvailable = $false; controlEnabled = $false; controlFocused = $false
            controlOffscreen = $false; controlPassword = $false; controlSameProcess = $false
            scrollSupported = $null -ne $scroll; pointAvailable = $click.pointAvailable; pointFinite = $false
            pointDiagnosticsAvailable = $false; pointInsideControl = $false; pointInDesktop = $false; pointWindowOwned = $false
            physicalContextAvailable = $false; physicalContextRestored = $false
            pointOnPhysicalMonitor = $false; windowOnPhysicalMonitor = $false
            foregroundOwned = $false; windowMaximized = $false; modifiersReleased = $false; webViewNativeInputFocus = $false
            accessibilityWindowNativeFocus = $false; threadDpiContextKnown = $false; threadDpiUnaware = $false
            threadDpiSystemAware = $false; threadDpiPerMonitorAware = $false; windowDpiKnown = $false
            windowAbove96Dpi = $false; realProviderJobs = 0 }
        try {
            $diagnostic.controlEnabled = $Control.Current.IsEnabled
            $diagnostic.controlFocused = $Control.Current.HasKeyboardFocus
            $diagnostic.controlOffscreen = $Control.Current.IsOffscreen
            $diagnostic.controlPassword = $Control.Current.IsPassword
            $diagnostic.controlSameProcess = $Control.Current.ProcessId -eq $script:window.Current.ProcessId
            $diagnostic.controlStateAvailable = $true
            $diagnostic.pointFinite = $click.pointAvailable -and -not [double]::IsNaN($click.point.X) -and
                -not [double]::IsNaN($click.point.Y) -and -not [double]::IsInfinity($click.point.X) -and
                -not [double]::IsInfinity($click.point.Y)
            if ($diagnostic.pointFinite) {
                $diagnostic.pointInsideControl = $Control.Current.BoundingRectangle.Contains($click.point)
                $diagnostic.pointInDesktop = [ScarlettAcceptanceWindow]::PointInDesktop([int]$click.point.X, [int]$click.point.Y)
                $diagnostic.pointWindowOwned = [ScarlettAcceptanceWindow]::PointOwnedByWindow($handle, [int]$click.point.X, [int]$click.point.Y)
                $diagnostic.pointDiagnosticsAvailable = $true
                $physical = [ScarlettAcceptanceWindow]::PhysicalPointContext($handle, [int]$click.point.X, [int]$click.point.Y)
                $diagnostic.physicalContextAvailable = $physical[0]
                $diagnostic.pointOnPhysicalMonitor = $physical[1]
                $diagnostic.windowOnPhysicalMonitor = $physical[2]
                $diagnostic.physicalContextRestored = $physical[3]
            }
        } catch { }
        try {
            $diagnostic.foregroundOwned = [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle
            $diagnostic.windowMaximized = [ScarlettAcceptanceWindow]::IsZoomed($handle)
            $diagnostic.modifiersReleased = [ScarlettAcceptanceWindow]::ModifiersReleased()
            $diagnostic.webViewNativeInputFocus = [ScarlettAcceptanceWindow]::WebViewHasInputFocus($handle)
            $diagnostic.accessibilityWindowNativeFocus = [ScarlettAcceptanceWindow]::AccessibilityWindowFocused($handle)
            $awareness = [ScarlettAcceptanceWindow]::ThreadDpiAwareness()
            $diagnostic.threadDpiContextKnown = $awareness -in @(0, 1, 2)
            $diagnostic.threadDpiUnaware = $awareness -eq 0
            $diagnostic.threadDpiSystemAware = $awareness -eq 1
            $diagnostic.threadDpiPerMonitorAware = $awareness -eq 2
            $dpi = [ScarlettAcceptanceWindow]::WindowDpi($handle)
            $diagnostic.windowDpiKnown = $dpi -gt 0
            $diagnostic.windowAbove96Dpi = $dpi -gt 96
        } catch { }
        Write-Output ($diagnostic | ConvertTo-Json -Compress)
        try {
            New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
            $diagnostic | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-click-input-failure.json')
        } catch { }
        throw $originalFailure
    }
}

function Input-Advanced([string]$Name, [string]$NextName, [IntPtr]$Handle, [hashtable]$Diagnostic = $null) {
    $source = Find-Input $Name
    $sourcePresent = $null -ne $source
    $sourceFocused = $sourcePresent -and $source.Current.HasKeyboardFocus
    $foregroundOwned = [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $Handle
    $condition = [System.Windows.Automation.AndCondition]::new(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, $NextName),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::IsKeyboardFocusableProperty, $true)
    )
    $matches = $script:window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
    $focusedCount = 0
    $focused = [System.Windows.Automation.AutomationElement]::FocusedElement
    if ($null -ne $Diagnostic) {
        $Diagnostic.sourcePresent = $sourcePresent
        $Diagnostic.sourceFocused = $sourceFocused
        $Diagnostic.sourceOffscreen = $sourcePresent -and $source.Current.IsOffscreen
        $Diagnostic.foregroundOwned = $foregroundOwned
        $Diagnostic.successorPresent = $matches.Count -gt 0
        $Diagnostic.successorEnabled = $false
        $Diagnostic.successorFocused = $false
        $Diagnostic.successorSameProcess = $false
        $Diagnostic.successorActualFocusMatches = $false
    }
    foreach ($match in $matches) {
        $enabled = $match.Current.IsEnabled
        $hasFocus = $match.Current.HasKeyboardFocus
        $sameProcess = $sourcePresent -and $match.Current.ProcessId -eq $source.Current.ProcessId
        $actualFocusMatches = $null -ne $focused -and [System.Windows.Automation.Automation]::Compare($match, $focused)
        if ($null -ne $Diagnostic) {
            $Diagnostic.successorEnabled = $Diagnostic.successorEnabled -or $enabled
            $Diagnostic.successorFocused = $Diagnostic.successorFocused -or $hasFocus
            $Diagnostic.successorSameProcess = $Diagnostic.successorSameProcess -or ($hasFocus -and $sameProcess)
            $Diagnostic.successorActualFocusMatches = $Diagnostic.successorActualFocusMatches -or $actualFocusMatches
        }
        if ($enabled -and $hasFocus -and $sameProcess -and $actualFocusMatches) { $focusedCount++ }
    }
    # Require exactly one reviewed successor to own actual keyboard focus.
    if ($null -ne $Diagnostic) { $Diagnostic.successorUniqueFocused = $focusedCount -eq 1 }
    return $sourcePresent -and -not $sourceFocused -and $foregroundOwned -and $focusedCount -eq 1
}

function Wait-InputAdvanced([string]$Name, [string]$NextName, [IntPtr]$Handle, [bool]$Clearing, [string]$Failure) {
    try { Wait-Check { Input-Advanced $Name $NextName $Handle } 10 $Failure }
    catch {
        $originalFailure = $_
        $diagnostic = @{ clearAcknowledgmentFailed = $Clearing; textAcknowledgmentFailed = -not $Clearing
            realProviderJobs = 0 }
        try { Input-Advanced $Name $NextName $Handle $diagnostic | Out-Null } catch { }
        New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
        $diagnostic | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-input-focus-failure.json')
        Write-Output ($diagnostic | ConvertTo-Json -Compress)
        throw $originalFailure
    }
}

function Set-Text([string]$Name, [string]$Value, [string]$NextName) {
    # All inputs are disposable fixtures, never real credentials. Use one native
    # text/Tab stream and acknowledge focus changes instead of SendKeys timing.
    if ($Value -notmatch '^[a-z0-9-]+$' -or $Value.Length -gt 512) { throw 'Synthetic input contains unsupported characters' }
    if (-not (($Name -eq 'Local X account ID' -and $NextName -in @('Browser profile', 'auth_token')) -or
        ($Name -eq 'auth_token' -and $NextName -eq 'ct0') -or
        ($Name -eq 'ct0' -and $NextName -eq 'Connect X'))) { throw 'Synthetic input requires its reviewed successor control' }
    Wait-Check { (Find-Input $Name).Current.IsEnabled } 15 "Text input did not become ready: $Name"
    Wait-Check { (Find-Input $NextName).Current.IsEnabled } 15 "Synthetic input successor did not become ready: $NextName"
    $control = Find-Input $Name
    if (-not $control -or -not $control.Current.IsEnabled) { throw "Text input unavailable: $Name" }
    $handle = $application.MainWindowHandle
    Click-Control $control
    Wait-KeyboardTarget $control $handle 'Synthetic input did not acquire keyboard focus'
    [ScarlettAcceptanceWindow]::SelectAllClearAndTab()
    # An initially empty value is not evidence that queued clear events ran.
    Wait-InputAdvanced $Name $NextName $handle $true 'Synthetic clear input was not acknowledged by successor focus'
    if (-not $control.Current.IsPassword) {
        Wait-Check {
            $current = Find-Input $Name
            $pattern = $null
            return $null -ne $current -and $current.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern) -and
                $pattern.Current.Value -ceq ''
        } 10 'Synthetic input did not clear before typing'
    }
    $control = Find-Input $Name
    Click-Control $control
    Wait-KeyboardTarget $control $handle 'Synthetic input did not reacquire keyboard focus'
    [ScarlettAcceptanceWindow]::UnicodeTextAndTab($Value)
    Wait-InputAdvanced $Name $NextName $handle $false 'Synthetic text input was not acknowledged by successor focus'
    # Masked cookie fields may refuse value readback. Submission is checked
    # separately through a local duplicate-nickname rejection, without X I/O.
    if (-not $control.Current.IsPassword) {
        try {
            Wait-Check {
                $current = Find-Input $Name
                $pattern = $null
                return $null -ne $current -and $current.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern) -and
                    ([string]$pattern.Current.Value) -ceq $Value
            } 10 'Synthetic text value did not commit'
        } catch {
            $current = Find-Input $Name
            $pattern = $null
            $available = $null -ne $current -and $current.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)
            $observed = ''
            if ($available -and -not $current.Current.IsPassword) { $observed = [string]$pattern.Current.Value }
            $diagnostic = @{ controlPresent = $null -ne $current; controlFocused = $null -ne $current -and $current.Current.HasKeyboardFocus
                foregroundOwned = [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle
                valuePatternAvailable = $available; expectedLength = $Value.Length; observedLength = $observed.Length
                valueMatches = $observed -ceq $Value; realProviderJobs = 0 }
            New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
            $diagnostic | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-text-input-failure.json')
            Write-Output ($diagnostic | ConvertTo-Json -Compress)
            $observed = $null
            throw
        }
    }
}
function Select-Browser([int]$Index, [string]$ExpectedBrowser) {
    if ($Index -notin @(1, 2) -or $ExpectedBrowser -notin @('Chrome', 'Firefox')) { throw 'Unexpected synthetic browser selection' }
    Wait-Check { (Find-Input 'Browser profile').Current.IsEnabled } 15 'Browser chooser did not become ready'
    $target = Find-Input 'Browser profile'
    if (-not $target -or -not $target.Current.IsEnabled) { throw 'Browser chooser unavailable' }
    $handle = $application.MainWindowHandle
    [ScarlettAcceptanceWindow]::ShowWindow($handle, 9) | Out-Null
    [ScarlettAcceptanceWindow]::SetForegroundWindow($handle) | Out-Null
    $target.SetFocus()
    Wait-KeyboardTarget $target $handle 'Browser chooser did not acquire input focus'
    [System.Windows.Forms.SendKeys]::SendWait('{HOME}')
    # PowerShell variable names are case-insensitive; the loop counter must
    # not overwrite the requested Index before sending its navigation keys.
    for ($step = 0; $step -lt $Index; $step++) { [System.Windows.Forms.SendKeys]::SendWait('{DOWN}') }
    # Commit the native select before clicking consent. Keyboard navigation can
    # leave a preview choice in the popup; consent belongs to the committed
    # profile and must not race its change event.
    [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
    [System.Windows.Forms.SendKeys]::SendWait('{TAB}')
    $readback = @{ controlPresent = $false; valuePattern = $false; valueMatches = $false
        selectionPattern = $false; selectedItemCount = 0; selectedLabelMatches = $false }
    try {
        Wait-Check {
            $selected = Find-Input 'Browser profile'
            $readback.controlPresent = $null -ne $selected
            if (-not $selected) { return $false }
            $value = $null
            $readback.valuePattern = $selected.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$value)
            # WebView2 can expose ValuePattern with an empty/null value. Read the
            # selection provider too rather than dereferencing a null string.
            $readback.valueMatches = $readback.valuePattern -and ([string]$value.Current.Value).Contains($ExpectedBrowser)
            if ($readback.valueMatches) { return $true }
            $selection = $null
            $readback.selectionPattern = $selected.TryGetCurrentPattern([System.Windows.Automation.SelectionPattern]::Pattern, [ref]$selection)
            if ($readback.selectionPattern) {
                $items = @($selection.Current.GetSelection())
                $readback.selectedItemCount = $items.Count
                $readback.selectedLabelMatches = $items.Count -eq 1 -and $null -ne $items[0] -and
                    ([string]$items[0].Current.Name).Contains($ExpectedBrowser)
                return $readback.selectedLabelMatches
            }
            return $false
        } 10 'Synthetic browser selection did not commit'
    } catch {
        # Fixed booleans/counts only: never publish browser names, opaque ids or
        # any session values read through the accessibility provider.
        New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
        $readback | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-browser-selection-failure.json')
        Write-Output ($readback | ConvertTo-Json -Compress)
        throw
    }
}
function UI-Contains([string]$Text) {
    $elements = $script:window.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
    foreach ($element in $elements) { if (([string]$element.Current.Name).Contains($Text)) { return $true } }
    return $false
}
function Imported-Accounts {
    # Tauri resolves its native app-data directory; browser helpers use the
    # explicitly redirected APPDATA roots. Accommodate either OS resolution.
    $candidates = @($state, (Join-Path $script:fixture.roaming 'ai.scarlett.node')) | Select-Object -Unique
    $registries = @($candidates | Where-Object { Test-Path -LiteralPath (Join-Path $_ 'accounts.json') -PathType Leaf })
    if ($registries.Count -eq 0) { return @() }
    if ($registries.Count -ne 1) { throw 'Browser acceptance has ambiguous account state' }
    $script:importState = $registries[0]
    return @(([System.IO.File]::ReadAllText((Join-Path $script:importState 'accounts.json')) | ConvertFrom-Json).accounts)
}
function Invoke-SyntheticAccountCommand([string[]]$Arguments) {
    $stateBefore, $accountsBefore = $env:SCARLETT_STATE_DIR, $env:SCARLETT_ACCOUNTS_FILE
    try {
        $env:SCARLETT_STATE_DIR, $env:SCARLETT_ACCOUNTS_FILE = $script:importState, (Join-Path $script:importState 'accounts.json')
        $raw = & (Join-Path $install 'scarlett-node.exe') accounts @Arguments | Out-String
        if ($LASTEXITCODE -ne 0) { throw 'Installed helper refused its private synthetic account fixture' }
        return $raw
    } finally { $env:SCARLETT_STATE_DIR, $env:SCARLETT_ACCOUNTS_FILE = $stateBefore, $accountsBefore }
}
function Check-SyntheticAccounts([string[]]$IDs) {
    $registry = @(Imported-Accounts)
    $inventory = Invoke-SyntheticAccountCommand @('list')
    # Grouping enumerates the parsed array on both Windows PowerShell 5.1 and 7.
    $listed = @(($inventory | ConvertFrom-Json))
    foreach ($records in @($registry, $listed)) {
        if ($records.Count -ne $IDs.Count) { throw 'Synthetic account inventory count differs from its private registry' }
        foreach ($id in $IDs) {
            if (@($records | Where-Object { $_.service -ceq 'x_read' -and $_.id -ceq $id }).Count -ne 1) {
                throw 'Synthetic account inventory differs from its private registry'
            }
        }
    }
    $credentialRoot = [System.IO.Path]::GetFullPath((Join-Path $script:importState 'accounts')).TrimEnd('\') + '\'
    foreach ($record in $registry) {
        if (-not [System.IO.Path]::GetFullPath($record.path).StartsWith($credentialRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Synthetic credential escaped disposable app state'
        }
        $session = [System.IO.File]::ReadAllText($record.path) | ConvertFrom-Json
        if (@($session.PSObject.Properties).Count -ne 2 -or
            $session.auth_token -cne $script:fixture.authToken -or $session.ct0 -cne $script:fixture.csrf) {
            throw 'Private synthetic session differs from its fixture fields'
        }
    }
    if ($inventory.Contains($script:fixture.authToken) -or $inventory.Contains($script:fixture.csrf) -or
        (UI-Contains $script:fixture.authToken) -or (UI-Contains $script:fixture.csrf)) {
        throw 'Synthetic account inventory exposed fixture credentials'
    }
}
function Check-SyntheticRemoval {
    $registryPath = Join-Path $script:importState 'accounts.json'
    $removed = @(Imported-Accounts | Where-Object { $_.id -ceq 'removal-fixture' })
    if ($removed.Count -ne 1) { throw 'Removal acceptance requires its own synthetic account' }
    $credentialPath = $removed[0].path
    $credentialHash = (Get-FileHash -LiteralPath $credentialPath -Algorithm SHA256).Hash
    $before = (Get-FileHash -LiteralPath $registryPath -Algorithm SHA256).Hash
    foreach ($cancel in @('Keep', 'Escape')) {
        Click-Button 'Remove'
        Wait-Check { UI-Contains 'Remove X account removal-fixture?' } 10 'Removal dialog selected another account'
        Wait-Check { (Find-Button 'Keep account').Current.HasKeyboardFocus } 10 'Removal dialog did not default to Keep account'
        if ($cancel -eq 'Keep') { Click-Button 'Keep account' }
        else {
            $keep = Find-Button 'Keep account'
            Wait-KeyboardTarget $keep $application.MainWindowHandle 'Removal cancellation did not have native input focus'
            [ScarlettAcceptanceWindow]::Escape()
        }
        Wait-Check { $keep = Find-Button 'Keep account'; $null -eq $keep -or $keep.Current.IsOffscreen } 10 'Removal cancellation left the dialog open'
        if ((Get-FileHash -LiteralPath $registryPath -Algorithm SHA256).Hash -cne $before -or
            (Get-FileHash -LiteralPath $credentialPath -Algorithm SHA256).Hash -cne $credentialHash) {
            throw 'Cancelled removal changed private synthetic state'
        }
        Check-SyntheticAccounts @('removal-fixture', 'browser-firefox', 'browser-paste')
    }
    Click-Button 'Remove'
    Wait-Check { UI-Contains 'Remove X account removal-fixture?' } 10 'Removal confirmation selected another account'
    Click-Button 'Remove account'
    Wait-Check { @(Imported-Accounts).Count -eq 2 -and -not (UI-Contains ('X ' + [char]0x00B7 + ' removal-fixture')) } 15 'Confirmed removal did not update the registry and installed UI'
    Check-SyntheticAccounts @('browser-firefox', 'browser-paste')
    if ((Get-FileHash -LiteralPath $credentialPath -Algorithm SHA256).Hash -cne $credentialHash) { throw 'Removal changed retained credential bytes' }
    $after = (Get-FileHash -LiteralPath $registryPath -Algorithm SHA256).Hash
    $ack = Invoke-SyntheticAccountCommand @('remove', 'x_read', 'removal-fixture') | ConvertFrom-Json
    if ($ack.status -cne 'updated' -or
        (Get-FileHash -LiteralPath $registryPath -Algorithm SHA256).Hash -cne $after -or
        (Get-FileHash -LiteralPath $credentialPath -Algorithm SHA256).Hash -cne $credentialHash) {
        throw 'Repeated removal changed private synthetic state'
    }
    Click-Button 'Quit Scarlett'
    if (-not $application.WaitForExit(135000)) { throw 'Removal acceptance app did not quit' }
    Start-App
    Wait-Check { (UI-Contains ('X ' + [char]0x00B7 + ' browser-firefox')) -and (UI-Contains ('X ' + [char]0x00B7 + ' browser-paste')) } 15 'Restart lost the retained synthetic accounts'
    if (UI-Contains ('X ' + [char]0x00B7 + ' removal-fixture')) { throw 'Removed synthetic account returned after restart' }
    Check-SyntheticAccounts @('browser-firefox', 'browser-paste')
    @{
        keepCancellation = 'passed'; escapeCancellation = 'passed'; defaultKeepFocus = 'passed'
        confirmedRemoval = 'passed'; registryAndInstalledHelperReadback = 'passed'; retainedCredentials = 'passed'
        repeatedRemoval = 'passed'; restartPersistence = 'passed'; privateSeededInventory = $true
        realAccountLoginTested = $false; realProviderJobs = 0; providerAuthenticationRequests = 0
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-account-removal-ui.json')
}
function Check-BrowserImport {
    $root = [System.IO.Path]::GetFullPath((Split-Path -Parent $BrowserFixture))
    $temporary = [System.IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    if (-not $root.StartsWith($temporary, [StringComparison]::OrdinalIgnoreCase)) { throw 'Browser fixtures must be below the disposable runner directory' }
    $script:fixture = [System.IO.File]::ReadAllText($BrowserFixture) | ConvertFrom-Json
    if (-not $script:fixture.syntheticOnly) { throw 'Browser acceptance requires synthetic fixtures' }
    foreach ($path in @($script:fixture.roaming, $script:fixture.local) + @($script:fixture.stores | ForEach-Object { $_.path })) {
        if (-not [System.IO.Path]::GetFullPath($path).StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Browser fixture escaped its isolated home' }
    }
    foreach ($store in $script:fixture.stores) {
        if ((Get-FileHash -LiteralPath $store.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $store.sha256) { throw 'Browser fixture changed before preparation' }
    }
    # An incomplete Firefox session exercises the installed native cookie reader
    # and its fixed error before Viewer. Successful extraction has source tests;
    # complete fake credentials must never reach production authentication.
    $firefox = @($script:fixture.stores | Where-Object { [IO.Path]::GetFileName($_.path) -ceq 'cookies.sqlite' })
    if ($firefox.Count -ne 1) { throw 'Expected one isolated Firefox store' }
    $prepareIncomplete = @'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db:
    db.execute('DELETE FROM moz_cookies WHERE name = ?', ('ct0',))
'@
    & $script:pythonExe -c $prepareIncomplete $firefox[0].path
    if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the offline Firefox rejection fixture' }
    $firefox[0].sha256 = (Get-FileHash -LiteralPath $firefox[0].path -Algorithm SHA256).Hash.ToLowerInvariant()
    $roamingBefore, $localBefore = $env:APPDATA, $env:LOCALAPPDATA
    try {
        $env:APPDATA, $env:LOCALAPPDATA = $script:fixture.roaming, $script:fixture.local
        Start-App
        Open-Disclosure 'Add account'
        Open-Disclosure 'Import an X session'
        Wait-Check { (Find-Input 'Browser profile').Current.IsEnabled } 15 'Isolated browser profiles were not discovered'
        if (@(Imported-Accounts).Count -ne 0) { throw 'Browser test encountered existing accounts' }
        if (-not (Checkbox-Is 'Import only X session cookies from this profile' $false) -or (Find-Button 'Import X account').Current.IsEnabled) { throw 'Browser import did not require opt-in consent' }
        Select-Browser 1 'Chrome'
        Set-Checkbox 'Import only X session cookies from this profile' $true
        Wait-Check { (Find-Button 'Import X account').Current.IsEnabled } 10 'Consent did not enable import'
        Select-Browser 2 'Firefox'
        Wait-Check { Checkbox-Is 'Import only X session cookies from this profile' $false } 10 'Changing profile retained consent'
        Wait-Check { -not (Find-Button 'Import X account').Current.IsEnabled } 10 'Profile change allowed import without new consent'
        Verify-KeyboardDelivery
        Set-Text 'Local X account ID' 'incomplete-firefox' 'Browser profile'
        Set-Checkbox 'Import only X session cookies from this profile' $true
        Click-Button 'Import X account'
        Wait-Check { UI-Contains 'No complete X session was found in that profile' } 45 'Installed Firefox reader did not reject the incomplete synthetic session'
        if (@(Imported-Accounts).Count -ne 0) { throw 'Incomplete Firefox import saved an account' }
        Select-Browser 1 'Chrome'
        Set-Text 'Local X account ID' 'protected-chrome' 'Browser profile'
        Set-Checkbox 'Import only X session cookies from this profile' $true
        Click-Button 'Import X account'
        Wait-Check { UI-Contains 'The browser or OS protected this profile' } 20 'Protected Chrome did not show the paste fallback'
        if (@(Imported-Accounts).Count -ne 0) { throw 'Protected Chrome import saved an account' }
        Click-Button 'Quit Scarlett'
        if (-not $application.WaitForExit(135000)) { throw 'Browser acceptance app did not quit before fixture seeding' }
        # Resolve the app-owned home actually used by the two failed imports.
        $homes = @(@($state, (Join-Path $script:fixture.roaming 'ai.scarlett.node')) | Select-Object -Unique |
            Where-Object { Test-Path -LiteralPath (Join-Path $_ 'accounts') -PathType Container })
        if ($homes.Count -ne 1) { throw 'Synthetic account fixture has ambiguous app-owned storage' }
        $script:importState = $homes[0]
        $records = @()
        foreach ($id in @('removal-fixture', 'browser-firefox', 'browser-paste')) {
            $accountHome = Join-Path (Join-Path $script:importState 'accounts') ('x_read-' + $id)
            $privateOutput = & (Join-Path $install 'scarlett-node.exe') desktop private-dir $accountHome | Out-String
            $privateOutput = $null
            if ($LASTEXITCODE -ne 0) { throw 'Could not create private synthetic account directory' }
            $session = Join-Path $accountHome 'session.json'
            Write-SyntheticPrivateJSON $session @{ auth_token = $script:fixture.authToken; ct0 = $script:fixture.csrf }
            $records += @{ id = $id; service = 'x_read'; path = $session; concurrency = 1 }
        }
        Write-SyntheticPrivateJSON (Join-Path $script:importState 'accounts.json') @{ version = 1; accounts = $records }
        Start-App
        Open-Disclosure 'Add account'
        Open-Disclosure 'Import an X session'
        Wait-Check { UI-Contains ('X ' + [char]0x00B7 + ' removal-fixture') } 15 'Installed app did not render its private synthetic inventory'
        Wait-Check { UI-Contains 'access not verified' } 15 'Private synthetic inventory claimed verified access'
        Check-SyntheticAccounts @('removal-fixture', 'browser-firefox', 'browser-paste')
        foreach ($name in @('auth_token', 'ct0')) {
            if (-not (Find-Input $name).Current.IsPassword) { throw 'Cookie paste field was not masked' }
        }
        # This existing nickname is rejected locally before reading the cookies
        # or verifying identity. It proves masked input and native command routing.
        Set-Text 'Local X account ID' 'browser-paste' 'Browser profile'
        Set-Text 'auth_token' $script:fixture.authToken 'ct0'
        Set-Text 'ct0' $script:fixture.csrf 'Connect X'
        $before = (Get-FileHash -LiteralPath (Join-Path $script:importState 'accounts.json') -Algorithm SHA256).Hash
        $sessionHashes = @{}
        foreach ($record in (Imported-Accounts)) { $sessionHashes[$record.path] = (Get-FileHash -LiteralPath $record.path -Algorithm SHA256).Hash }
        Click-Button 'Connect X'
        Wait-Check { UI-Contains 'The node could not complete that action' } 20 'Installed masked paste did not reject the existing local nickname'
        Check-SyntheticAccounts @('removal-fixture', 'browser-firefox', 'browser-paste')
        if ((Get-FileHash -LiteralPath (Join-Path $script:importState 'accounts.json') -Algorithm SHA256).Hash -cne $before) { throw 'Local nickname rejection changed the private registry' }
        foreach ($path in $sessionHashes.Keys) {
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $sessionHashes[$path]) { throw 'Local nickname rejection changed private session bytes' }
        }
        foreach ($store in $script:fixture.stores) {
            if ((Get-FileHash -LiteralPath $store.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $store.sha256) { throw 'Import modified its prepared browser store' }
        }
        Check-SyntheticRemoval
        Click-Button 'Quit Scarlett'
        if (-not $application.WaitForExit(135000)) { throw 'Browser acceptance app did not quit' }
        @{
            redirectedBrowserRoots = 'passed'; profileConsent = 'passed'; consentReset = 'passed'
            firefoxIncompleteSessionRejected = 'passed'; protectedChromeFallback = 'passed'; maskedPasteLocalRejection = 'passed'
            privateSeededInventory = 'passed'; unchangedPreparedBrowserStores = 'passed'; accessUnverified = $true
            successfulIdentityVerificationTested = $false; successfulBrowserExtraction = 'source tests'
            realBrowserAccountsTested = $false; realProviderJobs = 0; providerAuthenticationRequests = 0
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-browser-import-ui.json')
        Write-Output 'Installed browser acceptance: consent, offline reader rejection, protected Chrome and masked local rejection passed'
    } finally {
        $env:APPDATA, $env:LOCALAPPDATA = $roamingBefore, $localBefore
        $script:fixture = $null
    }
}

function Write-SyntheticPrivateJSON([string]$Path, $Value) {
    if (Test-Path -LiteralPath $Path) { throw 'Synthetic identity/journal fixture would overwrite existing state' }
    # The installed helper deliberately accepts only a file named bearer.
    # Create that file in a fresh private sibling directory, replace its
    # test-only bytes, then move it on the same volume to retain its ACL.
    # Capture helper output privately; never log or use it as a credential.
    $staging = $Path + '.fixture-private'
    if (Test-Path -LiteralPath $staging) { throw 'Synthetic fixture staging directory already exists' }
    $privateOutput = & (Join-Path $install 'scarlett-node.exe') desktop private-dir $staging | Out-String
    $privateOutput = $null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create private fixture staging directory' }
    $temporaryFile = Join-Path $staging 'bearer'
    $privateOutput = & (Join-Path $install 'scarlett-node.exe') desktop bearer $temporaryFile | Out-String
    $privateOutput = $null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create private installation fixture' }
    [System.IO.File]::WriteAllText($temporaryFile, ($Value | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::Move($temporaryFile, $Path)
    Remove-Item -LiteralPath $staging -Recurse
}
function Durable-Hashes {
    $files = @('identity.json', 'accounts.json', 'preferences.json', 'local-api/bearer') | ForEach-Object {
        Get-Item -LiteralPath (Join-Path $script:importState $_)
    }
    $files += @(Get-ChildItem -LiteralPath (Join-Path $script:importState 'accounts') -Recurse -File)
    $files += @(Get-ChildItem -LiteralPath (Join-Path $script:importState 'attempts') -Filter '*.json' -File)
    if ($files.Count -gt 256) { throw 'Installation fixture exceeded its file bound' }
    $hashes = @{}
    foreach ($file in $files) {
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -gt 16MB) {
            throw 'Unexpected private installation fixture file'
        }
        $hashes[$file.FullName] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    return $hashes
}
function Node-Probe([string[]]$Arguments, [hashtable]$Environment) {
    # Failure evidence only: exit status, duration and output size. Never record
    # node output; error text is reduced to its fixed node classification.
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path $install 'scarlett-node.exe'
    $start.Arguments = ($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables.Clear()
    foreach ($name in $Environment.Keys) { if ($Environment[$name]) { $start.EnvironmentVariables[$name] = [string]$Environment[$name] } }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $process = [System.Diagnostics.Process]::Start($start)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $exited = $process.WaitForExit(20000)
    if (-not $exited) { $process.Kill(); $process.WaitForExit(5000) | Out-Null }
    $watch.Stop()
    $errorText = [string]$stderr.Result
    $known = @('desktop private storage unavailable', 'invalid private directory', 'state directory must be absolute',
        'accounts directory must be private', 'cannot lock account configuration', 'cannot read private account configuration',
        'invalid local status', 'invalid local account status', 'invalid journal capacity status', 'Access is denied',
        'The process cannot access the file', 'private file', 'requires', 'NTFS')
    $classes = @($known | Where-Object { $errorText.Contains($_) })
    return @{ exited = $exited; exitCode = $(if ($exited) { $process.ExitCode } else { $null })
        milliseconds = $watch.ElapsedMilliseconds; stdoutBytes = ([string]$stdout.Result).Length
        okJSON = ([string]$stdout.Result).Trim() -ceq '{"ok":true}'; stderrBytes = $errorText.Length; stderrClasses = $classes }
}
function Identity-Diagnostics([string]$Name) {
    # The check has already failed; its result stands. Distinguish a late
    # status from none, then record what the app shows and what its node
    # commands do under the desktop's own environment.
    $late = $null
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt 45) {
        if ($null -eq (Find-Button 'Pair node')) { $late = [int]$watch.Elapsed.TotalSeconds; break }
        Start-Sleep -Milliseconds 500
    }
    $statuses = @{}
    foreach ($text in @('Node not installed', 'Not paired', 'Running outside this app', 'Stopped', 'Waiting for node status')) {
        $statuses[$text] = UI-Contains $text
    }
    $notices = @{}
    foreach ($text in @('Scarlett could not open its private local storage', 'The node could not complete that action',
        'The action timed out', 'Scarlett could not complete that action', 'The node or proof helper is missing')) {
        $notices[$text] = UI-Contains $text
    }
    $root = $script:importState
    $base = @{ SystemRoot = $env:SystemRoot; WINDIR = $env:WINDIR }
    $desktop = @{ HOME = $env:HOME; USERPROFILE = $env:USERPROFILE; APPDATA = $env:APPDATA; LOCALAPPDATA = $env:LOCALAPPDATA
        SystemRoot = $env:SystemRoot; WINDIR = $env:WINDIR; TEMP = $env:TEMP; TMP = $env:TMP; TMPDIR = $env:TMPDIR; LANG = $env:LANG
        SCARLETT_STATE_DIR = $root; SCARLETT_ACCOUNTS_FILE = (Join-Path $root 'accounts.json')
        SCARLETT_COORDINATOR = 'https://network.scarlett.ai'; SCARLETT_VERIFIER = 'verifier.scarlett.ai:7047'
        SCARLETT_EXECUTOR = 'services'; SCARLETT_SERVICES = 'codex,x_read'; SCARLETT_PROFILE = 'standard'
        SCARLETT_PROVER = (Join-Path $install 'scarlett-prover.exe')
        SCARLETT_CODEX_HOME = (Join-Path $root 'unused-legacy-codex'); SCARLETT_X_SESSION = (Join-Path $root 'unused-legacy-x.json')
        SCARLETT_CODEX_MANAGED_ROOT = (Join-Path $root 'codex-logins') }
    $diagnostic = @{ check = $Name; recognizedSecondsAfterFailure = $late; statuses = $statuses; notices = $notices
        identityRegular = Test-Path -LiteralPath (Join-Path $root 'identity.json') -PathType Leaf
        appStateIsImportState = [System.IO.Path]::GetFullPath($root) -ieq [System.IO.Path]::GetFullPath($state)
        accountsRendered = UI-Contains 'browser-firefox'; observationRendered = UI-Contains 'jobs in flight'
        appRunning = -not $application.HasExited
        privateDir = Node-Probe @('desktop', 'private-dir', $root) $base
        accounts = Node-Probe @('accounts', 'list') $desktop; status = Node-Probe @('status') $desktop
        realProviderJobs = 0 }
    New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
    $diagnostic | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-identity-failure.json')
    Write-Output ($diagnostic | ConvertTo-Json -Depth 4 -Compress)
}
function Get-XLoginFailureDetails([string]$Output, [string]$ErrorOutput, [string]$Phase) {
    $result = @{ category = 'unclassified'; failedCase = $null; interceptedBrowserCasesPassed = $null
        errorCode = $null; failureType = $null; sourceBasename = $null; sourceLine = $null; sourceColumn = $null
        expected = $null; actual = $null; fixtureError = $null }
    if ($Output -match '(?m)^# pass ([0-7])\r?$') { $result.interceptedBrowserCasesPassed = [int]$Matches[1] }
    if ($Phase -eq 'manager') {
        foreach ($known in @('helper readiness cancelled or timed out', 'helper exited before readiness',
            'resource checksum mismatch', 'resource inventory invalid', 'private node state inaccessible',
            'private state inaccessible', 'private profiles inaccessible', 'private bearer unavailable',
            'helper process containment unavailable', 'Google Chrome must be installed')) {
            if (($Output + $ErrorOutput).Contains($known)) { $result.category = $known; break }
        }
    }
    if ($Phase -ne 'browser-fixtures') { return $result }
    $block = ''
    foreach ($knownCase in @('real Chromium parks X and submits invalid then valid code on the same page with one password',
        'real Chromium cancel closes a parked browser and releases capacity',
        'real Chromium expiry closes a parked browser and releases capacity',
        'real Chromium shutdown closes a parked browser and releases capacity',
        'real Chromium crash closes a parked browser and releases capacity',
        'real Chromium budget closes a parked browser and releases capacity',
        'real Chromium warm authenticated profile returns a candidate without another password')) {
        $match = [regex]::Match($Output, '(?ms)^not ok [1-7] - ' + [regex]::Escape($knownCase) + '\r?\n(?<details>.*?)(?=^# Subtest:|^# tests |^1\.\.|\z)')
        if ($match.Success) { $result.failedCase = $knownCase; $block = $match.Groups['details'].Value; break }
    }
    # A failed block can itself contain expected queue_timeout. Classify only
    # its anchored runner error code, never telemetry or expected values.
    $statuses = @('verification_required', 'login_failed', 'proxy_error', 'challenge_not_found',
        'challenge_expired', 'queue_timeout', 'profile_busy', 'attempts_exhausted', 'deadline_exceeded')
    foreach ($match in [regex]::Matches($block, '(?m)^  (code|failureType):[ \t]*[''"]?([A-Za-z_]+)[''"]?\r?$')) {
        $value = $match.Groups[2].Value
        if ($match.Groups[1].Value -eq 'code' -and ($value -in $statuses -or $value -in @('ERR_ASSERTION', 'ERR_TEST_FAILURE'))) {
            $result.errorCode = $value
            $result.category = if ($value -eq 'ERR_ASSERTION') { 'assertion' } else { $value }
        } elseif ($match.Groups[1].Value -eq 'failureType' -and $value -in @('testCodeFailure', 'hookFailed', 'cancelledByParent', 'testAborted')) {
            $result.failureType = $value
        }
    }
    $stack = [regex]::Match($block, '(?m)^  stack: [|>][+-]?\r?\n(?<frames>(?:^    [^\r\n]*(?:\r?\n|\z))*)')
    $location = [regex]::Match($stack.Groups['frames'].Value, '(?m)^    (?:at )?[^\r\n]*[\\/]interactive-x\.test\.js:([1-9][0-9]{0,3}):([1-9][0-9]{0,2})\)?[ \t]*\r?$')
    if ($location.Success) {
        $result.sourceBasename = 'interactive-x.test.js'
        $result.sourceLine = [int]$location.Groups[1].Value
        $result.sourceColumn = [int]$location.Groups[2].Value
    }
    foreach ($match in [regex]::Matches($block, '(?m)^  (expected|actual):[ \t]*(.*?)\r?$')) {
        $value = $match.Groups[2].Value.Trim()
        $status = $value.Trim("'").Trim('"')
        $number = [double]0
        if ($status -in $statuses) { $result[$match.Groups[1].Value] = $status }
        elseif ($value -in @('true', 'false')) { $result[$match.Groups[1].Value] = $value -eq 'true' }
        elseif ($value -match '^[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$' -and
            [double]::TryParse($value, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$number) -and
            -not [double]::IsNaN($number) -and -not [double]::IsInfinity($number) -and [math]::Abs($number) -le 1000000) { $result[$match.Groups[1].Value] = $number }
    }
    # The fixture projects browser exceptions before production converts them
    # to login_failed. Read only the reviewed diagnostic within this failed case.
    $fixture = [regex]::Match($block, '(?m)^# SCARLETT_X_FIXTURE_ERROR (?<json>[^\r\n]{1,1000})\r?$')
    if ($fixture.Success -and $fixture.Groups['json'].Value -match '^\{.*\}$') {
        try {
            $value = $fixture.Groups['json'].Value | ConvertFrom-Json -ErrorAction Stop
            if ($value -is [pscustomobject] -and $value.stage -is [string] -and $value.stage -cin @('start', 'continue') -and
                $value.errorName -is [string] -and $value.errorName -cin @('TimeoutError', 'Error', 'TypeError', 'ServiceError', 'AdmissionError', 'AbortError', 'unclassified')) {
                $safe = @{ stage = $value.stage; errorName = $value.errorName
                    sourceBasename = $null; sourceLine = $null; sourceColumn = $null }
                $line = $value.sourceLine
                $column = $value.sourceColumn
                $numericLine = $line -is [int] -or $line -is [long] -or $line -is [double] -or $line -is [decimal]
                $numericColumn = $column -is [int] -or $column -is [long] -or $column -is [double] -or $column -is [decimal]
                if ($value.sourceBasename -is [string] -and $value.sourceBasename -cin @('interactive-x.test.js', 'legacy.js', 'login-budget.js', 'service.js') -and
                    $numericLine -and $numericColumn -and $line -ge 1 -and $line -le 9999 -and $column -ge 1 -and $column -le 999 -and
                    [math]::Floor($line) -eq $line -and [math]::Floor($column) -eq $column) {
                    $safe.sourceBasename = $value.sourceBasename
                    $safe.sourceLine = [int]$line
                    $safe.sourceColumn = [int]$column
                }
                $result.fixtureError = $safe
            }
        } catch { } # Malformed or unreviewed diagnostics have no public projection.
    }
    return $result
}

function Invoke-XLoginAcceptanceProcess([string]$File, [string[]]$Arguments, [int]$TimeoutMs,
    [ValidateSet('manager', 'headed-chrome', 'browser-fixtures')][string]$Phase) {
    # Only fixed, reviewed fixture arguments enter this subprocess. Capture all
    # output internally; evidence contains classifications, never native errors.
    $quoted = @($Arguments | ForEach-Object {
        if ($_ -match '["\r\n]' -or $_.EndsWith('\')) { throw 'Invalid browser acceptance argument' }
        '"' + $_ + '"'
    })
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName = $File
    $process.StartInfo.Arguments = $quoted -join ' '
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    Write-Host ('Installed browser acceptance phase: ' + $Phase)
    try {
        if (-not $process.Start()) { throw 'Installed browser acceptance process could not start' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMs)) {
            & (Join-Path $env:SystemRoot 'System32/taskkill.exe') /PID $process.Id /T /F 2>&1 | Out-Null
            $process.WaitForExit(10000) | Out-Null
            throw 'Installed browser acceptance process timed out'
        }
        $output = $stdout.GetAwaiter().GetResult()
        $errorOutput = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            $details = Get-XLoginFailureDetails $output $errorOutput $Phase
            $details.phase = $Phase
            $details.exitCode = $process.ExitCode
            $details.elapsedMs = $elapsed.ElapsedMilliseconds
            # The success stream is assigned by callers; the host stream reaches
            # powershell.exe stdout without becoming a fixture return value.
            Write-Host ('SCARLETT_X_LOGIN_FAILURE ' + ($details | ConvertTo-Json -Depth 4 -Compress))
            try {
                $details | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-x-login-process-failure.json')
            } catch { } # Evidence writing must not replace the original process failure.
            Write-Host ('Installed browser acceptance failed phase: ' + $Phase + '; exit status: ' + $process.ExitCode)
            throw 'Installed browser acceptance process failed'
        }
        return $output
    } finally {
        $process.Dispose()
    }
}

function Check-XLoginRuntime([string]$Phase) {
    if (-not $XLoginRuntimeFixture) { throw 'Installed browser runtime requires the reviewed native fixture executable' }
    $fixturePath = [System.IO.Path]::GetFullPath($XLoginRuntimeFixture)
    $runnerRoot = [System.IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    if (-not [System.IO.Path]::IsPathRooted($XLoginRuntimeFixture) -or
        -not $fixturePath.StartsWith($runnerRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $fixturePath -PathType Leaf) -or
        ((Get-Item -LiteralPath $fixturePath).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Browser acceptance fixture must be a regular native executable in the disposable runner'
    }
    $resources = Join-Path $install 'runtime'
    $runtimeRoot = Join-Path $resources 'x-login-runtime'
    $node = Join-Path $runtimeRoot 'node.exe'
    $browserTest = Join-Path $runtimeRoot 'social-login/test/interactive-x.test.js'
    $chrome = Join-Path $env:ProgramFiles 'Google/Chrome/Application/chrome.exe'
    foreach ($path in @($node, $browserTest, $chrome)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Installed browser acceptance prerequisite missing'
        }
    }
    $names = @('SCARLETT_TEST_X_LOGIN_RESOURCES', 'SCARLETT_TEST_X_LOGIN_BROWSER',
        'CAP_BROWSER_EXECUTABLE_PATH', 'CAP_BROWSER_CHANNEL', 'PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH', 'NODE_OPTIONS')
    $before = @{}
    foreach ($name in $names) { $before[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
    try {
        $env:SCARLETT_TEST_X_LOGIN_RESOURCES = $resources
        $env:SCARLETT_TEST_X_LOGIN_BROWSER = $chrome
        $env:CAP_BROWSER_EXECUTABLE_PATH = $chrome
        foreach ($name in @('CAP_BROWSER_CHANNEL', 'PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH', 'NODE_OPTIONS')) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
        $manager = Invoke-XLoginAcceptanceProcess $fixturePath @('-test.run=^TestPackagedRuntimeLoopbackOptIn$', '-test.v', '-test.timeout=45s') 90000 'manager'
        if ($manager -notmatch '--- PASS: TestPackagedRuntimeLoopbackOptIn') { throw 'Installed browser manager fixture did not run' }
        # Exercise the installed Playwright bytes and actual headed Chrome too.
        # about:blank performs no X navigation and requires no account state.
        $playwright = Join-Path $runtimeRoot 'social-login/node_modules/playwright/index.mjs'
        $headed = "const{pathToFileURL}=await import('node:url');const{chromium}=await import(pathToFileURL(process.argv[1]).href);const b=await chromium.launch({executablePath:process.env.CAP_BROWSER_EXECUTABLE_PATH,headless:false});try{const p=await b.newPage();await p.goto('about:blank')}finally{await b.close()}"
        $null = Invoke-XLoginAcceptanceProcess $node @('--input-type=module', '-e', $headed, $playwright) 45000 'headed-chrome'
        $browserOutput = Invoke-XLoginAcceptanceProcess $node @('--test', '--test-reporter=tap', $browserTest) 180000 'browser-fixtures'
        if ($browserOutput -notmatch '(?m)^# tests 7\r?$' -or
            $browserOutput -notmatch '(?m)^# pass 7\r?$' -or
            $browserOutput -notmatch '(?m)^# skipped 0\r?$') {
            throw 'Installed browser fixtures did not execute all seven cases'
        }
        New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
        @{ phase = $Phase; installedRuntimeBytes = 'passed'; privateStateAndBearer = 'passed'
            serviceReadiness = 'passed'; headedChromeLaunchAndClose = 'passed'; EOFShutdown = 'passed'; interceptedBrowserCases = 7
            codeOnlyContinuation = 'passed'; passwordSubmissionBudget = 'passed'; lifecycleAndWarmReuse = 'passed'
            chromeVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($chrome).ProductVersion
            providerRequests = 0; accountProfiles = 'disposable only'
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory ('windows-x-login-runtime-' + $Phase + '.json'))
        Write-Output 'Installed browser acceptance: manager readiness, private bearer, code continuation and lifecycle passed'
    } finally {
        foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $before[$name], 'Process') }
    }
}

function Check-InstallationRoundTrip {
    if (-not $BrowserFixture -or -not $script:importState -or
        @(([System.IO.File]::ReadAllText((Join-Path $script:importState 'accounts.json')) | ConvertFrom-Json).accounts).Count -ne 2) {
        throw 'Installation acceptance requires its own two synthetic X accounts'
    }
    $temporary = [System.IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    foreach ($path in @($UpgradeFixture, $UpgradeInstaller)) {
        if (-not [System.IO.Path]::GetFullPath($path).StartsWith($temporary, [StringComparison]::OrdinalIgnoreCase) -and
            -not [System.IO.Path]::GetFullPath($path).StartsWith([System.IO.Path]::GetFullPath($env:GITHUB_WORKSPACE) + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Installation fixtures must remain in the disposable runner'
        }
    }
    $fixture = [System.IO.File]::ReadAllText($UpgradeFixture) | ConvertFrom-Json
    if (-not $fixture.syntheticOnly -or -not $fixture.sameRuntimeSource -or $fixture.signedInstaller -or
        $fixture.baselineVersion -notmatch '^\d+\.\d+\.\d+$' -or $fixture.upgradeVersion -notmatch '^\d+\.\d+\.\d+$' -or
        $fixture.baselineVersion -ceq $fixture.upgradeVersion -or
        [System.IO.Path]::GetFullPath($fixture.baselineInstaller) -cne [System.IO.Path]::GetFullPath($Installer) -or
        (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant() -cne $fixture.baselineSha256) {
        throw 'Installation round-trip metadata does not match its testing installers'
    }
    $browser = [System.IO.File]::ReadAllText($BrowserFixture) | ConvertFrom-Json
    $roamingBefore, $localBefore, $stateBefore = $env:APPDATA, $env:LOCALAPPDATA, $script:state
    try {
        $env:APPDATA, $env:LOCALAPPDATA = $browser.roaming, $browser.local
        $script:state = $script:importState
        Write-SyntheticPrivateJSON (Join-Path $script:importState 'identity.json') @{
            node_id = 'synthetic-installer-node'; supplier_pubkey = 'synthetic-local-wallet'
            credential = 'synthetic-installation-credential-never-used-remotely'
        }
        $journal = Join-Path $script:importState 'attempts'
        $privateOutput = & (Join-Path $install 'scarlett-node.exe') desktop private-dir $journal | Out-String
        $privateOutput = $null
        if ($LASTEXITCODE -ne 0) { throw 'Could not create private journal fixture directory' }
        $job, $attempt, $fence = 'synthetic-upgrade-job', 'synthetic-upgrade-attempt', 'synthetic-upgrade-fence'
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($job + [char]0 + $attempt + [char]0 + $fence)) }
        finally { $sha.Dispose() }
        $name = [BitConverter]::ToString($digest).Replace('-', '').ToLowerInvariant() + '.json'
        Write-SyntheticPrivateJSON (Join-Path $journal $name) @{
            job_id = $job; attempt = $attempt; fence = $fence; fingerprint = ('a' * 64)
            deadline = [DateTime]::UtcNow.AddHours(2).ToString('o'); updated_at = [DateTime]::UtcNow.ToString('o')
            state = 'started'; provider_account_id = 'browser-firefox'; provider_service = 'x_read'
        }
        Start-App
        $version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($executable).ProductVersion
        if ($version -notin @($fixture.baselineVersion, ($fixture.baselineVersion + '.0'))) { throw 'Baseline executable has the wrong product version' }
        try { Wait-Check { $null -eq (Find-Button 'Pair node') } 15 'Baseline app did not recognize its private synthetic identity' }
        catch {
            $failure = $_
            try { Identity-Diagnostics 'baseline' } catch { Write-Output 'Identity failure diagnostics were unavailable' }
            throw $failure
        }
        Open-Disclosure 'Device settings'
        Set-Number 'Saved local API port' 18088
        Click-Button 'Save device preferences'
        Wait-Check { Saved-Preferences 18088 $false } 15 'Baseline app did not retain its test port'
        Click-Button 'Start local API'
        Wait-Check { (Api-Status '/health') -eq 200 } 30 'Baseline private API did not start'
        Click-Button 'Quit Scarlett'
        if (-not $application.WaitForExit(135000)) { throw 'Baseline app did not drain before installation' }
        Wait-Check { (Api-Status '/health') -eq 0 } 30 'Baseline app left API running before installation'
        $before = Durable-Hashes
        foreach ($candidate in @(@{ path = $UpgradeInstaller; version = $fixture.upgradeVersion; direction = 'upgrade' },
                                  @{ path = $Installer; version = $fixture.baselineVersion; direction = 'downgrade' })) {
            if ((Api-Status '/health') -ne 0) { throw 'Installation began while local API was running' }
            $setup = Start-Process -FilePath $candidate.path -ArgumentList '/S', "/D=$install" -PassThru
            if (-not $setup.WaitForExit(120000)) { $setup.Kill(); throw 'Installation round trip timed out' }
            if ($setup.ExitCode -ne 0) { throw 'Installation round trip failed' }
            $version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($executable).ProductVersion
            if ($version -notin @($candidate.version, ($candidate.version + '.0'))) { throw 'Installed executable has the wrong product version' }
            & $script:pythonExe (Join-Path $PSScriptRoot 'check-complete-bundle.py') $install $install
            if ($LASTEXITCODE -ne 0) { throw 'Replaced installation failed complete component validation' }
            Check-XLoginRuntime $candidate.direction
            $after = Durable-Hashes
            if ($after.Count -ne $before.Count) { throw 'Installation changed private account/identity/journal files' }
            foreach ($path in $before.Keys) { if ($after[$path] -cne $before[$path]) { throw 'Installation changed private retained bytes' } }
            Start-App
            try { Wait-Check { $null -eq (Find-Button 'Pair node') } 15 'Installed app lost its synthetic node identity' }
            catch {
                $failure = $_
                try { Identity-Diagnostics $candidate.direction } catch { Write-Output 'Identity failure diagnostics were unavailable' }
                throw $failure
            }
            Wait-Check { UI-Contains 'browser-firefox' } 15 'Installed app lost the connected X account'
            if ((Api-Status '/health') -ne 0 -or -not (Saved-Preferences 18088 $false)) { throw 'Opening replaced app started API or lost saved preferences' }
            Click-Button 'Start local API'
            Wait-Check { (Api-Status '/health') -eq 200 } 30 'Replaced app could not start the retained local API'
            $key = [System.IO.File]::ReadAllText((Join-Path $script:importState 'local-api/bearer'))
            if ((Api-Status '/v1/models' $key) -ne 200) { throw 'Replaced app refused its retained private API bearer' }
            $key = $null
            Click-Button 'Quit Scarlett'
            if (-not $application.WaitForExit(135000)) { throw 'Replaced app did not drain and quit' }
            Wait-Check { (Api-Status '/health') -eq 0 } 30 'Replaced app left local API running'
            $after = Durable-Hashes
            if ($after.Count -ne $before.Count) { throw 'Replaced app changed durable file inventory' }
            foreach ($path in $before.Keys) { if ($after[$path] -cne $before[$path]) { throw 'Replaced app changed private durable state' } }
            Write-Output "Installed round trip: $($candidate.direction) retained private state and protected API"
        }
        @{
            baselineVersion = $fixture.baselineVersion; upgradeVersion = $fixture.upgradeVersion
            upgrade = 'passed'; downgrade = 'passed'; privateIdentity = 'passed'; XAccounts = 'passed'
            uncertainJournalBytes = 'passed'; preferences = 'passed'; APIBearer = 'passed'; protectedAPI = 'passed'
            sameRuntimeSource = $true; signedInstaller = $false; historicalSchemaCompatibility = 'not tested'
            realProviderJobs = 0
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-installation-round-trip.json')
    } finally {
        $key = $null
        $env:APPDATA, $env:LOCALAPPDATA = $roamingBefore, $localBefore
        $script:state = $stateBefore
    }
}

$install = Join-Path $env:RUNNER_TEMP 'Scarlett Installed UI Acceptance'
$state = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'ai.scarlett.node'
if ((Test-Path $install) -or (Test-Path $state)) {
    throw 'Acceptance requires a clean installer destination and app-owned profile'
}
if ((Api-Status '/health') -ne 0) { throw 'Acceptance loopback port is already occupied' }
$setup = Start-Process -FilePath $Installer -ArgumentList '/S', "/D=$install" -PassThru
if (-not $setup.WaitForExit(120000)) { $setup.Kill(); throw 'Silent test installation timed out' }
if ($setup.ExitCode -ne 0) { throw 'Silent test installation failed' }
$executable = Join-Path $install 'scarlett-node-desktop.exe'
foreach ($file in @($executable, (Join-Path $install 'scarlett-node.exe'),
    (Join-Path $install 'scarlett-prover.exe'), (Join-Path $install 'open-agent-api.exe'),
    (Join-Path $install 'runtime/COMPONENTS.json'))) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Installed runtime component missing' }
}
# The release signer runs this script from desktop/, PR CI from the repository root.
python (Join-Path $PSScriptRoot 'check-complete-bundle.py') $install $install
if ($LASTEXITCODE -ne 0) { throw 'Installed component integrity or API payload validation failed' }
Check-XLoginRuntime 'baseline'

# Keep one absolute interpreter for installation validation after PATH cleanup.
# Application discovery can return several paths; the call operator needs one.
$script:pythonExe = Get-Command python -CommandType Application | Select-Object -First 1 -ExpandProperty Path
if (-not [System.IO.Path]::IsPathRooted($script:pythonExe) -or
    -not (Test-Path -LiteralPath $script:pythonExe -PathType Leaf)) {
    throw 'Installation validation requires one existing absolute Python executable'
}
$previousPath = $env:PATH
$env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
$application = $null
$script:nativeFocusRestores = 0
$script:ownsLoginRegistration = $false
$key = $null
try {
    Start-App
    Click-Button 'Start local API'
    Wait-Check { (Api-Status '/health') -eq 200 } 30 'Installed UI did not start the local API'
    if ((Api-Status '/v1/models') -ne 401) { throw 'Installed API allowed unauthenticated model access' }
    $keyPath = Join-Path $state 'local-api/bearer'
    $key = [System.IO.File]::ReadAllText($keyPath)
    if ($key -notmatch '^[0-9a-f]{64}$' -or (Api-Status '/v1/models' $key) -ne 200) {
        throw 'Installed API bearer validation failed'
    }
    Write-Output 'Installed acceptance: Start and bearer protection passed'
    $key = $null
    Click-Button 'Stop local API'
    Wait-Check { (Api-Status '/health') -eq 0 } 30 'Installed UI Stop left the API running'
    Wait-Check { (Find-Button 'Start local API').Current.IsEnabled } 10 'Start did not recover after Stop'
    Click-Button 'Start local API'
    Wait-Check { (Api-Status '/health') -eq 200 } 30 'Installed UI restart did not become ready'
    Write-Output 'Installed acceptance: Stop and immediate restart passed'
    # Kill only the exact desktop process launched above; EOF must stop its API
    $application.Kill()
    if (-not $application.WaitForExit(10000)) { throw 'Owned desktop did not exit' }
    Wait-Check { (Api-Status '/health') -eq 0 } 30 'API survived unexpected desktop exit'
    Start-App
    Click-Button 'Start local API'
    Wait-Check { (Api-Status '/health') -eq 200 } 30 'Desktop recovery did not start the API'
    Write-Output 'Installed acceptance: unexpected exit and recovery passed'
    Focus-QuitShortcut
    Check-QuitShortcut 'Installed desktop Quit did not exit'
    Wait-Check { (Api-Status '/health') -eq 0 } 30 'Installed desktop Quit left the API running'
    New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
    @{
        installedNSIS = 'passed'; completePayload = 'passed'; nativeWindow = 'passed'
        uiStartStop = 'passed'; bearerProtection = 'passed'; developerPathCleared = $true
        unexpectedDesktopExit = 'passed'; uiQuit = 'passed'; quitInputFocus = 'verified'; realProviderJobs = 0
        signedInstaller = 'separate signature acceptance required'; remoteAccountLoginTested = $false
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-installed-ui.json')
    if ($Preferences) { Check-Preferences }
    if ($BrowserFixture) { Check-BrowserImport }
    if ($UpgradeFixture -or $UpgradeInstaller) {
        if (-not $UpgradeFixture -or -not $UpgradeInstaller) { throw 'Both installation fixture and upgrade installer are required' }
        Check-InstallationRoundTrip
    }
    Write-Output "Installed acceptance: WebView native input focus restored after UIA focus $($script:nativeFocusRestores) times"
} catch {
    # Record source line numbers for failures hidden by the workflow wrapper,
    # without publishing stack paths, UI values or native exception messages.
    $lines = @([regex]::Matches([string]$_.ScriptStackTrace, 'check-windows-install\.ps1: line (\d+)') |
        ForEach-Object { [int]$_.Groups[1].Value })
    Write-Output (@{ acceptanceFailureLines = $lines; realProviderJobs = 0 } | ConvertTo-Json -Compress)
    throw
} finally {
    $key = $null
    $env:PATH = $previousPath
    if ($script:ownsLoginRegistration) {
        $ownedRun = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $true)
        if ($ownedRun) { try { $ownedRun.DeleteValue('Scarlett Node', $false) } finally { $ownedRun.Dispose() } }
    }
    if ($application -and -not $application.HasExited) {
        $application.Kill()
        $application.WaitForExit(10000) | Out-Null
    }
}
