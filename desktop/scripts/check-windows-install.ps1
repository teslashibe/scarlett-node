# Runs only on a disposable native CI runner, never an operator's Windows profile
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
    [switch]$Preferences,
    [string]$BrowserFixture = ''
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
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
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
function Focus-QuitShortcut {
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
    Wait-Check {
        $focused = [System.Windows.Automation.AutomationElement]::FocusedElement
        return $null -ne $focused -and $focused.Current.ProcessId -eq $target.Current.ProcessId -and
            $target.Current.HasKeyboardFocus -and
            [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle
    } 10 'Installed desktop control did not acquire keyboard focus for Quit'
    Write-Output 'Installed acceptance: foreground and WebView keyboard focus verified'
}

function Check-QuitShortcut([string]$Failure) {
    [System.Windows.Forms.SendKeys]::SendWait('^q')
    if ($application.WaitForExit(135000)) { return }
    # Keep the shortcut failure, but distinguish missed input from a native
    # shutdown error. Capture only fixed classifications, never UI text or keys.
    $shutdownError = $false
    $focusMatches = $false
    $foregroundMatches = $false
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
    } catch { }
    $diagnostic = @{
        shortcutExited = $false; shutdownErrorVisible = $shutdownError
        stopControlKeyboardFocus = $focusMatches; foregroundOwnedWindow = $foregroundMatches
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
    # Prove SendKeys reaches a harmless empty field before blaming a shortcut.
    Write-Output "Installed keyboard probe: interactive=$([Environment]::UserInteractive), session=$([System.Diagnostics.Process]::GetCurrentProcess().SessionId)"
    $target = $null
    foreach ($name in @('Local Codex account ID', 'Local account ID')) {
        $condition = [System.Windows.Automation.AndCondition]::new(
            [System.Windows.Automation.PropertyCondition]::new(
                [System.Windows.Automation.AutomationElement]::NameProperty, $name),
            [System.Windows.Automation.PropertyCondition]::new(
                [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
                [System.Windows.Automation.ControlType]::Edit)
        )
        $target = $script:window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
        if ($null -ne $target) { break }
    }
    $value = $null
    if ($null -eq $target -or -not $target.Current.IsEnabled -or
        -not $target.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$value) -or
        $value.Current.Value -ne '') { throw 'Keyboard probe requires an empty disposable account field' }
    $handle = $application.MainWindowHandle
    [ScarlettAcceptanceWindow]::ShowWindow($handle, 9) | Out-Null
    [ScarlettAcceptanceWindow]::SetForegroundWindow($handle) | Out-Null
    $target.SetFocus()
    Wait-Check {
        return $target.Current.HasKeyboardFocus -and [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle
    } 10 'Keyboard probe did not acquire foreground and field focus'
    [System.Windows.Forms.SendKeys]::SendWait('keyboard-probe')
    Wait-Check { $value.Current.Value -ceq 'keyboard-probe' } 10 'CI keyboard injection did not reach the editable control'
    $value.SetValue('')
    Write-Output 'Installed acceptance: synthetic keyboard delivery verified'
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
    $saved = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
    return $saved.schema -eq 1 -and $saved.local_api_port -eq $Port -and $saved.background -eq $Background
}
function Close-Window {
    $pattern = $null
    if (-not $script:window.TryGetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern, [ref]$pattern)) {
        throw 'Native window close pattern unavailable'
    }
    $pattern.Close()
}
function Registered-Command {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run')
    if (-not $key) { return $null }
    try { return $key.GetValue('Scarlett Node', $null) } finally { $key.Dispose() }
}
function Check-Preferences {
    if ($null -ne (Registered-Command)) { throw 'Clean runner already has a Scarlett login registration' }
    Start-App
    if (-not (Checkbox-Is 'Keep running when the window closes' $false)) { throw 'Background mode was not opt-in' }
    if (-not (Checkbox-Is 'Open Scarlett when I log in' $false)) { throw 'Start at login was not opt-in' }
    Set-Number 'Saved local API port' 18088
    Click-Button 'Save device preferences'
    Wait-Check { Saved-Preferences 18088 $false } 15 'Device preferences were not saved privately'
    $script:apiPort = 18088
    if ((Api-Status '/health') -ne 0) { throw 'Preferences test port is already occupied' }
    Click-Button 'Start local API'
    Wait-Check { (Api-Status '/health') -eq 200 } 30 'Saved port did not start the local API'
    Close-Window
    if (-not $application.WaitForExit(135000)) { throw 'Default window close did not quit' }
    Wait-Check { (Api-Status '/health') -eq 0 } 30 'Default window close left the API running'
    Write-Output 'Installed preferences: default close drained and saved port passed'

    Start-App
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
    if (-not (Checkbox-Is 'Open Scarlett when I log in' $true)) { throw 'Native login registration did not survive app reopening' }
    if ((Api-Status '/health') -ne 0) { throw 'Registered app opening automatically started API' }
    Set-Checkbox 'Open Scarlett when I log in' $false
    Wait-Check { $null -eq (Registered-Command) } 15 'Disabling login left the native registration'
    $script:ownsLoginRegistration = $false
    Write-Output 'Installed preferences: quoted native login enable/read-back/disable passed'

    Set-Checkbox 'Keep running when the window closes' $true
    Click-Button 'Save device preferences'
    Wait-Check { Saved-Preferences 18088 $true } 15 'Background preference did not save'
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
    if ($application.Id -ne $originalProcess -or (Api-Status '/health') -ne 200) { throw 'Reopening did not retain the same background app and API' }
    Set-Checkbox 'Keep running when the window closes' $false
    Click-Button 'Save device preferences'
    Wait-Check { Saved-Preferences 18088 $false } 15 'Background mode did not restore off'
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

function Set-Text([string]$Name, [string]$Value) {
    Wait-Check { (Find-Input $Name).Current.IsEnabled } 15 "Text input did not become ready: $Name"
    $control = Find-Input $Name
    if (-not $control -or -not $control.Current.IsEnabled) { throw "Text input unavailable: $Name" }
    $pattern = $null
    if (-not $control.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) {
        # Password fields can refuse ValuePattern. These test-only values have
        # no SendKeys metacharacters; never pass a real browser credential here.
        if ($Value -notmatch '^[a-z0-9-]+$') { throw 'Synthetic input contains unsupported characters' }
        $handle = $application.MainWindowHandle
        [ScarlettAcceptanceWindow]::ShowWindow($handle, 9) | Out-Null
        [ScarlettAcceptanceWindow]::SetForegroundWindow($handle) | Out-Null
        $control.SetFocus()
        Wait-Check {
            return $control.Current.HasKeyboardFocus -and [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle
        } 10 'Synthetic input did not acquire keyboard focus'
        [System.Windows.Forms.SendKeys]::SendWait('^a')
        [System.Windows.Forms.SendKeys]::SendWait($Value)
        return
    }
    $pattern.SetValue($Value)
    Wait-Check { ([string]$pattern.Current.Value) -ceq $Value } 10 'Synthetic text value did not commit'
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
    Wait-Check {
        return $target.Current.HasKeyboardFocus -and [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle
    } 10 'Browser chooser did not acquire input focus'
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
function Check-BrowserImport {
    $root = [System.IO.Path]::GetFullPath((Split-Path -Parent $BrowserFixture))
    $temporary = [System.IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    if (-not $root.StartsWith($temporary, [StringComparison]::OrdinalIgnoreCase)) { throw 'Browser fixtures must be below the disposable runner directory' }
    $script:fixture = [System.IO.File]::ReadAllText($BrowserFixture) | ConvertFrom-Json
    if (-not $script:fixture.syntheticOnly) { throw 'Browser acceptance requires synthetic fixtures' }
    foreach ($path in @($script:fixture.roaming, $script:fixture.local) + @($script:fixture.stores | ForEach-Object { $_.path })) {
        if (-not [System.IO.Path]::GetFullPath($path).StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Browser fixture escaped its isolated home' }
    }
    $roamingBefore, $localBefore = $env:APPDATA, $env:LOCALAPPDATA
    try {
        $env:APPDATA, $env:LOCALAPPDATA = $script:fixture.roaming, $script:fixture.local
        Start-App
        Wait-Check { (Find-Input 'Browser profile').Current.IsEnabled } 15 'Isolated browser profiles were not discovered'
        if ((Imported-Accounts).Count -ne 0) { throw 'Browser test encountered existing accounts' }
        if (-not (Checkbox-Is 'Import only X session cookies from this profile' $false) -or (Find-Button 'Import X account').Current.IsEnabled) { throw 'Browser import did not require opt-in consent' }
        # The two fixture profiles sort Chrome, then Firefox after the prompt.
        Select-Browser 1 'Chrome'
        Set-Checkbox 'Import only X session cookies from this profile' $true
        Wait-Check { (Find-Button 'Import X account').Current.IsEnabled } 10 'Consent did not enable import'
        Select-Browser 2 'Firefox'
        Wait-Check { Checkbox-Is 'Import only X session cookies from this profile' $false } 10 'Changing profile retained consent'
        Wait-Check { -not (Find-Button 'Import X account').Current.IsEnabled } 10 'Profile change allowed import without new consent'
        Set-Text 'Local X account ID' 'browser-firefox'
        Set-Checkbox 'Import only X session cookies from this profile' $true
        Click-Button 'Import X account'
        try {
            # The native import contract permits 45 seconds, then the UI refresh
            # runs. Observe that complete contract rather than timing out at 20.
            Wait-Check { (Imported-Accounts).Count -eq 1 } 55 'Installed Firefox UI import did not persist'
        } catch {
            $errors = @{
                invalid_input = 'Check the account ID, capacity and cookie values'
                command_failed = 'The node could not complete that action'
                command_timeout = 'The action timed out'
                private_storage = 'Scarlett could not open its private local storage'
                browser_protected = 'The browser or OS protected this profile'
                browser_busy = 'Close the selected browser, then try importing again'
                browser_invalid = 'Scarlett could not read this cookie store safely'
                browser_no_x_session = 'No complete X session was found in that profile'
                browser_ambiguous = 'This profile contains multiple X sessions'
                browser_unsupported = 'This browser format is not supported on this device'
            }
            $classifications = @{}
            foreach ($classification in $errors.Keys) { $classifications[$classification] = UI-Contains $errors[$classification] }
            $failure = @{ accountCount = (Imported-Accounts).Count
                importButtonEnabled = (Find-Button 'Import X account').Current.IsEnabled
                successNoticeVisible = (UI-Contains 'X account imported on this device')
                errorClasses = $classifications; realProviderJobs = 0 }
            $failure | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-browser-import-failure.json')
            Write-Output ($failure | ConvertTo-Json -Depth 3 -Compress)
            throw
        }
        Wait-Check { Checkbox-Is 'Import only X session cookies from this profile' $false } 10 'Successful import retained consent'
        Wait-Check { UI-Contains 'access not verified' } 15 'Imported account claimed verified access'
        Select-Browser 1 'Chrome'
        Set-Text 'Local X account ID' 'protected-chrome'
        Set-Checkbox 'Import only X session cookies from this profile' $true
        Click-Button 'Import X account'
        Wait-Check { UI-Contains 'The browser or OS protected this profile' } 20 'Protected Chrome did not show the paste fallback'
        if ((Imported-Accounts).Count -ne 1) { throw 'Protected Chrome import added an account' }
        foreach ($name in @('auth_token', 'ct0')) {
            if (-not (Find-Input $name).Current.IsPassword) { throw 'Cookie paste field was not masked' }
        }
        Set-Text 'Local X account ID' 'browser-paste'
        Set-Text 'auth_token' $script:fixture.authToken
        Set-Text 'ct0' $script:fixture.csrf
        Click-Button 'Connect X'
        Wait-Check { (Imported-Accounts).Count -eq 2 } 20 'Installed masked paste did not persist'
        foreach ($record in (Imported-Accounts)) {
            if ($record.service -ne 'x_read' -or $record.id -notin @('browser-firefox', 'browser-paste')) { throw 'Unexpected imported account' }
            $credentialRoot = [System.IO.Path]::GetFullPath((Join-Path $script:importState 'accounts')).TrimEnd('\') + '\'
            if (-not [System.IO.Path]::GetFullPath($record.path).StartsWith($credentialRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Imported credential escaped disposable app state' }
            $raw = [System.IO.File]::ReadAllText($record.path) | ConvertFrom-Json
            if (@($raw.PSObject.Properties).Count -ne 2 -or $raw.auth_token -cne $script:fixture.authToken -or $raw.ct0 -cne $script:fixture.csrf) { throw 'Imported session differs from selected synthetic fields' }
            $raw = $null
        }
        foreach ($store in $script:fixture.stores) {
            if ((Get-FileHash -LiteralPath $store.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $store.sha256) { throw 'Import modified its browser store' }
        }
        # The installed helper checks native private ACLs before exposing its
        # credential-free inventory. Never print cookie files or this output.
        $stateBefore, $accountsBefore = $env:SCARLETT_STATE_DIR, $env:SCARLETT_ACCOUNTS_FILE
        try {
            $env:SCARLETT_STATE_DIR, $env:SCARLETT_ACCOUNTS_FILE = $script:importState, (Join-Path $script:importState 'accounts.json')
            $inventory = & (Join-Path $install 'scarlett-node.exe') accounts list | Out-String
            if ($LASTEXITCODE -ne 0 -or @($inventory | ConvertFrom-Json).Count -ne 2) { throw 'Installed helper refused private imported accounts' }
            if ($inventory.Contains($script:fixture.authToken) -or $inventory.Contains($script:fixture.csrf) -or (UI-Contains $script:fixture.authToken) -or (UI-Contains $script:fixture.csrf)) { throw 'Import exposed fixture credentials in status' }
            $inventory = $null
        } finally { $env:SCARLETT_STATE_DIR, $env:SCARLETT_ACCOUNTS_FILE = $stateBefore, $accountsBefore }
        Click-Button 'Quit Scarlett'
        if (-not $application.WaitForExit(135000)) { throw 'Browser acceptance app did not quit' }
        @{
            redirectedBrowserRoots = 'passed'; profileConsent = 'passed'; consentReset = 'passed'
            firefoxUIImport = 'passed'; protectedChromeFallback = 'passed'; maskedPaste = 'passed'
            privatePersistence = 'passed'; unchangedBrowserStores = 'passed'; accessUnverified = $true
            realBrowserAccountsTested = $false; realProviderJobs = 0
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-browser-import-ui.json')
        Write-Output 'Installed browser acceptance: consent, Firefox import, protected Chrome and masked paste passed'
    } finally {
        $env:APPDATA, $env:LOCALAPPDATA = $roamingBefore, $localBefore
        $script:fixture = $null
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
python desktop/scripts/check-complete-bundle.py $install $install
if ($LASTEXITCODE -ne 0) { throw 'Installed component integrity or API payload validation failed' }

$previousPath = $env:PATH
$env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
$application = $null
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
    Verify-KeyboardDelivery
    Focus-QuitShortcut
    Check-QuitShortcut 'Installed desktop Quit did not exit'
    Wait-Check { (Api-Status '/health') -eq 0 } 30 'Installed desktop Quit left the API running'
    New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
    @{
        installedNSIS = 'passed'; completePayload = 'passed'; nativeWindow = 'passed'
        uiStartStop = 'passed'; bearerProtection = 'passed'; developerPathCleared = $true
        unexpectedDesktopExit = 'passed'; uiQuit = 'passed'; quitInputFocus = 'verified'; realProviderJobs = 0
        signedInstaller = $false; remoteAccountLoginTested = $false
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-installed-ui.json')
    if ($Preferences) { Check-Preferences }
    if ($BrowserFixture) { Check-BrowserImport }
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
