# Runs only on a disposable native CI runner, never an operator's Windows profile
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
    [switch]$Preferences
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
    [System.Windows.Forms.SendKeys]::SendWait('^q')
    if (-not $application.WaitForExit(135000)) { throw 'Preferences app Quit did not exit' }
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
    [System.Windows.Forms.SendKeys]::SendWait('^q')
    if (-not $application.WaitForExit(135000)) { throw 'Installed desktop Quit did not exit' }
    Wait-Check { (Api-Status '/health') -eq 0 } 30 'Installed desktop Quit left the API running'
    New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
    @{
        installedNSIS = 'passed'; completePayload = 'passed'; nativeWindow = 'passed'
        uiStartStop = 'passed'; bearerProtection = 'passed'; developerPathCleared = $true
        unexpectedDesktopExit = 'passed'; uiQuit = 'passed'; quitInputFocus = 'verified'; realProviderJobs = 0
        signedInstaller = $false; remoteAccountLoginTested = $false
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'windows-installed-ui.json')
    if ($Preferences) { Check-Preferences }
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
