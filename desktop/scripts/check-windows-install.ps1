# Runs only on a disposable native CI runner, never an operator's Windows profile
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
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
    $request = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:8088$Path")
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
function Start-App {
    $script:application = Start-Process -FilePath $script:executable -WorkingDirectory $script:install -PassThru
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
        $button = Find-Button 'Start local API'
        return $null -ne $button -and $button.Current.IsEnabled
    } 30 'Installed desktop API controls did not become available'
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
    $target = Find-Button 'Stop local API'
    if (-not $target -or -not $target.Current.IsEnabled) { throw 'Quit focus control unavailable' }
    $target.SetFocus()
    Wait-Check {
        $focused = [System.Windows.Automation.AutomationElement]::FocusedElement
        return $null -ne $focused -and $focused.Current.ProcessId -eq $target.Current.ProcessId -and
            $target.Current.HasKeyboardFocus -and
            [ScarlettAcceptanceWindow]::GetForegroundWindow() -eq $handle
    } 10 'Installed desktop control did not acquire keyboard focus for Quit'
    Write-Output 'Installed acceptance: foreground and WebView keyboard focus verified'
}

$install = Join-Path $env:RUNNER_TEMP 'scarlett-installed-ui-acceptance'
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
} finally {
    $key = $null
    $env:PATH = $previousPath
    if ($application -and -not $application.HasExited) {
        $application.Kill()
        $application.WaitForExit(10000) | Out-Null
    }
}
