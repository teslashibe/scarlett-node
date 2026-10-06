# Validate exact acceptance helpers without starting an app or injecting input
$ErrorActionPreference = 'Stop'
if ($env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_ACTIONS -ne 'true') { throw 'Use a disposable native Windows CI runner' }
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'check-windows-install.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'Installed Windows acceptance script did not parse' }
$definitions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Value.Contains('public static class ScarlettAcceptanceWindow')
}, $true))
if ($definitions.Count -ne 1) { throw 'Expected exactly one native acceptance input definition' }
Add-Type -TypeDefinition $definitions[0].Value
$expectedSize = 28
if ([IntPtr]::Size -eq 8) { $expectedSize = 40 }
if ([ScarlettAcceptanceWindow]::InputSize() -ne $expectedSize) { throw 'Native input layout differs from the platform ABI' }
Write-Output 'Native Windows acceptance input compiled with the correct ABI; no input injected'

# Exercise the exact bounds guard with a point that cannot belong to the desktop.
# Fail before calling Click if the guard disagrees, so this never injects input.
if ([ScarlettAcceptanceWindow]::PointInDesktop([int]::MinValue, [int]::MinValue)) {
    throw 'Native click bounds guard accepted the invalid test point'
}
[ScarlettAcceptanceWindow]::ResetInputDiagnostics()
$rejected = $false
try { [ScarlettAcceptanceWindow]::Click([int]::MinValue, [int]::MinValue) } catch { $rejected = $true }
if (-not $rejected -or [string][ScarlettAcceptanceWindow]::LastNativeFailure -cne 'DesktopBounds' -or
    [ScarlettAcceptanceWindow]::LastInputExpected -ne 0 -or [ScarlettAcceptanceWindow]::LastInputAccepted -ne 0 -or
    [ScarlettAcceptanceWindow]::LastInputError -ne 0) {
    throw 'Native click bounds failure did not preserve its classification without input'
}
[ScarlettAcceptanceWindow]::ResetInputDiagnostics()
if ([string][ScarlettAcceptanceWindow]::LastNativeFailure -cne 'None' -or
    [ScarlettAcceptanceWindow]::LastInputExpected -ne 0 -or [ScarlettAcceptanceWindow]::LastInputAccepted -ne 0 -or
    [ScarlettAcceptanceWindow]::LastInputError -ne 0) {
    throw 'Native input diagnostics retained a previous failure'
}
Write-Output 'Native click bounds rejection and diagnostic reset passed; no input injected'

# Evaluate the exact inventory normalization used by installed acceptance.
# Windows PowerShell 5.1 emits JSON arrays as one pipeline object; PowerShell 7
# enumerates them. Neither shell may turn 0/1/3 records into a nested one-item list.
$normalizations = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -ceq 'listed'
}, $true))
if ($normalizations.Count -ne 1) { throw 'Expected exactly one synthetic inventory normalization' }
$scenarios = @(
    @{ json = '[]'; ids = @() },
    @{ json = '[{"id":"one","service":"x_read"}]'; ids = @('one') },
    @{ json = '[{"id":"one","service":"x_read"},{"id":"two","service":"x_read"},{"id":"three","service":"x_read"}]'; ids = @('one', 'two', 'three') }
)
foreach ($scenario in $scenarios) {
    $inventory = $scenario.json
    Invoke-Expression $normalizations[0].Extent.Text
    if ($listed.Count -ne $scenario.ids.Count) { throw 'Synthetic inventory normalization changed the JSON record count' }
    for ($recordIndex = 0; $recordIndex -lt $scenario.ids.Count; $recordIndex++) {
        if ($listed[$recordIndex].id -cne $scenario.ids[$recordIndex] -or $listed[$recordIndex].service -cne 'x_read') {
            throw 'Synthetic inventory normalization changed its record identities'
        }
    }
}
Write-Output 'Synthetic inventory normalization preserved 0/1/3 records and identities'

# Bind the exact probe names and control types to the installed form markup.
# This checks the real source before any app launch or native input injection.
$probes = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Verify-KeyboardDelivery'
}, $true))
if ($probes.Count -ne 1) { throw 'Expected exactly one installed keyboard probe' }
$resolvers = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'X-AccountIDSuccessor'
}, $true))
if ($resolvers.Count -ne 0) { throw 'Keyboard probe must not depend on browser discovery' }
$probe = $probes[0].Extent.Text
$name = [regex]::Match($probe, '\$name = ''([^'']+)''').Groups[1].Value
$nextName = [regex]::Match($probe, '\$nextName = ''([^'']+)''').Groups[1].Value
$main = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../src/main.ts') -Raw
$form = [regex]::Match($main, '<form id="x-login-form">([\s\S]*?)</form>').Groups[1].Value
if ($form -ceq '') { throw 'Installed keyboard probe form is missing' }
$source = [regex]::Match($form, '<label>([^<]+)<input id="x-login-id"([^>]*)>')
$successor = [regex]::Match($form, '<label class="check"><input id="x-login-reconnect"([^>]*)>([^<]+)</label>')
if (-not $source.Success -or -not $successor.Success -or
    $name -cne $source.Groups[1].Value -or $nextName -cne $successor.Groups[2].Value) {
    throw 'Installed keyboard probe names differ from their labelled controls'
}
if ($source.Groups[2].Value -match '\btype="password"|\bdisabled\b' -or
    $successor.Groups[1].Value -notmatch '\btype="checkbox"' -or
    $successor.Groups[1].Value -match '\bdisabled\b') {
    throw 'Installed keyboard probe requires an enabled text field and checkbox'
}
$controls = @([regex]::Matches($form, '<(?:input|select|button)\b([^>]*)>') | ForEach-Object {
    $attributes = $_.Groups[1].Value
    if ($attributes -notmatch '\btype="hidden"') {
        [regex]::Match($attributes, '\bid="([^"]+)"').Groups[1].Value
    }
})
if ($controls.Count -lt 2 -or $controls[0] -cne 'x-login-id' -or $controls[1] -cne 'x-login-reconnect' -or
    $form -notmatch '<input id="x-login-capacity" type="hidden" value="1">') {
    throw 'Installed keyboard probe controls are not adjacent in the visible form'
}
Write-Output 'Installed keyboard probe names, text/checkbox types and visible tab order match the real form; no input injected'
