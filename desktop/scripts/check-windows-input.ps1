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
