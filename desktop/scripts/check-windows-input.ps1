# Compile the exact acceptance helper without starting an app or injecting input
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
