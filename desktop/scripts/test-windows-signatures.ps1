param([Parameter(Mandatory = $true)][string]$UnsignedNativeBinary)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Signature fixtures require a disposable native Windows runner'
}
. (Join-Path $PSScriptRoot 'check-windows-signatures.ps1')
$publisher = '0123456789abcdef0123456789abcdef01234567'

function Require-Rejection([scriptblock]$Action) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unsafe signature fixture was accepted' }
}

# Synthetic records prove rejection contracts, not real certificate trust
$valid = @{ Status = 'Valid'; SignatureType = 'Authenticode'
    SignerCertificate = @{ Thumbprint = $publisher; Issuer = 'Synthetic CA'; Subject = 'Synthetic leaf' }
    TimeStamperCertificate = @{ fixture = $true } }
Assert-SignatureRecord $valid $publisher
foreach ($status in @('NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError')) {
    $record = $valid.Clone(); $record.Status = $status
    Require-Rejection { Assert-SignatureRecord $record $publisher }
}
$record = $valid.Clone(); $record.SignatureType = 'Catalog'
Require-Rejection { Assert-SignatureRecord $record $publisher }
$record = $valid.Clone(); $record.TimeStamperCertificate = $null
Require-Rejection { Assert-SignatureRecord $record $publisher }
Require-Rejection { Assert-SignatureRecord $valid ('f' * 40) }
Require-Rejection { Assert-SignatureRecord $valid 'invalid-thumbprint' }
$record = $valid.Clone(); $record.SignerCertificate = @{ Thumbprint = $publisher; Issuer = 'Self'; Subject = 'Self' }
Require-Rejection { Assert-SignatureRecord $record $publisher }
Require-Rejection { Assert-RegularLocalFile '\\server\share\fixture.exe' }
Require-Rejection { Assert-RegularLocalFile 'C:\fixture.exe:alternate-stream' }

# Exercise the actual OS verifier against the native CI Go executable, not a
# mocked status, with no signing certificate/trust-store creation or mutation
$binary = Assert-RegularLocalFile ([System.IO.Path]::GetFullPath($UnsignedNativeBinary))
$before = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
$actual = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $binary
if ([string]$actual.Status -cne 'NotSigned') { throw 'Native unsigned rejection fixture unexpectedly has a signature' }
Require-Rejection { Read-TrustedSignature $binary $publisher }
if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -cne $before) { throw 'Signature validation changed the native executable' }
$evidence = Join-Path $env:RUNNER_TEMP 'scarlett-unsigned-signature-fixture.json'
if (Test-Path -LiteralPath $evidence) { throw 'Signature fixture output already exists' }
$fixtureRoot = Join-Path $env:RUNNER_TEMP 'scarlett-signature-rejection-fixture'
if (Test-Path -LiteralPath $fixtureRoot) { throw 'Signature fixture directory already exists' }
New-Item -ItemType Directory -Path (Join-Path $fixtureRoot 'runtime') | Out-Null
Copy-Item -LiteralPath $binary -Destination (Join-Path $fixtureRoot 'scarlett-node-desktop.exe')
[System.IO.File]::WriteAllText((Join-Path $fixtureRoot 'runtime\COMPONENTS.json'), '{"syntheticOnly":true}', [System.Text.UTF8Encoding]::new($false))
Require-Rejection { Write-WindowsSignatureEvidence $binary $fixtureRoot $publisher $evidence }
if (Test-Path -LiteralPath $evidence) { throw 'Rejected signature wrote release evidence' }
. (Join-Path $PSScriptRoot 'sign-windows-file.ps1')
$signingRoot = Join-Path $fixtureRoot 'prepared'
New-Item -ItemType Directory -Path (Join-Path $signingRoot 'binaries') | Out-Null
$signingInput = Join-Path $signingRoot 'binaries\scarlett-node-x86_64-pc-windows-msvc.exe'
Copy-Item -LiteralPath $binary -Destination $signingInput
$signingBefore = (Get-FileHash -LiteralPath $signingInput -Algorithm SHA256).Hash
$savedRoot, $savedPublisher, $savedTool = $env:SCARLETT_WINDOWS_SIGNING_ROOT, $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT, $env:SCARLETT_WINDOWS_SIGNTOOL
try {
    $env:SCARLETT_WINDOWS_SIGNING_ROOT = $signingRoot
    $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT = $publisher
    # A real unsigned Go executable cannot substitute for the trusted SDK tool.
    # Reject it before opening any publisher key or invoking a signing command.
    $env:SCARLETT_WINDOWS_SIGNTOOL = $binary
    Require-Rejection { Sign-WindowsReleaseFile $signingInput }
    if ((Get-FileHash -LiteralPath $signingInput -Algorithm SHA256).Hash -cne $signingBefore) {
        throw 'Rejected signing-tool substitution changed the native executable'
    }
} finally {
    $env:SCARLETT_WINDOWS_SIGNING_ROOT, $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT, $env:SCARLETT_WINDOWS_SIGNTOOL = $savedRoot, $savedPublisher, $savedTool
}
Write-Output 'Signature record rejection contracts and actual native unsigned rejection passed; no release signature proven'
