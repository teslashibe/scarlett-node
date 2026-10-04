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

function Write-NSISPEFixture([string]$Path, [bool]$DLL) {
    # Header-only synthetic x86 PE: exercises guards, never executed or signed.
    $bytes = [byte[]]::new(512)
    [BitConverter]::GetBytes([uint16]0x5a4d).CopyTo($bytes, 0)
    [BitConverter]::GetBytes([uint32]128).CopyTo($bytes, 60)
    [BitConverter]::GetBytes([uint32]0x4550).CopyTo($bytes, 128)
    [BitConverter]::GetBytes([uint16]0x14c).CopyTo($bytes, 132)
    [BitConverter]::GetBytes([uint16]1).CopyTo($bytes, 134)
    [BitConverter]::GetBytes([uint16]224).CopyTo($bytes, 148)
    $flags = 0x102
    if ($DLL) { $flags = $flags -bor 0x2000 }
    [BitConverter]::GetBytes([uint16]$flags).CopyTo($bytes, 150)
    [BitConverter]::GetBytes([uint16]0x10b).CopyTo($bytes, 152)
    [System.IO.File]::WriteAllBytes($Path, $bytes)
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
$signingRoot = Join-Path $fixtureRoot 'prepared NSIS copy'
New-Item -ItemType Directory -Path (Join-Path $signingRoot 'binaries') | Out-Null
$signingInput = Join-Path $signingRoot 'binaries\scarlett-node-x86_64-pc-windows-msvc.exe'
Copy-Item -LiteralPath $binary -Destination $signingInput
$signingBefore = (Get-FileHash -LiteralPath $signingInput -Algorithm SHA256).Hash
$savedRoot, $savedPublisher, $savedTool = $env:SCARLETT_WINDOWS_SIGNING_ROOT, $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT, $env:SCARLETT_WINDOWS_SIGNTOOL
$savedNSISTemp, $savedTMP, $savedTEMP = $env:SCARLETT_WINDOWS_NSIS_TEMP, $env:TMP, $env:TEMP
try {
    $env:SCARLETT_WINDOWS_SIGNING_ROOT = $signingRoot
    $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT = $publisher
    if ((Resolve-WindowsSigningTarget $signingInput) -cne [System.IO.Path]::GetFullPath($signingInput)) {
        throw 'Ordinary target with omitted preservation flag was rejected'
    }
    $preserved = $true
    Resolve-WindowsSigningTarget $signingInput ([ref]$preserved) | Out-Null
    if ($preserved -ne $false) { throw 'Ordinary target incorrectly reported provider preservation' }
    foreach ($invalid in @($null, 'not a reference', @{ Value = $false })) {
        Require-Rejection { Resolve-WindowsSigningTarget $signingInput -PreservedProvider $invalid }
    }
    foreach ($relative in @('binaries/scarlett-prover-x86_64-pc-windows-msvc.exe',
        'binaries/open-agent-api-x86_64-pc-windows-msvc.exe',
        'target/release/scarlett-node-desktop.exe', 'target/release/bundle/nsis/Scarlett setup.exe')) {
        $target = Join-Path $signingRoot $relative
        New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($target)) -Force | Out-Null
        Copy-Item -LiteralPath $binary -Destination $target
        if ((Resolve-WindowsSigningTarget $target) -cne [System.IO.Path]::GetFullPath($target)) {
            throw 'Existing Scarlett signing target was rejected'
        }
    }
    # A real unsigned Go executable cannot substitute for the trusted SDK tool.
    # Reject it before opening any publisher key or invoking a signing command.
    $env:SCARLETT_WINDOWS_SIGNTOOL = $binary
    Require-Rejection { Sign-WindowsReleaseFile $signingInput }
    if ((Get-FileHash -LiteralPath $signingInput -Algorithm SHA256).Hash -cne $signingBefore) {
        throw 'Rejected signing-tool substitution changed the native executable'
    }
    # Model the exact pinned Tauri 2.12.1 NSIS callback targets with synthetic
    # x86 DLL headers. Resolve only; no publisher key is opened.
    $plugins = @('NSISdl.dll', 'StartMenu.dll', 'System.dll', 'nsDialogs.dll', 'additional/nsis_tauri_utils.dll')
    $pluginRoot = Join-Path $signingRoot 'target/release/nsis/x64/Plugins/x86-unicode'
    foreach ($plugin in $plugins) {
        $target = Join-Path $pluginRoot $plugin
        New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($target)) -Force | Out-Null
        Write-NSISPEFixture $target $true
        $before = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        if ((Resolve-WindowsSigningTarget $target) -cne [System.IO.Path]::GetFullPath($target)) {
            throw 'Pinned NSIS callback target was not preserved as one absolute path'
        }
        # The same target must still fail the unsigned SignTool substitution,
        # before certificate lookup or any native signing operation.
        Require-Rejection { Sign-WindowsReleaseFile $target }
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -cne $before) {
            throw 'NSIS target validation changed the native fixture'
        }
    }
    foreach ($relative in @('target/release/nsis/x64/Plugins/x86-unicode/unexpected.dll',
        'target/release/nsis/x64/Plugins/x86-unicode/nested/System.dll',
        'target/release/nsis/arm64/Plugins/x86-unicode/System.dll',
        'target/release/nsis/x64/System.dll', 'runtime/codex/System.dll',
        'cache/Plugins/x86-unicode/System.dll')) {
        $target = Join-Path $signingRoot $relative
        New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($target)) -Force | Out-Null
        Copy-Item -LiteralPath $binary -Destination $target
        Require-Rejection { Resolve-WindowsSigningTarget $target }
    }
    # A matching basename outside the prepared root must still be rejected.
    $outside = Join-Path $fixtureRoot 'outside NSIS copy/x86-unicode/System.dll'
    New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($outside)) -Force | Out-Null
    Write-NSISPEFixture $outside $true
    $outsideBefore = (Get-FileHash -LiteralPath $outside -Algorithm SHA256).Hash
    Require-Rejection { Resolve-WindowsSigningTarget $outside }
    Require-Rejection { Resolve-WindowsSigningTarget ($outside + ':alternate-stream') }
    Require-Rejection { Resolve-WindowsSigningTarget $pluginRoot }
    $plugin = Join-Path $pluginRoot 'System.dll'
    Copy-Item -LiteralPath $binary -Destination $plugin -Force
    Require-Rejection { Resolve-WindowsSigningTarget $plugin } # Wrong x64 architecture
    Write-NSISPEFixture $plugin $false
    Require-Rejection { Resolve-WindowsSigningTarget $plugin } # EXE is not a plugin DLL
    [System.IO.File]::WriteAllText($plugin, 'not a portable executable')
    Require-Rejection { Resolve-WindowsSigningTarget $plugin }

    $nsisTemp = Join-Path $signingRoot 'target/release/nsis-signing-temp'
    New-Item -ItemType Directory -Path $nsisTemp | Out-Null
    $env:SCARLETT_WINDOWS_NSIS_TEMP, $env:TMP, $env:TEMP = $nsisTemp, $nsisTemp, $nsisTemp
    foreach ($name in @('nst1.tmp', 'nstFFFF.tmp')) {
        $target = Join-Path $nsisTemp $name
        Write-NSISPEFixture $target $false
        $before = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        if ((Resolve-WindowsSigningTarget $target) -cne [System.IO.Path]::GetFullPath($target)) {
            throw 'Generated NSIS uninstaller callback path was rejected'
        }
        Require-Rejection { Sign-WindowsReleaseFile $target }
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -cne $before) {
            throw 'Uninstaller target validation changed the fixture'
        }
    }
    $target = Join-Path $nsisTemp 'nst1.tmp'
    $env:SCARLETT_WINDOWS_NSIS_TEMP = $null
    Require-Rejection { Resolve-WindowsSigningTarget $target }
    $env:SCARLETT_WINDOWS_NSIS_TEMP = $nsisTemp
    $env:TMP = $fixtureRoot
    Require-Rejection { Resolve-WindowsSigningTarget $target }
    $env:TMP = $nsisTemp
    $outsideUninstaller = Join-Path $fixtureRoot 'outside NSIS uninstaller/nst1.tmp'
    New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($outsideUninstaller)) -Force | Out-Null
    Write-NSISPEFixture $outsideUninstaller $false
    Require-Rejection { Resolve-WindowsSigningTarget $outsideUninstaller }
    foreach ($name in @('uninstall.exe', 'provider.exe', 'nst12345.tmp', 'nested/nst1.tmp')) {
        $target = Join-Path $nsisTemp $name
        New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($target)) -Force | Out-Null
        Write-NSISPEFixture $target $false
        Require-Rejection { Resolve-WindowsSigningTarget $target }
    }
    $target = Join-Path $nsisTemp 'nstA.tmp'
    Copy-Item -LiteralPath $binary -Destination $target
    Require-Rejection { Resolve-WindowsSigningTarget $target } # Native provider/Go PE is x64
    Write-NSISPEFixture $target $true
    Require-Rejection { Resolve-WindowsSigningTarget $target } # Plugin DLL is not an uninstaller

    # Tauri may callback for unsigned resources. Exact finalized vendor bytes
    # return successfully without opening a key or adding a publisher signature.
    $provider = Join-Path $signingRoot 'runtime/codex/bin/codex.exe'
    New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($provider)) -Force | Out-Null
    Copy-Item -LiteralPath $binary -Destination $provider
    $providerHash = (Get-FileHash -LiteralPath $provider -Algorithm SHA256).Hash
    $metadata = @{ schemaVersion = 1; target = 'x86_64-pc-windows-msvc'; codexVersion = '0.159.2'
        claudeVersion = '2.1.286'; modelApiVersion = '0.1.32'
        releaseSigning = @{ publisherThumbprint = $publisher; vendorBytesPreserved = $true }
        files = @(@{ path = 'codex/bin/codex.exe'; bytes = (Get-Item -LiteralPath $provider).Length; sha256 = $providerHash }) }
    $providerDLL = Join-Path $signingRoot 'runtime/claude/provider.dll'
    New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($providerDLL)) -Force | Out-Null
    Write-NSISPEFixture $providerDLL $true
    $providerDLLHash = (Get-FileHash -LiteralPath $providerDLL -Algorithm SHA256).Hash
    $metadata.files += @{ path = 'claude/provider.dll'; bytes = (Get-Item -LiteralPath $providerDLL).Length; sha256 = $providerDLLHash }
    $manifest = Join-Path $signingRoot 'runtime/COMPONENTS.json'
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest
    $preserved = $false
    Resolve-WindowsSigningTarget $provider ([ref]$preserved) | Out-Null
    if ($preserved -ne $true) { throw 'Exact provider target did not report preservation through its reference' }
    Sign-WindowsReleaseFile $provider | Out-Null
    Sign-WindowsReleaseFile $providerDLL | Out-Null
    if ((Get-FileHash -LiteralPath $provider -Algorithm SHA256).Hash -cne $providerHash) {
        throw 'Provider preservation callback changed the native fixture'
    }
    if ((Get-FileHash -LiteralPath $providerDLL -Algorithm SHA256).Hash -cne $providerDLLHash) {
        throw 'Provider DLL preservation callback changed the fixture'
    }
    foreach ($oldApiVersion in @('0.1.29', '0.1.30', '0.1.31')) {
        $metadata.modelApiVersion = $oldApiVersion
        $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest
        Require-Rejection { Resolve-WindowsSigningTarget $provider }
    }
    $metadata.modelApiVersion = '0.1.32'
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest
    $unknown = Join-Path $signingRoot 'runtime/codex/bin/unknown.exe'
    Copy-Item -LiteralPath $binary -Destination $unknown
    Require-Rejection { Resolve-WindowsSigningTarget $unknown }
    [System.IO.File]::WriteAllText($provider, 'changed vendor')
    Require-Rejection { Resolve-WindowsSigningTarget $provider }
    Copy-Item -LiteralPath $binary -Destination $provider -Force
    $metadata.files += $metadata.files[0]
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest
    Require-Rejection { Resolve-WindowsSigningTarget $provider }
    $metadata.files = @($metadata.files[0])
    $metadata.releaseSigning = $null
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest
    Require-Rejection { Resolve-WindowsSigningTarget $provider }
    # Junctions exercise the same reparse-parent rejection as symlinked
    # directories, without requiring file-symlink creation privileges.
    $reparseRoot = Join-Path $fixtureRoot 'prepared-reparse'
    $junction = Join-Path $reparseRoot 'target/release/nsis/x64/Plugins'
    New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($junction)) -Force | Out-Null
    New-Item -ItemType Junction -Path $junction -Target (Join-Path $fixtureRoot 'outside NSIS copy') | Out-Null
    $env:SCARLETT_WINDOWS_SIGNING_ROOT = $reparseRoot
    Require-Rejection { Resolve-WindowsSigningTarget (Join-Path $junction 'x86-unicode/System.dll') }
    if ((Get-FileHash -LiteralPath $outside -Algorithm SHA256).Hash -cne $outsideBefore) {
        throw 'Reparse rejection changed the outside native fixture'
    }
    $junction = Join-Path $reparseRoot 'target/release/nsis-signing-temp'
    New-Item -ItemType Junction -Path $junction -Target ([System.IO.Path]::GetDirectoryName($outsideUninstaller)) | Out-Null
    $env:SCARLETT_WINDOWS_NSIS_TEMP, $env:TMP, $env:TEMP = $junction, $junction, $junction
    Require-Rejection { Resolve-WindowsSigningTarget (Join-Path $junction 'nst1.tmp') }
} finally {
    $env:SCARLETT_WINDOWS_SIGNING_ROOT, $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT, $env:SCARLETT_WINDOWS_SIGNTOOL = $savedRoot, $savedPublisher, $savedTool
    $env:SCARLETT_WINDOWS_NSIS_TEMP, $env:TMP, $env:TEMP = $savedNSISTemp, $savedTMP, $savedTEMP
}
Write-Output 'Signature record rejection contracts and actual native unsigned rejection passed; no release signature proven'
