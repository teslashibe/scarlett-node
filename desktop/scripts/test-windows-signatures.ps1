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
Assert-SignatureRecord $valid $publisher 'authenticode'
foreach ($status in @('NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError')) {
    $record = $valid.Clone(); $record.Status = $status
    Require-Rejection { Assert-SignatureRecord $record $publisher 'authenticode' }
}
$record = $valid.Clone(); $record.SignatureType = 'Catalog'
Require-Rejection { Assert-SignatureRecord $record $publisher 'authenticode' }
$record = $valid.Clone(); $record.TimeStamperCertificate = $null
Require-Rejection { Assert-SignatureRecord $record $publisher 'authenticode' }
Require-Rejection { Assert-SignatureRecord $valid ('f' * 40) 'authenticode' }
Require-Rejection { Assert-SignatureRecord $valid 'invalid-thumbprint' 'authenticode' }
$record = $valid.Clone(); $record.SignerCertificate = @{ Thumbprint = $publisher; Issuer = 'Self'; Subject = 'Self' }
Require-Rejection { Assert-SignatureRecord $record $publisher 'authenticode' }
# The scheme is explicit; there is no default and no unsigned scheme.
foreach ($scheme in @('', 'developer-id', 'unsigned', 'Authenticode')) {
    Require-Rejection { Assert-SignatureRecord $valid $publisher $scheme }
}

# self-signed-stable: Authenticode + UnknownError + exact CERT_E_UNTRUSTEDROOT,
# a self-issued signer matching both pins, and a timestamp.
$rawCertificate = [byte[]](1..64)
$rawSha256 = Get-CertificateSha256 @{ RawData = $rawCertificate }
$untrustedRoot = [uint32]2148204809
if (('0x{0:X8}' -f $untrustedRoot) -cne '0x800B0109') { throw 'Untrusted-root constant changed' }
$selfIssued = @{ Thumbprint = $publisher; Issuer = 'CN=Scarlett Node Self-Signed Windows, O=Scarlett'
    Subject = 'CN=Scarlett Node Self-Signed Windows, O=Scarlett'; RawData = $rawCertificate }
$untrusted = @{ Status = 'UnknownError'; SignatureType = 'Authenticode'; SignerCertificate = $selfIssued
    TimeStamperCertificate = @{ fixture = $true } }
Assert-SignatureRecord $untrusted $publisher 'self-signed-stable' $rawSha256 $untrustedRoot
# A bare UnknownError without exactly 0x800B0109 (bad digest, no signature,
# revoked, success or nothing) is rejected.
foreach ($code in @($null, [uint32]0, [uint32]2148098064, [uint32]2148204800, [uint32]2148204812, [int]-2146762487)) {
    Require-Rejection { Assert-SignatureRecord $untrusted $publisher 'self-signed-stable' $rawSha256 $code }
}
# Valid would mean the certificate was added as a trusted root.
foreach ($status in @('Valid', 'NotSigned', 'HashMismatch', 'NotTrusted')) {
    $record = $untrusted.Clone(); $record.Status = $status
    Require-Rejection { Assert-SignatureRecord $record $publisher 'self-signed-stable' $rawSha256 $untrustedRoot }
}
Require-Rejection { Assert-SignatureRecord $untrusted ('f' * 40) 'self-signed-stable' $rawSha256 $untrustedRoot }
Require-Rejection { Assert-SignatureRecord $untrusted $publisher 'self-signed-stable' ('0' * 64) $untrustedRoot }
Require-Rejection { Assert-SignatureRecord $untrusted $publisher 'self-signed-stable' $rawSha256.ToUpperInvariant() $untrustedRoot }
Require-Rejection { Assert-SignatureRecord $untrusted $publisher 'self-signed-stable' '' $untrustedRoot }
Require-Rejection { Assert-SignatureRecord $untrusted $publisher 'authenticode' $rawSha256 $untrustedRoot }
# Issuer == Subject is accepted only for this mode with matching pins.
$record = $untrusted.Clone()
$record.SignerCertificate = @{ Thumbprint = $publisher; Issuer = 'CN=Some CA'; Subject = 'CN=Scarlett'; RawData = $rawCertificate }
Require-Rejection { Assert-SignatureRecord $record $publisher 'self-signed-stable' $rawSha256 $untrustedRoot }
$record = $untrusted.Clone(); $record.SignerCertificate = @{ Thumbprint = $publisher; Issuer = 'CN=Self'; Subject = 'CN=Self' }
Require-Rejection { Assert-SignatureRecord $record $publisher 'self-signed-stable' $rawSha256 $untrustedRoot }
$record = $untrusted.Clone(); $record.TimeStamperCertificate = $null
Require-Rejection { Assert-SignatureRecord $record $publisher 'self-signed-stable' $rawSha256 $untrustedRoot }
$record = $untrusted.Clone(); $record.SignatureType = 'Catalog'
Require-Rejection { Assert-SignatureRecord $record $publisher 'self-signed-stable' $rawSha256 $untrustedRoot }
Require-Rejection { Assert-TimestampChain @{ fixture = $true } }
Require-Rejection { Assert-TimestampChain $null }
Require-Rejection { Assert-RegularLocalFile '\\server\share\fixture.exe' }
Require-Rejection { Assert-RegularLocalFile 'C:\fixture.exe:alternate-stream' }

# Exercise the actual OS verifier against the native CI Go executable, not a
# mocked status, with no signing certificate/trust-store creation or mutation
$binary = Assert-RegularLocalFile ([System.IO.Path]::GetFullPath($UnsignedNativeBinary))
$before = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
$actual = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $binary
if ([string]$actual.Status -cne 'NotSigned') { throw 'Native unsigned rejection fixture unexpectedly has a signature' }
if ((Get-WinVerifyTrustResult $binary) -ne [uint32]2148204800) { throw 'WinVerifyTrust must report TRUST_E_NOSIGNATURE for the unsigned executable' }
Require-Rejection { Read-TrustedSignature $binary $publisher 'authenticode' }
Require-Rejection { Read-TrustedSignature $binary $publisher 'self-signed-stable' $rawSha256 }
if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -cne $before) { throw 'Signature validation changed the native executable' }
$evidence = Join-Path $env:RUNNER_TEMP 'scarlett-unsigned-signature-fixture.json'
if (Test-Path -LiteralPath $evidence) { throw 'Signature fixture output already exists' }
$fixtureRoot = Join-Path $env:RUNNER_TEMP 'scarlett-signature-rejection-fixture'
if (Test-Path -LiteralPath $fixtureRoot) { throw 'Signature fixture directory already exists' }
New-Item -ItemType Directory -Path (Join-Path $fixtureRoot 'runtime') | Out-Null
Copy-Item -LiteralPath $binary -Destination (Join-Path $fixtureRoot 'scarlett-node-desktop.exe')
[System.IO.File]::WriteAllText((Join-Path $fixtureRoot 'runtime\COMPONENTS.json'), '{"syntheticOnly":true}', [System.Text.UTF8Encoding]::new($false))
Require-Rejection { Write-WindowsSignatureEvidence -Setup $binary -Installed $fixtureRoot -PublisherThumbprint $publisher -Scheme 'authenticode' -CertificateSha256 '' -Output $evidence }
Require-Rejection { Write-WindowsSignatureEvidence -Setup $binary -Installed $fixtureRoot -PublisherThumbprint $publisher -Scheme 'self-signed-stable' -CertificateSha256 $rawSha256 -Output $evidence }
if (Test-Path -LiteralPath $evidence) { throw 'Rejected signature wrote release evidence' }
. (Join-Path $PSScriptRoot 'sign-windows-file.ps1')
$signingRoot = Join-Path $fixtureRoot 'prepared NSIS copy'
New-Item -ItemType Directory -Path (Join-Path $signingRoot 'binaries') | Out-Null
$signingInput = Join-Path $signingRoot 'binaries\scarlett-node-x86_64-pc-windows-msvc.exe'
Copy-Item -LiteralPath $binary -Destination $signingInput
$signingBefore = (Get-FileHash -LiteralPath $signingInput -Algorithm SHA256).Hash
$savedRoot, $savedPublisher, $savedTool = $env:SCARLETT_WINDOWS_SIGNING_ROOT, $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT, $env:SCARLETT_WINDOWS_SIGNTOOL
$savedNSISTemp, $savedTMP, $savedTEMP = $env:SCARLETT_WINDOWS_NSIS_TEMP, $env:TMP, $env:TEMP
$savedScheme, $savedSha256, $savedTimestamp = $env:SCARLETT_SIGNING_SCHEME, $env:SCARLETT_WINDOWS_CERT_SHA256, $env:SCARLETT_WINDOWS_TIMESTAMP_URL
try {
    $env:SCARLETT_WINDOWS_SIGNING_ROOT = $signingRoot
    $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT = $publisher
    $env:SCARLETT_SIGNING_SCHEME = 'self-signed-stable'
    $env:SCARLETT_WINDOWS_CERT_SHA256 = $rawSha256
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
        releaseSigning = @{ scheme = 'self-signed-stable'; publisherThumbprint = $publisher; certificateSha256 = $rawSha256
            vendorBytesPreserved = $true }
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
    # The finalized inventory must name the same scheme and certificate pin.
    $env:SCARLETT_SIGNING_SCHEME = 'authenticode'
    Require-Rejection { Resolve-WindowsSigningTarget $provider }
    Require-Rejection { Sign-WindowsReleaseFile $provider }
    $env:SCARLETT_SIGNING_SCHEME = 'self-signed-stable'
    $env:SCARLETT_WINDOWS_CERT_SHA256 = 'f' * 64
    Require-Rejection { Resolve-WindowsSigningTarget $provider }
    $env:SCARLETT_WINDOWS_CERT_SHA256 = $null
    Require-Rejection { Sign-WindowsReleaseFile $provider }
    $env:SCARLETT_WINDOWS_CERT_SHA256 = $rawSha256
    $env:SCARLETT_SIGNING_SCHEME = $null
    Require-Rejection { Sign-WindowsReleaseFile $provider }
    $env:SCARLETT_SIGNING_SCHEME = 'self-signed-stable'
    Resolve-WindowsSigningTarget $provider | Out-Null
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
    $env:SCARLETT_SIGNING_SCHEME, $env:SCARLETT_WINDOWS_CERT_SHA256, $env:SCARLETT_WINDOWS_TIMESTAMP_URL = $savedScheme, $savedSha256, $savedTimestamp
}

# Native self-signed fixture with no secrets: two ephemeral RSA-3072 code-signing
# certificates exist only in CurrentUser\My for this run and are never trusted.
# The real signer, SDK SignTool and the reviewed DigiCert RFC3161 endpoint sign
# a copy of the Go executable; WinVerifyTrust must then report exactly
# CERT_E_UNTRUSTEDROOT, and tampering or a different certificate must fail.
$certificates = @()
$nativeRoot = Join-Path $env:RUNNER_TEMP 'scarlett-self-signed-fixture'
if (Test-Path -LiteralPath $nativeRoot) { throw 'Self-signed fixture directory already exists' }
$savedRoot, $savedPublisher, $savedTool = $env:SCARLETT_WINDOWS_SIGNING_ROOT, $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT, $env:SCARLETT_WINDOWS_SIGNTOOL
$savedScheme, $savedSha256, $savedTimestamp = $env:SCARLETT_SIGNING_SCHEME, $env:SCARLETT_WINDOWS_CERT_SHA256, $env:SCARLETT_WINDOWS_TIMESTAMP_URL
try {
    foreach ($suffix in @('A', 'B')) {
        $certificates += New-SelfSignedCertificate -Type CodeSigningCert -Subject ('CN=Scarlett Node Rehearsal Windows ' + $suffix + ', O=Scarlett Rehearsal') `
            -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
            -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(1)
    }
    $first, $second = $certificates
    foreach ($certificate in $certificates) {
        if ($certificate.Issuer -cne $certificate.Subject) { throw 'Fixture certificates must be self-issued' }
        foreach ($root in @('Cert:\CurrentUser\Root\', 'Cert:\LocalMachine\Root\')) {
            if (Test-Path -LiteralPath ($root + $certificate.Thumbprint)) { throw 'A fixture certificate must never be a trusted root' }
        }
    }
    $firstSha256, $secondSha256 = (Get-CertificateSha256 $first), (Get-CertificateSha256 $second)
    $nativeTarget = Join-Path $nativeRoot 'binaries\scarlett-node-x86_64-pc-windows-msvc.exe'
    New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($nativeTarget)) | Out-Null
    Copy-Item -LiteralPath $binary -Destination $nativeTarget
    $unsignedHash = (Get-FileHash -LiteralPath $nativeTarget -Algorithm SHA256).Hash
    $env:SCARLETT_SIGNING_SCHEME = 'self-signed-stable'
    $env:SCARLETT_WINDOWS_SIGNING_ROOT = $nativeRoot
    $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT = $first.Thumbprint
    $env:SCARLETT_WINDOWS_CERT_SHA256 = $firstSha256
    $env:SCARLETT_WINDOWS_SIGNTOOL = Find-WindowsSdkSignTool
    $env:SCARLETT_WINDOWS_TIMESTAMP_URL = 'https://timestamp.digicert.com'
    Require-Rejection { Sign-WindowsReleaseFile $nativeTarget } # Not the exact reviewed endpoint
    $env:SCARLETT_WINDOWS_TIMESTAMP_URL = Get-ReviewedTimestampUrl
    if ((Get-FileHash -LiteralPath $nativeTarget -Algorithm SHA256).Hash -cne $unsignedHash) { throw 'Rejected endpoint changed the executable' }
    Sign-WindowsReleaseFile $nativeTarget
    $signedHash = (Get-FileHash -LiteralPath $nativeTarget -Algorithm SHA256).Hash
    $trust = Get-WinVerifyTrustResult $nativeTarget
    if ($trust -ne $untrustedRoot) { throw ('Expected CERT_E_UNTRUSTEDROOT, WinVerifyTrust returned 0x{0:X8}' -f $trust) }
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $nativeTarget
    if ([string]$signature.Status -cne 'UnknownError' -or -not $signature.TimeStamperCertificate) {
        throw 'Self-signed fixture must be UnknownError with a timestamp'
    }
    Read-TrustedSignature $nativeTarget $first.Thumbprint 'self-signed-stable' $firstSha256 | Out-Null
    # Tauri calls the hook again for signed sidecars: our pinned signature stays byte for byte.
    Sign-WindowsReleaseFile $nativeTarget
    if ((Get-FileHash -LiteralPath $nativeTarget -Algorithm SHA256).Hash -cne $signedHash) { throw 'Re-invoking the signer changed a pinned signature' }
    # A second ephemeral certificate is another identity: rejected, never re-signed over.
    Require-Rejection { Read-TrustedSignature $nativeTarget $second.Thumbprint 'self-signed-stable' $secondSha256 }
    Require-Rejection { Read-TrustedSignature $nativeTarget $first.Thumbprint 'self-signed-stable' $secondSha256 }
    Require-Rejection { Read-TrustedSignature $nativeTarget $first.Thumbprint 'authenticode' $firstSha256 }
    $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT, $env:SCARLETT_WINDOWS_CERT_SHA256 = $second.Thumbprint, $secondSha256
    Require-Rejection { Sign-WindowsReleaseFile $nativeTarget }
    $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT, $env:SCARLETT_WINDOWS_CERT_SHA256 = $first.Thumbprint, $secondSha256
    Require-Rejection { Sign-WindowsReleaseFile $nativeTarget }
    $env:SCARLETT_SIGNING_SCHEME, $env:SCARLETT_WINDOWS_CERT_SHA256 = 'authenticode', $firstSha256
    Require-Rejection { Sign-WindowsReleaseFile $nativeTarget } # A self-issued key never signs as authenticode
    if ((Get-FileHash -LiteralPath $nativeTarget -Algorithm SHA256).Hash -cne $signedHash) { throw 'A rejected signer changed the executable' }
    # One flipped byte: HashMismatch, a digest failure rather than an untrusted root.
    $tampered = Join-Path $nativeRoot 'tampered.exe'
    $bytes = [System.IO.File]::ReadAllBytes($nativeTarget)
    $offset = [int]($bytes.Length / 2)
    $bytes[$offset] = $bytes[$offset] -bxor 0xFF
    [System.IO.File]::WriteAllBytes($tampered, $bytes)
    if ([string](Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $tampered).Status -cne 'HashMismatch') {
        throw 'A flipped byte must produce HashMismatch'
    }
    if ((Get-WinVerifyTrustResult $tampered) -eq $untrustedRoot) { throw 'A tampered file reported only an untrusted root' }
    Require-Rejection { Read-TrustedSignature $tampered $first.Thumbprint 'self-signed-stable' $firstSha256 }
    # Release evidence over an install-shaped copy of the signed executable.
    $installed = Join-Path $nativeRoot 'installed'
    New-Item -ItemType Directory -Path (Join-Path $installed 'runtime') | Out-Null
    foreach ($name in @('scarlett-node-desktop', 'scarlett-node', 'scarlett-prover', 'open-agent-api')) {
        Copy-Item -LiteralPath $nativeTarget -Destination (Join-Path $installed ($name + '.exe'))
    }
    [System.IO.File]::WriteAllText((Join-Path $installed 'runtime\COMPONENTS.json'), '{"syntheticOnly":true}', [System.Text.UTF8Encoding]::new($false))
    $setup = Join-Path $nativeRoot 'Scarlett Node setup.exe'
    Copy-Item -LiteralPath $nativeTarget -Destination $setup
    $nativeEvidence = Join-Path $nativeRoot 'signatures.json'
    Require-Rejection { Write-WindowsSignatureEvidence -Setup $setup -Installed $installed -PublisherThumbprint $first.Thumbprint -Scheme 'self-signed-stable' -CertificateSha256 $secondSha256 -Output $nativeEvidence }
    if (Test-Path -LiteralPath $nativeEvidence) { throw 'Rejected self-signed evidence was written' }
    Write-WindowsSignatureEvidence -Setup $setup -Installed $installed -PublisherThumbprint $first.Thumbprint -Scheme 'self-signed-stable' -CertificateSha256 $firstSha256 -Output $nativeEvidence
    $recorded = [System.IO.File]::ReadAllText($nativeEvidence) | ConvertFrom-Json
    if ($recorded.signature -cne 'self-signed-stable' -or $recorded.trustResult -cne '0x800B0109' -or
        $recorded.certificateSha256 -cne $firstSha256 -or $recorded.publisherThumbprint -cne $first.Thumbprint.ToUpperInvariant() -or
        $recorded.installer.sha256 -cne $signedHash.ToLowerInvariant()) {
        throw 'Self-signed release evidence does not record the pinned outcome'
    }
} finally {
    foreach ($certificate in $certificates) {
        Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $certificate.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue
        # New-SelfSignedCertificate can also leave a public copy among intermediate CAs.
        Remove-Item -LiteralPath ('Cert:\CurrentUser\CA\' + $certificate.Thumbprint) -ErrorAction SilentlyContinue
    }
    $env:SCARLETT_WINDOWS_SIGNING_ROOT, $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT, $env:SCARLETT_WINDOWS_SIGNTOOL = $savedRoot, $savedPublisher, $savedTool
    $env:SCARLETT_SIGNING_SCHEME, $env:SCARLETT_WINDOWS_CERT_SHA256, $env:SCARLETT_WINDOWS_TIMESTAMP_URL = $savedScheme, $savedSha256, $savedTimestamp
}
foreach ($certificate in $certificates) {
    foreach ($store in @('Cert:\CurrentUser\My\', 'Cert:\CurrentUser\CA\')) {
        if (Test-Path -LiteralPath ($store + $certificate.Thumbprint)) { throw 'Ephemeral fixture certificate was not removed' }
    }
}
Write-Output 'Signature contracts, native unsigned rejection and the ephemeral self-signed sign/verify/tamper fixture passed; no release key used'
