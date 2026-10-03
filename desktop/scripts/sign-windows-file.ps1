# Use an existing current-user code-signing identity; never import/export keys
# or add trust roots. SCARLETT_SIGNING_SCHEME (self-signed-stable or
# authenticode) has no default; the pins come from the caller's environment.
param([string]$File = '')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'check-windows-signatures.ps1')
$ScarlettSigningIdentitiesPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\signing\identities.json'))

function Get-ReviewedTimestampUrl {
    $identities = [System.IO.File]::ReadAllText((Assert-RegularLocalFile $ScarlettSigningIdentitiesPath)) | ConvertFrom-Json
    $url = [string]$identities.windows.timestampUrl
    if (-not $url) { throw 'Reviewed RFC3161 timestamp endpoint missing' }
    return $url
}

function Find-WindowsSdkSignTool {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $tools = @(Get-ChildItem -LiteralPath $kits -Directory |
        Where-Object { $_.Name -match '^10(\.[0-9]+){3}$' } |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($tools.Count -lt 1) { throw 'Windows SDK SignTool not found' }
    return $tools[0]
}

function Assert-NSISPortableExecutable([string]$Path, [bool]$DLL) {
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $reader = $null
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($stream.Length -lt 64 -or $stream.Length -gt 64MB -or $reader.ReadUInt16() -ne 0x5a4d) {
            throw 'NSIS signing target must be a bounded native PE file'
        }
        $stream.Position = 60
        $offset = $reader.ReadUInt32()
        if ($offset -lt 64 -or $offset -gt $stream.Length - 26) { throw 'Invalid NSIS PE header offset' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x14c) {
            throw 'NSIS signing requires its pinned x86 PE architecture'
        }
        $sections = $reader.ReadUInt16()
        $stream.Position = $offset + 20
        $optionalBytes = $reader.ReadUInt16()
        $characteristics = $reader.ReadUInt16()
        if ($sections -lt 1 -or $sections -gt 96 -or $optionalBytes -lt 96 -or
            $offset + 24 + $optionalBytes + 40 * $sections -gt $stream.Length -or
            $reader.ReadUInt16() -ne 0x10b -or ($characteristics -band 2) -eq 0 -or
            (($characteristics -band 0x2000) -ne 0) -ne $DLL) {
            throw 'NSIS signing target has the wrong executable or DLL PE header'
        }
    } finally {
        try { if ($null -ne $reader) { $reader.Dispose() } }
        finally { $stream.Dispose() }
    }
}

function Assert-PreservedProviderResource([string]$Path, [string]$Root, [string]$Relative) {
    $manifest = Assert-RegularLocalFile ($Root + 'runtime\COMPONENTS.json')
    $metadata = [System.IO.File]::ReadAllText($manifest) | ConvertFrom-Json
    $release = $metadata.releaseSigning
    if ($metadata.schemaVersion -ne 1 -or $metadata.target -cne 'x86_64-pc-windows-msvc' -or
        $metadata.codexVersion -cne '0.159.2' -or $metadata.claudeVersion -cne '2.1.286' -or
        $metadata.modelApiVersion -cne '0.1.31' -or
        $release.vendorBytesPreserved -ne $true -or
        ([string]$release.scheme -cne 'self-signed-stable' -and [string]$release.scheme -cne 'authenticode') -or
        [string]$release.scheme -cne $env:SCARLETT_SIGNING_SCHEME -or
        [string]$release.certificateSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$release.certificateSha256 -cne $env:SCARLETT_WINDOWS_CERT_SHA256 -or
        $release.publisherThumbprint -notmatch '^[0-9a-fA-F]{40}$' -or
        $release.publisherThumbprint -ine $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT) {
        throw 'Provider preservation requires the finalized pinned release inventory'
    }
    $entries = @($metadata.files | Where-Object { $_.path -ceq $Relative.Substring(8) })
    if ($entries.Count -ne 1 -or (Get-Item -LiteralPath $Path).Length -ne $entries[0].bytes -or
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $entries[0].sha256) {
        throw 'Provider callback bytes differ from the exact pinned inventory'
    }
}

function Resolve-WindowsSigningTarget([string]$Path, $PreservedProvider = $null) {
    # Windows PowerShell cannot bind an omitted [ref] parameter to null.
    # Omission is allowed; an explicitly supplied flag must remain a reference.
    if ($PSBoundParameters.ContainsKey('PreservedProvider')) {
        if ($PreservedProvider -isnot [System.Management.Automation.PSReference]) {
            throw 'Explicit preservation flag must be a PowerShell reference'
        }
        $PreservedProvider.Value = $false
    }
    $resolved = Assert-RegularLocalFile $Path
    if ($env:SCARLETT_WINDOWS_SIGNING_ROOT -notmatch '^[a-zA-Z]:[\\/]' -or
        $env:SCARLETT_WINDOWS_SIGNING_ROOT.Substring(2).Contains(':')) {
        throw 'Explicit local prepared release directory required'
    }
    $root = [System.IO.Path]::GetFullPath($env:SCARLETT_WINDOWS_SIGNING_ROOT).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Signing target escaped the prepared release'
    }
    $relative = $resolved.Substring($root.Length).Replace('\', '/')
    if ($relative -match '^runtime/(codex|claude)/.+\.(exe|dll)$') {
        Assert-PreservedProviderResource $resolved $root $relative
        if ($null -ne $PreservedProvider) { $PreservedProvider.Value = $true }
        return $resolved
    }
    # Tauri CLI 2.12.1 copies and signs exactly these five NSIS plugins before
    # makensis. Permit the disposable copies, never the SDK/cache originals or
    # provider runtime. Keep this list aligned with its NSIS_PLUGIN_FILES.
    $nsisPlugins = @(
        'target/release/nsis/x64/Plugins/x86-unicode/NSISdl.dll',
        'target/release/nsis/x64/Plugins/x86-unicode/StartMenu.dll',
        'target/release/nsis/x64/Plugins/x86-unicode/System.dll',
        'target/release/nsis/x64/Plugins/x86-unicode/nsDialogs.dll',
        'target/release/nsis/x64/Plugins/x86-unicode/additional/nsis_tauri_utils.dll'
    )
    $isPlugin = $relative -in $nsisPlugins
    $isUninstaller = $false
    if ($relative -match '^target/release/nsis-signing-temp/nst[0-9a-f]{1,4}\.tmp$') {
        # NSIS 3.11 creates an x86 uninstaller with GetTempFileName("nst").
        # Its context is propagated only to this packaging child; system TEMP
        # and other directories under the build root never grant permission.
        $temporary = $root + 'target\release\nsis-signing-temp'
        foreach ($context in @($env:SCARLETT_WINDOWS_NSIS_TEMP, $env:TMP, $env:TEMP)) {
            if (-not $context -or [System.IO.Path]::GetFullPath($context).TrimEnd('\') -ine $temporary) {
                throw 'Generated uninstaller requires the isolated packaging context'
            }
        }
        $directory = Get-Item -LiteralPath $temporary -Force
        if (-not $directory.PSIsContainer) { throw 'Uninstaller context must be a regular directory' }
        Assert-NoReparseParents $directory
        $isUninstaller = $true
    }
    $allowed = $relative -match '^binaries/(scarlett-node|scarlett-prover|open-agent-api)-x86_64-pc-windows-msvc\.exe$' -or
        $relative -ceq 'target/release/scarlett-node-desktop.exe' -or
        $relative -match '^target/release/bundle/nsis/[^/]+\.exe$' -or $isPlugin -or $isUninstaller
    if (-not $allowed) { throw 'Only reviewed Scarlett and NSIS packaging targets may be signed' }
    if ($isPlugin -or $isUninstaller) { Assert-NSISPortableExecutable $resolved $isPlugin }
    return $resolved
}

function Sign-WindowsReleaseFile([string]$Path) {
    if ($env:OS -ne 'Windows_NT') { throw 'Signing requires native Windows' }
    $scheme = $env:SCARLETT_SIGNING_SCHEME
    Assert-SigningScheme $scheme
    $publisher = $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT
    if ($publisher -notmatch '^[0-9a-fA-F]{40}$') { throw 'Reviewed publisher thumbprint required' }
    $certificateSha256 = $env:SCARLETT_WINDOWS_CERT_SHA256
    if ($certificateSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Reviewed certificate SHA-256 required' }
    $preservedProvider = $false
    $resolved = Resolve-WindowsSigningTarget $Path ([ref]$preservedProvider)
    if ($preservedProvider) {
        # Tauri's resource callback accepts a successful preservation outcome.
        # Hash-verified provider bytes keep their existing signing status.
        Write-Output 'Pinned provider resource preserved; no publisher signature added'
        return
    }
    $tool = Assert-RegularLocalFile $env:SCARLETT_WINDOWS_SIGNTOOL
    $toolSignature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $tool
    if ([string]$toolSignature.Status -cne 'Valid' -or
        [string]$toolSignature.SignatureType -cne 'Authenticode' -or
        -not $toolSignature.SignerCertificate -or
        $toolSignature.SignerCertificate.Subject -notmatch '(?i)Microsoft') {
        throw 'Use the Windows-trusted Microsoft SDK SignTool'
    }
    # An exact reviewed RFC3161 endpoint. The token is signed and verified, so
    # its transport carries no trust; any other endpoint is refused.
    $timestamp = Get-ReviewedTimestampUrl
    if ($env:SCARLETT_WINDOWS_TIMESTAMP_URL -cne $timestamp) {
        throw 'Use the reviewed RFC3161 timestamp endpoint'
    }
    $certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $publisher) -ErrorAction SilentlyContinue
    $usages = @($certificate.Extensions |
        Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
        ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
    if (-not $certificate -or -not $certificate.HasPrivateKey -or
        $certificate.NotBefore -gt [DateTime]::Now -or $certificate.NotAfter -le [DateTime]::Now -or
        '1.3.6.1.5.5.7.3.3' -notin $usages -or (Get-CertificateSha256 $certificate) -cne $certificateSha256) {
        throw 'Existing valid publisher code-signing identity required'
    }
    # self-signed-stable signs only with the self-issued pinned certificate;
    # authenticode never accepts a self-issued one.
    if (($scheme -ceq 'self-signed-stable') -ne ($certificate.Issuer -ceq $certificate.Subject)) {
        throw 'Publisher certificate does not fit the selected signing scheme'
    }
    # Tauri 2.12.1 invokes this callback again for already signed sidecars and
    # the main executable. Keep our pinned signature byte for byte so finalized
    # component hashes remain valid; refuse any other existing signature.
    if (Test-PinnedSignature $resolved $publisher $scheme $certificateSha256) { return }
    $nativeOutput = & $tool sign /q /s My /sha1 $publisher /fd SHA256 /tr $timestamp /td SHA256 $resolved 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Native signing or timestamping failed' }
    $nativeOutput = $null
    Read-TrustedSignature $resolved $publisher $scheme $certificateSha256 | Out-Null
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Sign-WindowsReleaseFile $File }
    catch { throw 'Windows release signing failed; artifact is not approved for publication' }
}
