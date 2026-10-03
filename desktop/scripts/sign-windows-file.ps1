# Use an existing current-user code-signing identity; never import/export keys
param([string]$File = '')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'check-windows-signatures.ps1')

function Sign-WindowsReleaseFile([string]$Path) {
    if ($env:OS -ne 'Windows_NT') { throw 'Signing requires native Windows' }
    $publisher = $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT
    if ($publisher -notmatch '^[0-9a-fA-F]{40}$') { throw 'Reviewed publisher thumbprint required' }
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
    $allowed = $relative -match '^binaries/(scarlett-node|scarlett-prover|open-agent-api)-x86_64-pc-windows-msvc\.exe$' -or
        $relative -ceq 'target/release/scarlett-node-desktop.exe' -or
        $relative -match '^target/release/bundle/nsis/[^/]+\.exe$'
    if (-not $allowed) { throw 'Only Scarlett executables and the release installer may be signed' }
    $tool = Assert-RegularLocalFile $env:SCARLETT_WINDOWS_SIGNTOOL
    $toolSignature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $tool
    if ([string]$toolSignature.Status -cne 'Valid' -or
        [string]$toolSignature.SignatureType -cne 'Authenticode' -or
        -not $toolSignature.SignerCertificate -or
        $toolSignature.SignerCertificate.Subject -notmatch '(?i)Microsoft') {
        throw 'Use the Windows-trusted Microsoft SDK SignTool'
    }
    $timestamp = $null
    if (-not [Uri]::TryCreate($env:SCARLETT_WINDOWS_TIMESTAMP_URL, [UriKind]::Absolute, [ref]$timestamp) -or
        $timestamp.Scheme -cne 'https' -or -not $timestamp.Host -or
        $timestamp.UserInfo -or $timestamp.Query -or $timestamp.Fragment) {
        throw 'Explicit HTTPS RFC3161 timestamp endpoint required'
    }
    $certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $publisher) -ErrorAction SilentlyContinue
    $usages = @($certificate.Extensions |
        Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
        ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
    if (-not $certificate -or -not $certificate.HasPrivateKey -or
        $certificate.Issuer -ceq $certificate.Subject -or
        $certificate.NotBefore -gt [DateTime]::Now -or $certificate.NotAfter -le [DateTime]::Now -or
        '1.3.6.1.5.5.7.3.3' -notin $usages) {
        throw 'Existing valid publisher code-signing identity required'
    }
    # Tauri can invoke its callback again for an already signed executable.
    # Preserve its bytes so the finalized component hashes remain valid.
    $current = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $resolved
    if ([string]$current.Status -ceq 'Valid') {
        Assert-SignatureRecord $current $publisher
        return
    }
    if ([string]$current.Status -cne 'NotSigned') { throw 'Refuse to replace a damaged or untrusted signature' }
    $nativeOutput = & $tool sign /q /s My /sha1 $publisher /fd SHA256 /tr $timestamp.AbsoluteUri /td SHA256 $resolved 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Native signing or timestamping failed' }
    $nativeOutput = $null
    Read-TrustedSignature $resolved $publisher | Out-Null
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Sign-WindowsReleaseFile $File }
    catch { throw 'Windows release signing failed; artifact is not approved for publication' }
}
