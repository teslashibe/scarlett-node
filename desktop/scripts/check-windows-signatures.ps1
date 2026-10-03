# Read-only native acceptance; this script never imports keys or signs files
param(
    [string]$Installer = '',
    [string]$InstalledDirectory = '',
    [string]$ExpectedPublisherThumbprint = '',
    [string]$EvidenceFile = ''
)
$ErrorActionPreference = 'Stop'

function Assert-SignatureRecord($Signature, [string]$PublisherThumbprint) {
    if ($PublisherThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Expected publisher certificate thumbprint is required' }
    if (-not $Signature -or [string]$Signature.Status -cne 'Valid' -or
        [string]$Signature.SignatureType -cne 'Authenticode') {
        throw 'An embedded Windows-trusted Authenticode signature is required'
    }
    if (-not $Signature.SignerCertificate -or
        $Signature.SignerCertificate.Thumbprint -ine $PublisherThumbprint) {
        throw 'Windows signature does not match the reviewed publisher certificate'
    }
    if (-not $Signature.SignerCertificate.Issuer -or -not $Signature.SignerCertificate.Subject -or
        $Signature.SignerCertificate.Issuer -ceq $Signature.SignerCertificate.Subject) {
        throw 'Self-signed publisher certificates are not stable release evidence'
    }
    if (-not $Signature.TimeStamperCertificate) { throw 'Windows release signature requires a trusted timestamp' }
}

function Assert-NoReparseParents($Directory) {
    $parent = $Directory
    while ($parent) {
        if ($parent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'Release paths cannot traverse reparse points'
        }
        $parent = $parent.Parent
    }
}

function Assert-RegularLocalFile([string]$Path) {
    if ($Path -notmatch '^[a-zA-Z]:[\\/]' -or $Path.Substring(2).Contains(':')) {
        throw 'Release evidence requires an absolute local file path without alternate streams'
    }
    $entry = Get-Item -LiteralPath $Path -Force
    if ($entry.PSIsContainer -or ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'Release evidence requires a regular file'
    }
    Assert-NoReparseParents $entry.Directory
    return $entry.FullName
}

function Read-TrustedSignature([string]$Path, [string]$PublisherThumbprint) {
    $resolved = Assert-RegularLocalFile $Path
    $before = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $resolved
    Assert-SignatureRecord $signature $PublisherThumbprint
    $after = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    if ($before -cne $after) { throw 'Release file changed during signature validation' }
    return @{ sha256 = $after.ToLowerInvariant(); bytes = (Get-Item -LiteralPath $resolved).Length }
}

function Write-WindowsSignatureEvidence([string]$Setup, [string]$Installed, [string]$PublisherThumbprint, [string]$Output) {
    if ($env:OS -ne 'Windows_NT') { throw 'Signature acceptance requires native Windows' }
    if ($PublisherThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Expected publisher certificate thumbprint is required' }
    if ($Installed -notmatch '^[a-zA-Z]:[\\/]' -or $Installed.Substring(2).Contains(':') -or
        $Setup -notmatch '(?i)\.exe$' -or $Output -notmatch '(?i)\.json$' -or
        $Output -notmatch '^[a-zA-Z]:[\\/]' -or $Output.Substring(2).Contains(':')) {
        throw 'Supply the installer, installed payload and a new absolute evidence file'
    }
    $outputPath = [System.IO.Path]::GetFullPath($Output)
    if (Test-Path -LiteralPath $outputPath) { throw 'Release evidence already exists' }
    $outputParent = Get-Item -LiteralPath ([System.IO.Path]::GetDirectoryName($outputPath)) -Force
    if (-not $outputParent.PSIsContainer) { throw 'Release evidence requires an existing output directory' }
    Assert-NoReparseParents $outputParent
    $root = [System.IO.Path]::GetFullPath($Installed).TrimEnd('\')
    $components = Assert-RegularLocalFile (Join-Path $root 'runtime\COMPONENTS.json')
    $manifestHash = (Get-FileHash -LiteralPath $components -Algorithm SHA256).Hash
    $signed = @{}
    foreach ($name in @('scarlett-node-desktop', 'scarlett-node', 'scarlett-prover', 'open-agent-api')) {
        $signed[$name] = Read-TrustedSignature (Join-Path $root ($name + '.exe')) $PublisherThumbprint
    }
    $setupEvidence = Read-TrustedSignature $Setup $PublisherThumbprint
    if ((Get-FileHash -LiteralPath $components -Algorithm SHA256).Hash -cne $manifestHash) {
        throw 'Component manifest changed during signature validation'
    }
    # Authenticode does not replace the complete installed payload/hash/API check
    # nor establish that this installed directory came from the supplied setup.
    $evidence = @{ schemaVersion = 1; signature = 'authenticode'; timestampRequired = $true
        publisherThumbprint = $PublisherThumbprint.ToUpperInvariant(); installer = $setupEvidence
        installedExecutables = $signed; componentManifestSha256 = $manifestHash.ToLowerInvariant()
        installedFromThisInstaller = 'separate acceptance required'; providerJobs = 0 }
    $encoded = [System.Text.UTF8Encoding]::new($false).GetBytes(($evidence | ConvertTo-Json -Depth 5) + "`n")
    # CreateNew refuses overwrites/races. This is the only filesystem mutation.
    $stream = [System.IO.File]::Open($outputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($encoded, 0, $encoded.Length); $stream.Flush() } finally { $stream.Dispose() }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Write-WindowsSignatureEvidence $Installer $InstalledDirectory $ExpectedPublisherThumbprint $EvidenceFile
        Write-Output 'Windows installer and installed Scarlett executables passed publisher and timestamp checks'
    } catch {
        # Never echo native certificate errors, paths or configuration values
        throw 'Windows release signature acceptance failed; artifact is not approved for publication'
    }
}
