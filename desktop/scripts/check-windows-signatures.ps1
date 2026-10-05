# Read-only native acceptance; this script never imports keys, signs files or
# changes certificate trust. Two schemes, chosen explicitly with no default:
#   authenticode        a Windows-trusted publisher certificate (Status Valid)
#   self-signed-stable  Scarlett's own pinned certificate. Windows reports the
#                       digest as good and only the root as untrusted.
param(
    [string]$Installer = '',
    [string]$InstalledDirectory = '',
    [string]$ExpectedPublisherThumbprint = '',
    [string]$Scheme = '',
    [string]$CertificateSha256 = '',
    [string]$EvidenceFile = ''
)
$ErrorActionPreference = 'Stop'
$ScarlettSigningScriptRoot = $PSScriptRoot

function Get-ScarlettLiteralReasons {
    # The only failure reasons ever written: single-quoted literal throw
    # statements in these signing scripts, read from their own source. Native
    # exception text, paths, certificate details and values never qualify.
    $reasons = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($name in @('check-windows-signatures.ps1', 'sign-windows-file.ps1', 'import-windows-identity.ps1')) {
        $path = Join-Path $ScarlettSigningScriptRoot $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
        $throws = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ThrowStatementAst] }, $true)
        foreach ($statement in $throws) {
            if (-not $statement.Pipeline) { continue }
            $expression = $statement.Pipeline.GetPureExpression()
            if ($expression -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $expression.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::SingleQuoted) {
                [void]$reasons.Add($expression.Value)
            }
        }
    }
    return ,$reasons
}

function Write-LiteralFailureReason($ErrorRecord, [string]$Summary) {
    # For callers that capture stderr: the fixed summary, then the specific
    # reason only when a literal throw above raised it. A SignTool HRESULT
    # (eight hex digits, no text) may follow that reason.
    [Console]::Error.WriteLine($Summary)
    $reason = $ErrorRecord.TargetObject
    $exception = $ErrorRecord.Exception
    if ($exception -is [System.Management.Automation.RuntimeException] -and $exception.WasThrownFromThrowStatement -and
        $reason -is [string] -and (Get-ScarlettLiteralReasons).Contains($reason)) {
        $code = [string]$script:ScarlettNativeFailureCode
        if ($code -cmatch '^0x[0-9A-F]{8}$') { $reason = $reason + ' (' + $code + ')' }
        [Console]::Error.WriteLine($reason)
    }
}

function Assert-SigningScheme([string]$Scheme) {
    if ($Scheme -cne 'self-signed-stable' -and $Scheme -cne 'authenticode') {
        throw 'An explicit Windows signing scheme is required'
    }
}

function Get-UntrustedRootCode {
    # CERT_E_UNTRUSTEDROOT 0x800B0109 as an unsigned 32-bit value
    return [uint32]2148204809
}

function Get-CertificateSha256($Certificate) {
    $bytes = [byte[]]$Certificate.RawData
    if (-not $bytes -or $bytes.Length -eq 0) { throw 'Certificate bytes are required' }
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($bytes) } finally { $algorithm.Dispose() }
    return -join ($hash | ForEach-Object { $_.ToString('x2') })
}

function Get-WinVerifyTrustResult([string]$Path) {
    # WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2, no UI, no
    # revocation and cache-only URL retrieval. Its exact HRESULT separates an
    # untrusted root (digest verified) from a bad digest or a missing signature.
    if (-not ('Scarlett.WinTrust' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Scarlett {
    public static class WinTrust {
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInfo {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct TrustData {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }
        [DllImport("wintrust.dll", ExactSpelling = true)]
        private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;
        private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
        private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
        public static uint Verify(string path) {
            Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            IntPtr name = Marshal.StringToHGlobalUni(path);
            IntPtr file = IntPtr.Zero;
            try {
                FileInfo info = new FileInfo();
                info.cbStruct = (uint)Marshal.SizeOf(typeof(FileInfo));
                info.pcwszFilePath = name;
                file = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FileInfo)));
                Marshal.StructureToPtr(info, file, false);
                TrustData data = new TrustData();
                data.cbStruct = (uint)Marshal.SizeOf(typeof(TrustData));
                data.dwUIChoice = WTD_UI_NONE;
                data.fdwRevocationChecks = WTD_REVOKE_NONE;
                data.dwUnionChoice = WTD_CHOICE_FILE;
                data.pFile = file;
                data.dwStateAction = WTD_STATEACTION_VERIFY;
                data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
                IntPtr window = new IntPtr(-1);
                int result = WinVerifyTrust(window, ref action, ref data);
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(window, ref action, ref data);
                return unchecked((uint)result);
            } finally {
                if (file != IntPtr.Zero) { Marshal.FreeHGlobal(file); }
                Marshal.FreeHGlobal(name);
            }
        }
    }
}
'@
    }
    return [Scarlett.WinTrust]::Verify($Path)
}

function Assert-SignatureRecord($Signature, [string]$PublisherThumbprint, [string]$Scheme, [string]$CertificateSha256 = '', $TrustResult = $null) {
    Assert-SigningScheme $Scheme
    if ($PublisherThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Expected publisher certificate thumbprint is required' }
    if ($CertificateSha256 -and $CertificateSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Certificate SHA-256 pins are lowercase hex' }
    if ($Scheme -ceq 'self-signed-stable' -and -not $CertificateSha256) { throw 'Self-signed releases require the certificate SHA-256 pin' }
    if (-not $Signature -or [string]$Signature.SignatureType -cne 'Authenticode') {
        throw 'An embedded Authenticode signature is required'
    }
    $signer = $Signature.SignerCertificate
    if (-not $signer -or $signer.Thumbprint -ine $PublisherThumbprint) {
        throw 'Windows signature does not match the reviewed publisher certificate'
    }
    if ($CertificateSha256 -and (Get-CertificateSha256 $signer) -cne $CertificateSha256) {
        throw 'Windows signature does not match the pinned certificate'
    }
    if (-not $signer.Issuer -or -not $signer.Subject) { throw 'Signer certificate names are required' }
    if ($Scheme -ceq 'authenticode') {
        if ([string]$Signature.Status -cne 'Valid') { throw 'An embedded Windows-trusted Authenticode signature is required' }
        if ($signer.Issuer -ceq $signer.Subject) { throw 'Self-signed publisher certificates are not stable release evidence' }
    } else {
        # Valid would mean someone made this certificate a trusted root. Never
        # add trust roots: the exact untrusted-root result is the only pass.
        if ([string]$Signature.Status -cne 'UnknownError') { throw 'Self-signed release signatures must report an untrusted root' }
        if ($null -eq $TrustResult -or $TrustResult -isnot [uint32] -or $TrustResult -ne (Get-UntrustedRootCode)) {
            throw 'WinVerifyTrust must report only CERT_E_UNTRUSTEDROOT'
        }
        if ($signer.Issuer -cne $signer.Subject) { throw 'Self-signed release certificates are self-issued' }
    }
    if (-not $Signature.TimeStamperCertificate) { throw 'Windows release signature requires a trusted timestamp' }
}

function Assert-TimestampChain($Certificate) {
    # Both schemes: the RFC3161 timestamp must chain to a root Windows trusts.
    if ($Certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        throw 'Windows release signature requires a trusted timestamp'
    }
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        [void]$chain.ChainPolicy.ApplicationPolicy.Add((New-Object System.Security.Cryptography.Oid '1.3.6.1.5.5.7.3.8'))
        if (-not $chain.Build($Certificate)) { throw 'Timestamp certificate does not chain to a trusted root' }
    } finally {
        if ($chain -is [System.IDisposable]) { $chain.Dispose() }
    }
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

function Assert-PinnedSignature([string]$Path, [string]$PublisherThumbprint, [string]$Scheme, [string]$CertificateSha256) {
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path
    $trust = $null
    if ($Scheme -ceq 'self-signed-stable') { $trust = Get-WinVerifyTrustResult $Path }
    Assert-SignatureRecord $signature $PublisherThumbprint $Scheme $CertificateSha256 $trust
    Assert-TimestampChain $signature.TimeStamperCertificate
}

function Test-PinnedSignature([string]$Path, [string]$PublisherThumbprint, [string]$Scheme, [string]$CertificateSha256) {
    # $false only for an unsigned file. Any existing signature must be exactly
    # the pinned one; anything else is refused rather than replaced.
    $current = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path
    if ([string]$current.Status -ceq 'NotSigned') { return $false }
    Assert-PinnedSignature $Path $PublisherThumbprint $Scheme $CertificateSha256
    return $true
}

function Read-TrustedSignature([string]$Path, [string]$PublisherThumbprint, [string]$Scheme, [string]$CertificateSha256 = '') {
    $resolved = Assert-RegularLocalFile $Path
    $before = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    Assert-PinnedSignature $resolved $PublisherThumbprint $Scheme $CertificateSha256
    $after = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    if ($before -cne $after) { throw 'Release file changed during signature validation' }
    return @{ sha256 = $after.ToLowerInvariant(); bytes = (Get-Item -LiteralPath $resolved).Length }
}

function Write-WindowsSignatureEvidence([string]$Setup, [string]$Installed, [string]$PublisherThumbprint, [string]$Scheme, [string]$CertificateSha256, [string]$Output) {
    if ($env:OS -ne 'Windows_NT') { throw 'Signature acceptance requires native Windows' }
    Assert-SigningScheme $Scheme
    if ($PublisherThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Expected publisher certificate thumbprint is required' }
    if ($Scheme -ceq 'self-signed-stable' -and $CertificateSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Self-signed releases require the certificate SHA-256 pin' }
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
        $signed[$name] = Read-TrustedSignature (Join-Path $root ($name + '.exe')) $PublisherThumbprint $Scheme $CertificateSha256
    }
    $setupEvidence = Read-TrustedSignature $Setup $PublisherThumbprint $Scheme $CertificateSha256
    if ((Get-FileHash -LiteralPath $components -Algorithm SHA256).Hash -cne $manifestHash) {
        throw 'Component manifest changed during signature validation'
    }
    # Authenticode does not replace the complete installed payload/hash/API check
    # nor establish that this installed directory came from the supplied setup.
    $evidence = @{ schemaVersion = 1; signature = $Scheme; timestampRequired = $true
        publisherThumbprint = $PublisherThumbprint.ToUpperInvariant(); installer = $setupEvidence
        installedExecutables = $signed; componentManifestSha256 = $manifestHash.ToLowerInvariant()
        installedFromThisInstaller = 'separate acceptance required'; providerJobs = 0 }
    if ($CertificateSha256) { $evidence.certificateSha256 = $CertificateSha256 }
    if ($Scheme -ceq 'self-signed-stable') { $evidence.trustResult = '0x{0:X8}' -f (Get-UntrustedRootCode) }
    $encoded = [System.Text.UTF8Encoding]::new($false).GetBytes(($evidence | ConvertTo-Json -Depth 5) + "`n")
    # CreateNew refuses overwrites/races. This is the only filesystem mutation.
    $stream = [System.IO.File]::Open($outputPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $stream.Write($encoded, 0, $encoded.Length); $stream.Flush() } finally { $stream.Dispose() }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Write-WindowsSignatureEvidence -Setup $Installer -Installed $InstalledDirectory -PublisherThumbprint $ExpectedPublisherThumbprint `
            -Scheme $Scheme -CertificateSha256 $CertificateSha256 -Output $EvidenceFile
        Write-Output 'Windows installer and installed Scarlett executables passed pinned publisher and timestamp checks'
    } catch {
        # Never echo native certificate errors, paths or configuration values:
        # only the summary and, when one raised it, a literal reason above.
        Write-LiteralFailureReason $_ 'Windows release signature acceptance failed; artifact is not approved for publication'
        exit 1
    }
}
