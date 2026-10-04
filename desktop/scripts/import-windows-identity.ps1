# Import one PKCS#12 code-signing identity into CurrentUser\My for
# sign-windows-bundle.py. The release workflow (the real key, decoded from its
# environment secret) and the PR rehearsal (an ephemeral OpenSSL 3 key) both use
# this, so a rehearsal exercises the release import.
#
# Import-PfxCertificate imports it without export rights, as the release always did.
# The result is then checked: exactly the pinned certificate, with a current-
# user, non-exportable RSA-3072+ key in the CNG Microsoft Software Key Storage
# Provider (where Windows Server 2025 puts an OpenSSL 3 AES-256/PBKDF2 PKCS#12
# key, and where SignTool SHA-256 signing is proven by the rehearsal), and not a
# trusted root. A key elsewhere is refused here with a precise reason instead
# of failing later inside SignTool.
#
# The PKCS#12 file is deleted whether or not the import succeeds, and a failed
# import leaves no certificate or key behind. Requires
# SCARLETT_WINDOWS_PFX_PASSWORD; prints no secret, key detail or path.
param(
    [string]$Pfx = '',
    [string]$Thumbprint = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'check-windows-signatures.ps1')

function Test-NonExportableSoftwareKey($Certificate) {
    # True only for a current-user, non-exportable RSA-3072+ key in the CNG
    # Microsoft Software Key Storage Provider. Opening the key exports nothing.
    $key = $null
    try { $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate) }
    catch { return $false }
    try {
        if ($key -isnot [System.Security.Cryptography.RSACng]) { return $false }
        $exportFlags = [System.Security.Cryptography.CngExportPolicies]::AllowExport -bor
            [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
        return ($key.Key.Provider.Provider -ceq 'Microsoft Software Key Storage Provider' -and -not $key.Key.IsMachineKey -and
            ($key.Key.ExportPolicy -band $exportFlags) -eq 0 -and $key.KeySize -ge 3072)
    } finally {
        if ($key -is [System.IDisposable]) { $key.Dispose() }
    }
}

function Import-WindowsSigningIdentity([string]$Path, [string]$Pin) {
    if ($env:OS -ne 'Windows_NT') { throw 'Importing a signing identity requires native Windows' }
    $imported = @()
    try {
        if ($Pin -cnotmatch '^[0-9a-f]{40}$') { throw 'Supply the pinned lowercase certificate SHA-1' }
        if (-not $env:SCARLETT_WINDOWS_PFX_PASSWORD) { throw 'SCARLETT_WINDOWS_PFX_PASSWORD is required' }
        $file = Assert-RegularLocalFile $Path
        # Certificate store paths use the uppercase thumbprint Windows reports.
        $upper = $Pin.ToUpperInvariant()
        if (Test-Path -LiteralPath ('Cert:\CurrentUser\My\' + $upper)) { throw 'A Scarlett signing identity is already installed' }
        $before = @(Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My' | ForEach-Object { $_.Thumbprint })
        $password = ConvertTo-SecureString -String $env:SCARLETT_WINDOWS_PFX_PASSWORD -AsPlainText -Force
        # Imported as non-exportable: the private key cannot leave this certificate store.
        try { $imported = @(Import-PfxCertificate -FilePath $file -CertStoreLocation Cert:\CurrentUser\My -Password $password) }
        catch { throw 'The PKCS#12 identity could not be imported' }
    } finally {
        if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) { Remove-Item -LiteralPath $Path -Force }
    }
    try {
        if ($imported.Count -ne 1 -or $imported[0].Thumbprint -ine $upper -or -not $imported[0].HasPrivateKey) {
            throw 'The imported identity does not match the pinned thumbprint'
        }
        $installed = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $upper)
        if (-not $installed.HasPrivateKey -or -not (Test-NonExportableSoftwareKey $installed)) {
            throw 'The signing key must be a non-exportable current-user CNG software key'
        }
        foreach ($root in @('Cert:\CurrentUser\Root\', 'Cert:\LocalMachine\Root\')) {
            if (Test-Path -LiteralPath ($root + $upper)) { throw 'The release certificate must never be a trusted root' }
        }
    } catch {
        # Never leave a partially imported identity behind.
        foreach ($certificate in $imported) {
            if ($before -notcontains $certificate.Thumbprint) {
                Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $certificate.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue
            }
        }
        throw
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Import-WindowsSigningIdentity $Pfx $Thumbprint
        Write-Output 'Imported the pinned Windows code-signing identity into CurrentUser\My as a non-exportable CNG key'
    } catch {
        Write-LiteralFailureReason $_ 'The Windows signing identity was not imported'
        exit 1
    }
    # In-process callers (the release step, the rehearsal) read $LASTEXITCODE.
    exit 0
}
