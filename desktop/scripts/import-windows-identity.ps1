# Import one PKCS#12 code-signing identity into CurrentUser\My for
# sign-windows-bundle.py. The release workflow (the real key, decoded from its
# environment secret) and the PR rehearsal (an ephemeral OpenSSL key) both use
# this, so a rehearsal exercises the release import.
#
# The private key goes to the current user's CNG Microsoft Software Key Storage
# Provider without export rights. Import-PfxCertificate is not used: a PKCS#12
# file from OpenSSL names no provider, so it would put the key in the legacy
# CryptoAPI "Microsoft Enhanced Cryptographic Provider v1.0" (PROV_RSA_FULL),
# which cannot make SHA-256 signatures; SignTool /fd SHA256 then fails with
# NTE_BAD_ALGID (0x80090008). New-SelfSignedCertificate keys are CNG too.
#
# The PKCS#12 file is deleted whether or not the import succeeds, and a failed
# import leaves no certificate or key behind. No trust root is added. Requires
# SCARLETT_WINDOWS_PFX_PASSWORD; prints no secret, key detail or path.
param(
    [string]$Pfx = '',
    [string]$Thumbprint = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'check-windows-signatures.ps1')

function Initialize-SoftwareKspImport {
    if (-not ('Scarlett.SoftwareKspImport' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
namespace Scarlett {
    public static class SoftwareKspImport {
        [StructLayout(LayoutKind.Sequential)]
        private struct DataBlob {
            public int cbData;
            public IntPtr pbData;
        }
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr PFXImportCertStore(ref DataBlob pfx, string password, uint flags);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern IntPtr CertEnumCertificatesInStore(IntPtr store, IntPtr previous);
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertCloseStore(IntPtr store, uint flags);
        private const uint CRYPT_USER_KEYSET = 0x00001000;
        private const uint PKCS12_ALWAYS_CNG_KSP = 0x00000200;
        // CRYPT_EXPORTABLE is never passed: the persisted key cannot be exported.
        public static X509Certificate2[] Import(byte[] pfx, string password) {
            GCHandle pinned = GCHandle.Alloc(pfx, GCHandleType.Pinned);
            IntPtr store = IntPtr.Zero;
            try {
                DataBlob blob = new DataBlob();
                blob.cbData = pfx.Length;
                blob.pbData = pinned.AddrOfPinnedObject();
                store = PFXImportCertStore(ref blob, password, CRYPT_USER_KEYSET | PKCS12_ALWAYS_CNG_KSP);
                if (store == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                List<X509Certificate2> certificates = new List<X509Certificate2>();
                IntPtr context = IntPtr.Zero;
                while ((context = CertEnumCertificatesInStore(store, context)) != IntPtr.Zero) {
                    // Duplicates the context with its key provider property.
                    certificates.Add(new X509Certificate2(context));
                }
                return certificates.ToArray();
            } finally {
                if (store != IntPtr.Zero) CertCloseStore(store, 0);
                pinned.Free();
            }
        }
    }
}
'@
    }
}

function Get-SoftwareKspKeyState($Certificate) {
    # 'cng' only for a current-user, non-exportable RSA-3072+ key in the CNG
    # Microsoft Software Key Storage Provider; otherwise a fixed description.
    $key = $null
    try { $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate) }
    catch { return 'unavailable' }
    try {
        if ($key -isnot [System.Security.Cryptography.RSACng]) { return 'legacy CryptoAPI' }
        $exportFlags = [System.Security.Cryptography.CngExportPolicies]::AllowExport -bor
            [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
        if ($key.Key.Provider.Provider -cne 'Microsoft Software Key Storage Provider' -or $key.Key.IsMachineKey -or
            ($key.Key.ExportPolicy -band $exportFlags) -ne 0 -or $key.KeySize -lt 3072) { return 'unexpected CNG' }
        return 'cng'
    } finally {
        if ($key -is [System.IDisposable]) { $key.Dispose() }
    }
}

function Remove-ImportedKey($Certificate) {
    # Deletes a key persisted by a failed import before it reached the store.
    try {
        $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if ($key -is [System.Security.Cryptography.RSACng]) { $key.Key.Delete() }
        elseif ($key -is [System.IDisposable]) { $key.Dispose() }
    } catch { }
}

function Import-WindowsSigningIdentity([string]$Path, [string]$Pin) {
    if ($env:OS -ne 'Windows_NT') { throw 'Importing a signing identity requires native Windows' }
    $bytes = $null
    try {
        if ($Pin -cnotmatch '^[0-9a-f]{40}$') { throw 'Supply the pinned lowercase certificate SHA-1' }
        if (-not $env:SCARLETT_WINDOWS_PFX_PASSWORD) { throw 'SCARLETT_WINDOWS_PFX_PASSWORD is required' }
        $file = Assert-RegularLocalFile $Path
        $upper = $Pin.ToUpperInvariant()
        if (Test-Path -LiteralPath ('Cert:\CurrentUser\My\' + $upper)) { throw 'A Scarlett signing identity is already installed' }
        $bytes = [System.IO.File]::ReadAllBytes($file)
    } finally {
        if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) { Remove-Item -LiteralPath $Path -Force }
    }
    $certificates = @()
    try {
        try { Initialize-SoftwareKspImport } catch { throw 'The CNG import helper could not be compiled' }
        try { $certificates = @([Scarlett.SoftwareKspImport]::Import($bytes, $env:SCARLETT_WINDOWS_PFX_PASSWORD)) }
        catch { throw 'The PKCS#12 identity could not be imported into the CNG key storage provider' }
    } finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    $stored = $false
    try {
        if ($certificates.Count -ne 1 -or $certificates[0].Thumbprint -ine $upper -or -not $certificates[0].HasPrivateKey) {
            throw 'The imported identity does not match the pinned thumbprint'
        }
        if ((Get-SoftwareKspKeyState $certificates[0]) -cne 'cng') {
            throw 'The signing key must be a non-exportable current-user CNG software key'
        }
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try { $store.Add($certificates[0]) } finally { $store.Close() }
        $stored = $true
        $installed = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $upper)
        if (-not $installed.HasPrivateKey -or (Get-SoftwareKspKeyState $installed) -cne 'cng') {
            throw 'The installed identity lost its non-exportable CNG key'
        }
        foreach ($root in @('Cert:\CurrentUser\Root\', 'Cert:\LocalMachine\Root\')) {
            if (Test-Path -LiteralPath ($root + $upper)) { throw 'The release certificate must never be a trusted root' }
        }
    } catch {
        if ($stored) {
            Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $upper) -DeleteKey -ErrorAction SilentlyContinue
        } else {
            foreach ($certificate in $certificates) { if ($certificate.HasPrivateKey) { Remove-ImportedKey $certificate } }
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
