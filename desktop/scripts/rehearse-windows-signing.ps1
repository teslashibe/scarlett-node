# Rehearse the self-signed-stable Windows release with no secrets: every PR runs
# the release import, signer, NSIS packaging, installed acceptance and signature
# checks against its own complete release build.
#
# A throwaway RSA-3072 certificate with the release extensions and one day of
# validity is made with OpenSSL 3 and exported as PKCS#12 with OpenSSL 3's
# defaults (AES-256-CBC, PBKDF2, SHA-256 MAC), as the release key was.
# import-windows-identity.ps1 imports it exactly as the release workflow imports
# its key; then the release workflow's signing commands run sign-windows-bundle.py
# with the pins injected through the rehearsal identities override. Its evidence
# says "rehearsal": true, which the release assembler rejects. The identity, its
# key and the key files are removed on exit; no trust root is ever added.
#
# A control first imports a copy of that PKCS#12 file the way the release
# workflow used to (Import-PfxCertificate) and reports, without failing, which
# key provider Windows chose and whether SignTool could make a SHA-256 signature.
#
# usage: rehearse-windows-signing.ps1 -Desktop <absolute desktop checkout>
#   -WorkDirectory <new absolute directory> -ControlBinary <absolute unsigned exe>
param(
    [string]$Desktop = '',
    [string]$WorkDirectory = '',
    [string]$ControlBinary = ''
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'The Windows signing rehearsal requires a disposable Windows CI runner'
}
foreach ($path in @($Desktop, $WorkDirectory, $ControlBinary)) {
    if ($path -notmatch '^[a-zA-Z]:[\\/]' -or $path.Substring(2).Contains(':')) { throw 'Supply absolute local paths' }
}
if (-not (Test-Path -LiteralPath (Join-Path $Desktop 'src-tauri\target\release\scarlett-node-desktop.exe') -PathType Leaf) -or
    -not (Test-Path -LiteralPath $ControlBinary -PathType Leaf) -or (Test-Path -LiteralPath $WorkDirectory)) {
    throw 'Build the release executable first and supply a new work directory'
}
$scripts = $PSScriptRoot
# The release step dot-sources the signer for Find-WindowsSdkSignTool; so does
# this rehearsal. It also brings the read-only signature checks.
. (Join-Path $scripts 'sign-windows-file.ps1')

function Invoke-RehearsalNative([string]$Tool, [string[]]$Arguments) {
    # Throwaway material only: native output is shown when a step fails.
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& $Tool @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $preference
    }
    if ($code -ne 0) {
        $output | ForEach-Object { Write-Output ('  ' + $_) }
        throw ('Rehearsal command failed with exit code ' + $code + ': ' + [System.IO.Path]::GetFileName($Tool) + ' ' + $Arguments[0])
    }
    return $output
}

function Find-OpenSsl3 {
    $candidates = @(
        (Join-Path $env:ProgramFiles 'OpenSSL\bin\openssl.exe'),
        (Join-Path $env:ProgramFiles 'Git\mingw64\bin\openssl.exe'),
        (Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe')
    ) + @(Get-Command openssl.exe -All -CommandType Application -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    foreach ($candidate in $candidates) {
        if (-not $candidate -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        try { $version = (Invoke-RehearsalNative $candidate @('version')) -join ' ' } catch { continue }
        if ($version -match '^OpenSSL 3\.') { return @{ Path = $candidate; Version = $version } }
    }
    throw 'OpenSSL 3 is required for the rehearsal PKCS#12 export'
}

function New-RandomHex([int]$Bytes) {
    $buffer = New-Object byte[] $Bytes
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($buffer) } finally { $generator.Dispose() }
    return -join ($buffer | ForEach-Object { $_.ToString('x2') })
}

function Invoke-SignToolControl([string]$Tool, [string]$Thumbprint, [string]$Target) {
    # No timestamp: this isolates whether the key's provider can sign SHA-256.
    $preference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $text = @(& $Tool sign /q /s My /sha1 $Thumbprint /fd SHA256 $Target 2>&1 | ForEach-Object { [string]$_ }) -join "`n"
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $preference
    }
    if ($code -eq 0) { return 'succeeded' }
    $hresult = ''
    if ($text -match '\((?:-?[0-9]+/)?0x([0-9A-Fa-f]{8})\)') { $hresult = ' with 0x' + $Matches[1].ToUpperInvariant() }
    return 'failed' + $hresult
}

function Get-KeyProviderDescription($Certificate) {
    $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    try {
        if ($key -is [System.Security.Cryptography.RSACng]) { return "CNG '" + $key.Key.Provider.Provider + "'" }
        if ($key -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            $info = $key.CspKeyContainerInfo
            return "CryptoAPI '" + $info.ProviderName + "' (provider type " + $info.ProviderType + ')'
        }
        return 'an unrecognised provider'
    } finally {
        if ($key -is [System.IDisposable]) { $key.Dispose() }
    }
}

New-Item -ItemType Directory -Path $WorkDirectory | Out-Null
$keys = New-Item -ItemType Directory -Path (Join-Path $WorkDirectory 'key')
$sha1 = ''
try {
    $openssl = Find-OpenSsl3
    Write-Output ('Rehearsal key material: ' + $openssl.Version)
    # Same extensions as the release certificate (desktop/signing, plan section 1).
    $config = Join-Path $keys.FullName 'codesign-ext.cnf'
    [System.IO.File]::WriteAllText($config, (@(
        '[req]', 'prompt = no', 'distinguished_name = dn', 'x509_extensions = ext',
        '[dn]', 'O = Scarlett Rehearsal', ('CN = Scarlett Node Rehearsal Windows ' + (New-RandomHex 4)),
        '[ext]', 'basicConstraints = critical,CA:FALSE', 'keyUsage = critical,digitalSignature',
        'extendedKeyUsage = critical,codeSigning', 'subjectKeyIdentifier = hash', '') -join "`n"),
        [System.Text.UTF8Encoding]::new($false))
    $key = Join-Path $keys.FullName 'key.pem'
    $certificate = Join-Path $keys.FullName 'cert.pem'
    $pfx = Join-Path $keys.FullName 'identity.pfx'
    $controlPfx = Join-Path $keys.FullName 'control.pfx'
    Invoke-RehearsalNative $openssl.Path @('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', $key) | Out-Null
    Invoke-RehearsalNative $openssl.Path @('req', '-new', '-x509', '-config', $config, '-key', $key, '-sha256', '-days', '1',
        '-set_serial', ('0x' + (New-RandomHex 16)), '-out', $certificate) | Out-Null
    $env:SCARLETT_WINDOWS_PFX_PASSWORD = New-RandomHex 24
    # OpenSSL 3 defaults, like the release export: no -legacy, -keypbe, -certpbe or -macalg.
    Invoke-RehearsalNative $openssl.Path @('pkcs12', '-export', '-inkey', $key, '-in', $certificate,
        '-name', 'Scarlett Node Rehearsal Windows', '-passout', 'env:SCARLETT_WINDOWS_PFX_PASSWORD', '-out', $pfx) | Out-Null
    Remove-Item -LiteralPath $key -Force
    $structure = (Invoke-RehearsalNative $openssl.Path @('pkcs12', '-in', $pfx, '-info', '-noout', '-noenc',
        '-passin', 'env:SCARLETT_WINDOWS_PFX_PASSWORD')) -join "`n"
    if ($structure -notmatch 'MAC: sha256' -or $structure -notmatch 'Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC' -or
        $structure -notmatch 'PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC') {
        Write-Output $structure
        throw 'The rehearsal PKCS#12 file does not use the OpenSSL 3 default AES-256/PBKDF2/SHA-256 protection'
    }
    Copy-Item -LiteralPath $pfx -Destination $controlPfx

    # Pins come from the rehearsal identities override, as in sign-macos rehearsals.
    $identities = Join-Path $WorkDirectory 'rehearsal-identities.json'
    Invoke-RehearsalNative 'python' @((Join-Path $scripts 'signing_identities.py'), 'rehearsal',
        '--windows-certificate', $certificate, '--output', $identities) | Out-Null
    $env:SCARLETT_SIGNING_REHEARSAL = '1'
    $env:SCARLETT_SIGNING_IDENTITIES = $identities
    $sha1 = [string](Invoke-RehearsalNative 'python' @((Join-Path $scripts 'signing_identities.py'), 'get', 'windows.sha1'))
    $sha256 = [string](Invoke-RehearsalNative 'python' @((Join-Path $scripts 'signing_identities.py'), 'get', 'windows.sha256'))
    if ($sha1 -cnotmatch '^[0-9a-f]{40}$' -or $sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Rehearsal pins unavailable' }
    $upper = $sha1.ToUpperInvariant()
    $signtool = Find-WindowsSdkSignTool

    # Control (informational): the previous release import.
    $controlTarget = Join-Path $WorkDirectory 'control-target.exe'
    Copy-Item -LiteralPath $ControlBinary -Destination $controlTarget
    try {
        $password = ConvertTo-SecureString -String $env:SCARLETT_WINDOWS_PFX_PASSWORD -AsPlainText -Force
        $legacy = @(Import-PfxCertificate -FilePath $controlPfx -CertStoreLocation Cert:\CurrentUser\My -Password $password)
        if ($legacy.Count -ne 1 -or $legacy[0].Thumbprint -cne $upper -or -not $legacy[0].HasPrivateKey) {
            throw 'The control import does not match the rehearsal certificate'
        }
        $provider = Get-KeyProviderDescription $legacy[0]
        $outcome = Invoke-SignToolControl $signtool $upper $controlTarget
        Write-Output ('Control (informational): Import-PfxCertificate put the OpenSSL 3 PKCS#12 key in ' + $provider +
            '; SignTool SHA-256 signing with it ' + $outcome)
    } finally {
        Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $upper) -DeleteKey -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $controlPfx, $controlTarget -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath ('Cert:\CurrentUser\My\' + $upper)) { throw 'The control identity was not removed' }

    # The release import, unchanged: import-windows-identity.ps1 deletes the file.
    $global:LASTEXITCODE = 0
    & (Join-Path $scripts 'import-windows-identity.ps1') -Pfx $pfx -Thumbprint $sha1
    if ($LASTEXITCODE -ne 0) { throw 'The rehearsal identity import failed' }
    if (Test-Path -LiteralPath $pfx) { throw 'The importer left the PKCS#12 file behind' }
    $env:SCARLETT_WINDOWS_PFX_PASSWORD = $null

    # The release workflow's signing step, with only the evidence location changed.
    $env:SCARLETT_SIGNING_SCHEME = 'self-signed-stable'
    $env:SCARLETT_WINDOWS_SIGNTOOL = Find-WindowsSdkSignTool
    $env:SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT = [string](python (Join-Path $scripts 'signing_identities.py') get windows.sha1)
    if ($LASTEXITCODE -ne 0) { throw 'Pinned Windows thumbprint unavailable' }
    $evidence = Join-Path $WorkDirectory 'Scarlett-Node-rehearsal-windows-amd64.evidence.json'
    python (Join-Path $scripts 'sign-windows-bundle.py') $Desktop $evidence
    if ($LASTEXITCODE -ne 0) { throw 'Windows release signing rehearsal failed' }

    # Independent checks, not through the signer's own evidence alone.
    $installers = @(Get-ChildItem -LiteralPath (Join-Path $Desktop 'src-tauri\target\release\bundle\nsis') -Filter '*.exe')
    if ($installers.Count -ne 1) { throw 'Expected exactly one signed rehearsal installer' }
    $installer = $installers[0].FullName
    $installerHash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    $record = [System.IO.File]::ReadAllText($evidence) | ConvertFrom-Json
    if ($record.rehearsal -ne $true -or $record.signature -cne 'self-signed-stable' -or $record.trustResult -cne '0x800B0109' -or
        $record.certificateSha1 -cne $sha1 -or $record.certificateSha256 -cne $sha256 -or $record.publisherThumbprint -cne $upper -or
        $record.installerSha256 -cne $installerHash -or $record.installedFromThisInstaller -ne $true -or $record.providerJobs -ne 0) {
        throw 'Rehearsal evidence does not record the pinned outcome'
    }
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $installer
    if ([string]$signature.Status -cne 'UnknownError' -or $signature.SignerCertificate.Thumbprint -cne $upper -or
        -not $signature.TimeStamperCertificate) {
        throw 'The rehearsal installer must carry the pinned untrusted-root signature and a timestamp'
    }
    if ((Get-WinVerifyTrustResult $installer) -ne (Get-UntrustedRootCode)) {
        throw 'WinVerifyTrust must report only CERT_E_UNTRUSTEDROOT for the rehearsal installer'
    }
    $components = [System.IO.File]::ReadAllText((Join-Path $Desktop 'src-tauri\runtime\COMPONENTS.json')) | ConvertFrom-Json
    if ($components.releaseSigning.rehearsal -ne $true -or $components.releaseSigning.publisherThumbprint -cne $upper) {
        throw 'The signed component manifest must record the rehearsal'
    }
    Write-Output (@{ rehearsal = $true; signature = $record.signature; trustResult = $record.trustResult
        installerSha256 = $installerHash; installedFromThisInstaller = $record.installedFromThisInstaller } | ConvertTo-Json -Compress)
    Write-Output 'Self-signed Windows rehearsal imported, signed, packaged, installed and verified the complete release build'
} finally {
    $env:SCARLETT_WINDOWS_PFX_PASSWORD = $null
    if ($sha1) {
        $upper = $sha1.ToUpperInvariant()
        Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $upper) -DeleteKey -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ('Cert:\CurrentUser\CA\' + $upper) -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $keys.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
foreach ($store in @('Cert:\CurrentUser\My\', 'Cert:\CurrentUser\CA\', 'Cert:\CurrentUser\Root\', 'Cert:\LocalMachine\Root\')) {
    if (Test-Path -LiteralPath ($store + $sha1.ToUpperInvariant())) { throw 'The rehearsal identity was not removed' }
}
