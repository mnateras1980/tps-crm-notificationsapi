<#
.SYNOPSIS
  DEV ONLY. Creates a self-signed TLS (serverAuth) cert in LocalMachine\My and trusts its public part.
.DESCRIPTION
  Subject CN=localhost, SAN = localhost + machine name. Nothing is written to disk except an optional
  public .cer. No PFX/key/password is ever produced. Requires elevation (LocalMachine store).
  Supports -WhatIf. Idempotent: reuses an unexpired cert with the same FriendlyName.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$FriendlyName = 'TPS WhoAmI DEV TLS',
    [int]$ValidDays = 365,
    # Optional public-only export. Default: none.
    [string]$PublicCerPath,
    # Required to run on a Server OS (shared/test/prod hosts must never get a dev Root trust).
    [switch]$Force
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$installType = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).InstallationType
if ($installType -ne 'Client' -and -not $Force) {
    throw 'Not a client OS (or OS unknown): dev Root trust is workstation-only. Use -Force to override. Denied.'
}
if ($PublicCerPath -and $PublicCerPath -notmatch '\.cer$') { throw 'Only .cer export is allowed.' }

$dns = @('localhost', $env:COMPUTERNAME)
$existing = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -eq $FriendlyName -and $_.NotAfter -gt (Get-Date).AddDays(7) } |
    Select-Object -First 1
$cert = $null
if ($existing) {
    Write-Output "Reusing existing cert $($existing.Thumbprint)"
    $cert = $existing
}
elseif ($PSCmdlet.ShouldProcess("Cert:\LocalMachine\My", "Create self-signed TLS cert for $($dns -join ', ')")) {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Elevation required to write LocalMachine\My. Denied.'
    }
    $cert = New-SelfSignedCertificate -Subject 'CN=localhost' -DnsName $dns -FriendlyName $FriendlyName `
        -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature, KeyEncipherment -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1') `
        -NotAfter (Get-Date).AddDays($ValidDays)
    Write-Output "Created TLS cert $($cert.Thumbprint)"
    # Trust: add the PUBLIC part only to Trusted Root (in memory, no file).
    $pub = [Security.Cryptography.X509Certificates.X509Certificate2]::new($cert.RawData)
    $root = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
    $root.Open('ReadWrite'); $root.Add($pub); $root.Close()
    Write-Output 'Public cert added to LocalMachine\Root (dev trust).'
}

if ($cert -and $PublicCerPath -and $PSCmdlet.ShouldProcess($PublicCerPath, 'Export public .cer')) {
    Export-Certificate -Cert $cert -FilePath $PublicCerPath -Type CERT | Out-Null
}
