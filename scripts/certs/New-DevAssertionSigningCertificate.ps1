<#
.SYNOPSIS
  DEV ONLY. Creates the assertion-signing cert (RSA 3072, NON-EXPORTABLE key) in LocalMachine\My and
  exports ONLY the public .cer for the API server.
.DESCRIPTION
  Run on the (dev) CRM workflow/async host. Private key can never be exported (no PFX possible).
  Supports -WhatIf. Requires elevation. Prints thumbprint for current/next pinning config.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$Subject = 'CN=TPS WhoAmI Assertion Signing (DEV)',
    [int]$ValidDays = 365,
    [ValidateRange(2048, 4096)][int]$KeyLength = 3072,
    # Public-only output. Default is outside any repo.
    [string]$PublicCerPath = (Join-Path $env:LOCALAPPDATA 'TpsWhoAmI\assertion-signing.cer')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($PublicCerPath -notmatch '\.cer$') { throw 'Only .cer export is allowed.' }

if ($PSCmdlet.ShouldProcess('Cert:\LocalMachine\My', "Create non-exportable signing cert '$Subject'")) {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Elevation required to write LocalMachine\My. Denied.'
    }
    $cert = New-SelfSignedCertificate -Subject $Subject -FriendlyName 'TPS WhoAmI DEV signing' `
        -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength $KeyLength -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable -KeyUsage DigitalSignature -Type Custom `
        -NotAfter (Get-Date).AddDays($ValidDays)
    $dir = Split-Path -Parent $PublicCerPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    Export-Certificate -Cert $cert -FilePath $PublicCerPath -Type CERT | Out-Null
    Write-Output "Signing thumbprint: $($cert.Thumbprint)"
    Write-Output "Public cert: $PublicCerPath (copy to API host; import to LocalMachine\TrustedPeople or configure path)"
}
