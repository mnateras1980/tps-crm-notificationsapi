<#
.SYNOPSIS
  DEV ONLY. Adds/updates an HTTPS binding on an IIS site using an existing LocalMachine\My TLS cert.
.DESCRIPTION
  Requires elevation and the WebAdministration module. Refuses a cert that lacks serverAuth EKU or
  is expired. Supports -WhatIf.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Thumbprint,
    [string]$SiteName = 'TpsWhoAmI',
    [int]$Port = 44350
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
if (-not $cert) { throw 'TLS certificate not found in LocalMachine\My. Denied.' }
if ($cert.NotAfter -lt (Get-Date)) { throw 'Certificate expired. Denied.' }
$eku = $cert.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
if (-not $eku -or -not ($eku.EnhancedKeyUsages | Where-Object Value -eq '1.3.6.1.5.5.7.3.1')) {
    throw 'Certificate lacks serverAuth EKU. Denied.'
}
Import-Module WebAdministration -ErrorAction Stop
if (-not (Get-Website -Name $SiteName)) { throw "IIS site '$SiteName' not found. Denied." }

if ($PSCmdlet.ShouldProcess("$SiteName :$Port", "Bind HTTPS with cert $Thumbprint")) {
    if (-not (Get-WebBinding -Name $SiteName -Protocol https -Port $Port)) {
        New-WebBinding -Name $SiteName -Protocol https -Port $Port -IPAddress '*'
    }
    $binding = Get-WebBinding -Name $SiteName -Protocol https -Port $Port
    $binding.AddSslCertificate($Thumbprint, 'My')
    Write-Output "Bound https :$Port on '$SiteName' to $Thumbprint"
}
