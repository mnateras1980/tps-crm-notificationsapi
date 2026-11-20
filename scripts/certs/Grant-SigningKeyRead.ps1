<#
.SYNOPSIS
  Grants READ-only on the signing cert private key to one named account (the CRM async service account).
.DESCRIPTION
  Least privilege: Read only, single account. Broad principals (Everyone, Users, Authenticated Users,
  BUILTIN\*, NT AUTHORITY\*) are refused. Unresolvable thumbprint/account/key denies. Supports -WhatIf.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Thumbprint,
    [Parameter(Mandatory)][string]$Account   # e.g. DOMAIN\svc-crm-async
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Account -match '^(Everyone|Users|Authenticated Users|(.*\\)?(Users|Everyone|Authenticated Users|Domain Users)|BUILTIN\\.*|NT AUTHORITY\\.*)$') {
    throw "Refusing broad/builtin principal '$Account'."
}
try { $sid = ([Security.Principal.NTAccount]$Account).Translate([Security.Principal.SecurityIdentifier]) }
catch { throw "Account '$Account' cannot be resolved. Denied." }

$cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
if (-not $cert -or -not $cert.HasPrivateKey) { throw 'Certificate or private key not found. Denied.' }

$rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$keyName = $rsa.Key.UniqueName
$path = Join-Path $env:ProgramData "Microsoft\Crypto\Keys\$keyName"
if (-not (Test-Path $path)) { $path = Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$keyName" }
if (-not (Test-Path $path)) { throw 'Key container file not found. Denied.' }

if ($PSCmdlet.ShouldProcess($path, "Grant Read to $Account")) {
    $acl = Get-Acl $path
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'Read', 'Allow'))
    Set-Acl -Path $path -AclObject $acl
    Write-Output "Granted Read on key of $Thumbprint to $Account"
}
