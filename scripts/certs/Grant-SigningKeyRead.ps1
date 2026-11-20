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

# Early, friendlier error only. The decision below is SID-based and authoritative.
if ($Account -match '^(Everyone|Users|Guests|Administrators|Authenticated Users|(.*\\)?(Users|Guests|Everyone|Authenticated Users|Domain \w+)|BUILTIN\\.*|NT AUTHORITY\\.*)$') {
    throw "Refusing broad/builtin principal '$Account'."
}
try { $sid = ([Security.Principal.NTAccount]$Account).Translate([Security.Principal.SecurityIdentifier]) }
catch { throw "Account '$Account' cannot be resolved. Denied." }

$s = $sid.Value
$denyExact = @('S-1-1-0', 'S-1-5-1', 'S-1-5-2', 'S-1-5-4', 'S-1-5-7', 'S-1-5-11')
if ($denyExact -contains $s -or $s -match '^S-1-5-32-') {
    throw "Refusing well-known/builtin SID $s ('$Account')."
}
if ($s -match '^S-1-5-21-(\d+-){3}(?<rid>\d+)$' -and [int64]$Matches['rid'] -ge 512 -and [int64]$Matches['rid'] -le 520) {
    throw "Refusing privileged/broad domain group SID $s ('$Account')."
}

# Allow only a single user or gMSA: the SID must resolve to SidTypeUser; groups, aliases, computers deny.
if (-not ('TpsSidLookup' -as [type])) {
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class TpsSidLookup {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool LookupAccountSid(string host, byte[] sid, StringBuilder name, ref int cchName,
      StringBuilder dom, ref int cchDom, out int use);
  public static int GetUse(byte[] sid) {
    var n = new StringBuilder(256); var d = new StringBuilder(256); int cn = 256, cd = 256, use;
    return LookupAccountSid(null, sid, n, ref cn, d, ref cd, out use) ? use : -1;
  }
}
'@
}
$bytes = New-Object byte[] $sid.BinaryLength
$sid.GetBinaryForm($bytes, 0)
if ([TpsSidLookup]::GetUse($bytes) -ne 1) {   # 1 = SidTypeUser
    throw "Account '$Account' ($s) is not a user or gMSA. Denied."
}

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
