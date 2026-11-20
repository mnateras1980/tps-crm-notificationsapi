<#
.SYNOPSIS
  Generates a repo-local IIS Express applicationhost.config for Tps.Crm.WhoAmI.Api
  (Windows Authentication on, Anonymous off, HTTPS binding). Creates no certificates.
.PARAMETER Port
  HTTPS port for the site (default 44390).
.PARAMETER OutputPath
  Where to write the config (default scripts\.local\applicationhost.config; do not commit).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(1024, 65535)][int]$Port = 44390,
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$sitePath = Join-Path $repo 'src\Tps.Crm.WhoAmI.Api'
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot '.local\applicationhost.config' }
$template = Join-Path $env:ProgramFiles 'IIS Express\config\templates\PersonalWebServer\applicationhost.config'
if (-not (Test-Path $template)) { throw "IIS Express template not found: $template" }

[xml]$doc = Get-Content -Raw $template
$cfg = $doc.configuration

# Unlock the auth sections so Web.config/site level can use them, then set them at site level.
foreach ($name in 'anonymousAuthentication', 'windowsAuthentication') {
    $sec = $cfg.'system.webServer'.security.authentication.SelectSingleNode($name)
    if ($null -eq $sec) { throw "Section $name missing in template" }
}
$sectionGroup = $cfg.configSections.sectionGroup | Where-Object name -eq 'system.webServer'
$secGroup = $sectionGroup.sectionGroup | Where-Object name -eq 'security'
$authGroup = $secGroup.sectionGroup | Where-Object name -eq 'authentication'
foreach ($s in $authGroup.section) { $s.SetAttribute('overrideModeDefault', 'Allow') }

$sites = $cfg.'system.applicationHost'.sites
foreach ($old in @($sites.site)) { if ($old.name -eq 'Tps.Crm.WhoAmI.Api') { [void]$sites.RemoveChild($old) } }
$site = $doc.CreateElement('site')
$site.SetAttribute('name', 'Tps.Crm.WhoAmI.Api'); $site.SetAttribute('id', '4390')
$app = $doc.CreateElement('application'); $app.SetAttribute('path', '/'); $app.SetAttribute('applicationPool', 'Clr4IntegratedAppPool')
$vd = $doc.CreateElement('virtualDirectory'); $vd.SetAttribute('path', '/'); $vd.SetAttribute('physicalPath', $sitePath)
[void]$app.AppendChild($vd); [void]$site.AppendChild($app)
$bindings = $doc.CreateElement('bindings'); $b = $doc.CreateElement('binding')
$b.SetAttribute('protocol', 'https'); $b.SetAttribute('bindingInformation', "*:${Port}:localhost")
[void]$bindings.AppendChild($b); [void]$site.AppendChild($bindings)
[void]$sites.AppendChild($site)

# Location-scoped auth: Windows on, Anonymous off.
$loc = $doc.CreateElement('location'); $loc.SetAttribute('path', 'Tps.Crm.WhoAmI.Api')
$sw = $doc.CreateElement('system.webServer'); $sec = $doc.CreateElement('security'); $auth = $doc.CreateElement('authentication')
$anon = $doc.CreateElement('anonymousAuthentication'); $anon.SetAttribute('enabled', 'false')
$win = $doc.CreateElement('windowsAuthentication'); $win.SetAttribute('enabled', 'true')
[void]$auth.AppendChild($anon); [void]$auth.AppendChild($win); [void]$sec.AppendChild($auth); [void]$sw.AppendChild($sec); [void]$loc.AppendChild($sw)
[void]$cfg.AppendChild($loc)

if ($PSCmdlet.ShouldProcess($OutputPath, 'Write applicationhost.config')) {
    New-Item -ItemType Directory -Force (Split-Path $OutputPath) | Out-Null
    $doc.Save($OutputPath)
    Write-Host "Wrote $OutputPath"
    Write-Host "Bind the TLS cert (from T5) to the port: see docs\local-run.md"
}
