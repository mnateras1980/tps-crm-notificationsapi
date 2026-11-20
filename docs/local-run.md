# Local run: Tps.Crm.WhoAmI.Api (IIS Express, HTTPS, Windows Authentication)

## Prerequisites
- Visual Studio 2022+ (MSBuild, .NET Framework 4.8 targeting pack), IIS Express, nuget.exe.
- Windows Authentication feature available to IIS Express (domain-joined or local account).

## Build and test
```
nuget restore src\Tps.Crm.WhoAmI.Api.sln -PackagesDirectory packages
msbuild src\Tps.Crm.WhoAmI.Api.sln /p:Configuration=Release
vstest.console.exe tests\Tps.Crm.WhoAmI.Api.Tests\bin\Release\Tps.Crm.WhoAmI.Api.Tests.dll
```

## Generate the repo-local IIS Express config
IIS Express locks the authentication sections, so use a repo-local config:
```
powershell -File scripts\Set-LocalIis.ps1 -Port 44390
```
This writes `scripts\.local\applicationhost.config` (do not commit): site `Tps.Crm.WhoAmI.Api`,
HTTPS binding `*:44390:localhost`, Windows Authentication on, Anonymous off.
Web.config also sets `authentication mode="Windows"` and `deny users="?"`.

## TLS certificate (produced by T5; no certs are created or committed here)
1. Obtain the dev TLS cert from T5 (`docs\certificates.md`) and import it into `Cert:\CurrentUser\My`
   (trust it in `Cert:\CurrentUser\Root` for local dev only). Note its thumbprint.
2. Bind it to the port (elevated prompt):
   `netsh http add sslcert ipport=0.0.0.0:44390 certhash=<THUMBPRINT> appid={214124cd-d05b-4309-9af9-9caa44b2b74a}`
   (that appid is the IIS Express GUID). Remove with `netsh http delete sslcert ipport=0.0.0.0:44390`.
   Ports 44300-44399 are also pre-bound by Visual Studio's IIS Express dev cert if you prefer that.

## Run and verify
```
"%ProgramFiles%\IIS Express\iisexpress.exe" /config:scripts\.local\applicationhost.config /site:Tps.Crm.WhoAmI.Api
curl.exe --negotiate -u : https://localhost:44390/api/whoami   # 200 {"name":"DOMAIN\\user","isAuthenticated":true}
curl.exe https://localhost:44390/api/whoami                   # 401 (add -k only if the cert is untrusted)
```
Stop the server with Ctrl+C. Negotiate uses the `Authorization` header; the later assertion uses
`X-Tps-Org-Assertion`. No credentials are stored in config.
