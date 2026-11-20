# Local run: Tps.Crm.WhoAmI.Api (IIS Express, HTTPS, Windows Authentication)

## Prerequisites
- Visual Studio 2022+ (MSBuild, .NET Framework 4.8 targeting pack), IIS Express, nuget.exe.
- Windows Authentication feature available to IIS Express (domain-joined or local account).

## GET /api/whoami/crm: assertion, allow-list, config
- `GET /api/whoami` is unchanged (caller only). `GET /api/whoami/crm` needs Windows auth AND a signed org assertion
  in the header `X-Tps-Org-Assertion` (never `Authorization`).
- Responses: 200 `{org, machine, userId, fullName}`; 401 missing/invalid/replayed assertion (no reason text);
  403 (org, machine) not on the allow-list; 400 if `CrmOrgUrl` (any case) is in the query names, a header name or
  any request body (never read or echoed); 502 on a CRM failure (no detail). The CRM URL is never returned.
- Web.config `appSettings`: `Assertion:CurrentCertPath` + `Assertion:CurrentSha256` (public .cer and its SHA-256 pin),
  optional `Assertion:NextCertPath` + `Assertion:NextSha256` for rotation. A .cer holding a private key is rejected.
  Blank/invalid = every assertion is rejected.
- Allow-list: `<tpsOrgAllowList><add org="..." machine="..." crmUrl="https://.../XRMServices/2011/Organization.svc" /></tpsOrgAllowList>`.
  org/machine must match `[A-Za-z0-9._-]{1,64}`; https only; case-insensitive; duplicates are dropped. Empty = deny all.
- CRM calls run as the app-pool identity (DefaultNetworkCredentials). There are no username/password settings.
  Keep ASP.NET impersonation off. The app-pool account needs read access in each allow-listed CRM org.

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
