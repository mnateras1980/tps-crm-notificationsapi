# Certificates: development and provisioning plan

> **Nothing is issued here.** This document and `scripts\certs\` are a plan plus dev-only helpers.
> No production certificate has been requested or issued. No PFX, key or password is stored in the repo
> (`*.pfx`, `*.key`, `*.pem` are git-ignored).

## 1. Roles and subjects

| | TLS certificate | Assertion-signing certificate |
|---|---|---|
| Purpose | HTTPS on the API's IIS binding | Sign the WhoAmI assertion (T1/T4) |
| EKU / usage | serverAuth; DigitalSignature, KeyEncipherment | DigitalSignature only |
| Subject / SAN | CN=localhost; DNS `localhost` + machine name (prod: service FQDN) | CN=TPS WhoAmI Assertion Signing (env suffix) |
| Key | RSA 2048+ | RSA 2048+ (dev script: 3072), **non-exportable** |
| Private key lives on | API server (LocalMachine\My) | **CRM workflow/async server only** (LocalMachine\My) |
| API server holds | private key (needed for TLS) | **public .cer only** |

The two roles never share a certificate or key.

## 2. Key storage and ACL (least privilege)
- Signing key: created non-exportable on the CRM async host; read ACL granted only to the async service
  account via `Grant-SigningKeyRead.ps1` (Read only; Everyone/Users/builtin refused). No key copy or backup.
- API host: public `.cer` in `LocalMachine\TrustedPeople` or a configured path. Verification pins thumbprints.
- TLS key: ACL read for the IIS app-pool identity only.
- Unresolvable thumbprint, account or key means the scripts and the API **deny** (fail closed).

## 3. Rotation
1. Issue the new signing cert on the CRM host; grant ACL; export public `.cer`.
2. Add its thumbprint as **next** on the API (config holds `current` + `next`); deploy.
3. Switch the CRM activity to sign with the new cert (it becomes `current`).
4. After max assertion lifetime plus clock skew, remove the old thumbprint and cert.

TLS: replace and rebind with `Bind-IisTls.ps1` before expiry (alert at 30 days).

## 4. Revocation
- Signing: remove the thumbprint from API config/trust store (immediate, no CRL dependency); delete the key on the CRM host; rotate. Short-lived assertions bound exposure.
- TLS: revoke via the issuing CA, rebind a new cert.
- Suspected key compromise: emergency rotation; notify the Security Lead.

## 5. Production issuance: request template only (not submitted)
```
Requester: <name/team>        Environment: <prod|test>
Type: <TLS | Assertion signing>
Subject: <CN=...>             SAN (TLS): <fqdn list>
Key: RSA >= 2048, non-exportable, generated on target host
EKU: <serverAuth | none (digitalSignature only)>
Validity: <= 1 year           Template: <internal CA template>
Private key host/ACL: <host> / <service account, Read>
Approver: <Security Lead>     Delivery: public cert only, via CSR
```

## 6. How the code consumes them
- **T2 (IIS / IIS Express):** run `New-DevTlsCertificate.ps1`, then `Bind-IisTls.ps1 -Thumbprint <tp>`. IIS Express uses its own dev cert unless bound separately.
- **T1/T4:** the activity (T4) signs with the cert found by thumbprint in LocalMachine\My on the CRM host; the API validator (T1) loads the public `.cer` and accepts only the `current`/`next` thumbprints.

## 7. Dev scripts (`scripts\certs\`)
All support `-WhatIf`, need elevation for real runs, and export only public `.cer` (default outside the repo):
`New-DevTlsCertificate.ps1`, `New-DevAssertionSigningCertificate.ps1`, `Grant-SigningKeyRead.ps1`, `Bind-IisTls.ps1`.
**Root trust blast radius.** `New-DevTlsCertificate.ps1` adds the TLS cert to `Cert:\LocalMachine\Root`. That trust is machine-wide: every user and service on the machine trusts anything signed by that cert. Use it on a developer workstation only, never on a shared, test or production host (the script refuses a Server OS unless `-Force`). Grant-SigningKeyRead.ps1 accepts only a single user or gMSA, decided on the resolved SID (groups, builtin and well-known SIDs are refused).

**Dev cleanup** (elevated; `<tp>` = thumbprint, `<port>` = binding port):
```
Remove-Item Cert:\LocalMachine\Root\<tp>
Remove-Item Cert:\LocalMachine\My\<tp>                  # TLS and signing certs
Remove-WebBinding -Name TpsWhoAmI -Protocol https -Port <port>
netsh http delete sslcert ipport=0.0.0.0:<port>         # if a http.sys binding remains
Remove-Item Cert:\LocalMachine\TrustedPeople\<tp>       # imported public signing cert
Remove-Item "$env:LOCALAPPDATA\TpsWhoAmI" -Recurse      # exported .cer files
```
