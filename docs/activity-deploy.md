# Org assertion workflow activity: build and deployment

Assembly `Tps.Crm.WhoAmI.Activity` (net462) contains `OrgAssertionActivity`, a CodeActivity with one output,
`Org Assertion` (string). It has no inputs. Org comes from `IWorkflowContext.OrganizationName`, machine from
`Environment.MachineName`. The signer (`src\Shared\Assertion`) is source-linked, so there is a single assembly
to register (no ILMerge).

## Build

```
dotnet build src\Tps.Crm.WhoAmI.Activity.sln -c Release
dotnet build src\Tps.Crm.WhoAmI.Activity\Tps.Crm.WhoAmI.Activity.csproj -c Release /p:AssemblyKeyFile=<path-to-key.snk>
```

- CRM requires a strong-named assembly. Supply the key file path with `/p:AssemblyKeyFile=`. Never commit a
  `.snk`, `.pfx` or key to the repo. Keep the key in the team's secret store.
- Without the property the build succeeds unsigned. Use that for development only. CRM will not register it.
- Target is net462 because `Microsoft.CrmSdk.Workflow` 9.0.2.x does not support net461. Confirm the CRM server's
  .NET Framework is 4.6.2 or later before deploying.

## Registration notes

1. Register the assembly with the Plugin Registration Tool: isolation mode **None (On-premises)** is typical for
   on-prem; **Sandbox** will not allow LocalMachine certificate-store access. Storage: Database.
2. The activity appears as workflow step **Org Assertion** (group `Tps.Crm.WhoAmI.Activity`).
3. Create an active `mm360_setup` row: `mm360_name` = `OrgAssertionCertThumbprint`, `mm360_value` = SHA-1
   thumbprint of the signing certificate (exactly one active row; zero or several denies).
4. Install the signing certificate with its private key in `LocalMachine\My` on every CRM async server, and grant
   the CRM async service account read access to the private key. See `docs\certificates.md`.
5. The API pins the matching public certificate. The token is valid for 120 seconds. Use the output in the same
   workflow step chain and do not store it.

## Failure behavior

Any failure (missing or ambiguous setup value, certificate not found, expired, no readable private key, signing
error) throws `InvalidPluginExecutionException` with a fixed generic message. Details are not logged or returned.
