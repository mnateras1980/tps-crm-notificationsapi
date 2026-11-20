using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Tps.Crm.Assertion;

namespace Tps.Crm.WhoAmI.Api.Services
{
    /// <summary>
    /// Process-wide composition. The verifier MUST be a singleton (its replay cache is per instance).
    /// Any configuration problem yields a deny-all verifier / empty allow-list (fail closed).
    /// </summary>
    public static class ApiServices
    {
        private static readonly Lazy<AssertionVerifier> VerifierInstance = new Lazy<AssertionVerifier>(BuildVerifier);
        private static readonly Lazy<IOrgAllowList> AllowListInstance = new Lazy<IOrgAllowList>(() => OrgAllowList.FromConfig());
        private static readonly ICrmConnectionFactory FactoryInstance = new CrmConnectionFactory();

        public static AssertionVerifier Verifier { get { return VerifierInstance.Value; } }
        public static IOrgAllowList AllowList { get { return AllowListInstance.Value; } }
        public static ICrmConnectionFactory CrmFactory { get { return FactoryInstance; } }

        private static AssertionVerifier BuildVerifier()
        {
            var certs = new List<X509Certificate2>();
            foreach (string slot in new[] { "Current", "Next" })
            {
                try
                {
                    string path = ConfigurationManager.AppSettings["Assertion:" + slot + "CertPath"];
                    string pin = ConfigurationManager.AppSettings["Assertion:" + slot + "Sha256"];
                    if (string.IsNullOrWhiteSpace(path) && string.IsNullOrWhiteSpace(pin)) continue;
                    if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(pin))
                    {
                        Trace.TraceError("Assertion {0} certificate needs both CertPath and Sha256; ignored.", slot);
                        continue;
                    }
                    string full = Path.IsPathRooted(path) ? path : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, path);
                    var cert = new X509Certificate2(full);
                    string expected = pin.Replace(":", string.Empty).Replace(" ", string.Empty).ToLowerInvariant();
                    if (cert.HasPrivateKey || !string.Equals(CertThumbprint.Sha256(cert), expected, StringComparison.OrdinalIgnoreCase))
                    {
                        Trace.TraceError("Assertion {0} certificate rejected (private key present or pin mismatch).", slot);
                        continue;
                    }
                    certs.Add(cert);
                }
                catch (Exception ex)
                {
                    Trace.TraceError("Assertion {0} certificate load failed: {1}", slot, ex.GetType().Name);
                }
            }
            return new AssertionVerifier(certs);
        }
    }
}
