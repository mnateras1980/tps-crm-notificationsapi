using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Tps.Crm.WhoAmI.Activity
{
    /// <summary>Reads the signing certificate from LocalMachine\My (read-only access).</summary>
    public sealed class LocalMachineCertificateSource : ISigningCertificateSource
    {
        public string UseCertificate(string thumbprint, Func<X509Certificate2, string> use)
        {
            string normalized = Normalize(thumbprint);
            if (normalized == null) throw new InvalidOperationException();

            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            X509Certificate2Collection found = null;
            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                // validOnly=false: chain trust is not the signer's concern; the verifier pins the public cert.
                found = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, false);
                if (found.Count != 1) throw new InvalidOperationException();

                X509Certificate2 cert = found[0];
                DateTime now = DateTime.UtcNow;
                if (!cert.HasPrivateKey || now < cert.NotBefore.ToUniversalTime() || now > cert.NotAfter.ToUniversalTime())
                    throw new InvalidOperationException();

                return use(cert);
            }
            finally
            {
                if (found != null)
                {
                    foreach (X509Certificate2 c in found) c.Dispose();
                }
                store.Close();
            }
        }

        /// <summary>Keeps hex digits only (drops spaces and invisible copy/paste characters); requires 40 digits.</summary>
        public static string Normalize(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint)) return null;
            var sb = new StringBuilder();
            foreach (char ch in thumbprint)
            {
                if (Uri.IsHexDigit(ch)) sb.Append(char.ToUpperInvariant(ch));
            }
            return sb.Length == 40 ? sb.ToString() : null;
        }
    }
}
