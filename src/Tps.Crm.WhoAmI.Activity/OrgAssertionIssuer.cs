using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Xrm.Sdk;
using Tps.Crm.Assertion;

namespace Tps.Crm.WhoAmI.Activity
{
    /// <summary>Supplies the signing certificate for the duration of one signing call.</summary>
    public interface ISigningCertificateSource
    {
        /// <summary>
        /// Invokes <paramref name="use"/> with the certificate identified by <paramref name="thumbprint"/>.
        /// Must throw when the certificate is missing, not unique, expired or has no private key.
        /// </summary>
        string UseCertificate(string thumbprint, Func<X509Certificate2, string> use);
    }

    /// <summary>Builds the signed org assertion. Every failure is generic and fail-closed.</summary>
    public sealed class OrgAssertionIssuer
    {
        public const string FailureMessage = "The organization assertion could not be issued.";
        public const int LifetimeSeconds = 120; // contract maximum is 300

        private readonly ISigningCertificateSource _source;
        private readonly Func<DateTimeOffset> _clock;

        public OrgAssertionIssuer(ISigningCertificateSource source, Func<DateTimeOffset> clock = null)
        {
            if (source == null) throw new ArgumentNullException("source");
            _source = source;
            _clock = clock ?? (() => DateTimeOffset.UtcNow);
        }

        /// <exception cref="InvalidPluginExecutionException">Any failure; the message never contains details.</exception>
        public string Issue(string org, string machine, string thumbprint)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(org) || string.IsNullOrWhiteSpace(machine) || string.IsNullOrWhiteSpace(thumbprint))
                    throw new InvalidOperationException();

                AssertionClaims claims = AssertionSigner.NewClaims(org, machine, _clock(), LifetimeSeconds);
                string token = _source.UseCertificate(thumbprint, cert => AssertionSigner.Sign(claims, cert));
                if (string.IsNullOrEmpty(token)) throw new InvalidOperationException();
                return token;
            }
            catch (Exception)
            {
                // Deliberately no inner exception, thumbprint, path or token.
                throw new InvalidPluginExecutionException(FailureMessage);
            }
        }
    }
}
