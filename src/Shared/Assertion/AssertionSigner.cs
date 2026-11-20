using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Tps.Crm.Assertion
{
    /// <summary>Produces the compact JWS (RS256) carried in X-Tps-Org-Assertion.</summary>
    public static class AssertionSigner
    {
        /// <summary>Builds claims with a fresh jti; iat = nbf = now.</summary>
        public static AssertionClaims NewClaims(string org, string mach, DateTimeOffset now, int lifetimeSeconds)
        {
            long iat = now.ToUnixTimeSeconds();
            return new AssertionClaims
            {
                Issuer = AssertionContract.Issuer,
                Audience = AssertionContract.Audience,
                Org = org,
                Mach = mach,
                IssuedAt = iat,
                NotBefore = iat,
                Expires = iat + lifetimeSeconds,
                Jti = Guid.NewGuid().ToString("D")
            };
        }

        /// <exception cref="ArgumentException">Claims violate the contract (including lifetime over 300s).</exception>
        public static string Sign(AssertionClaims claims, X509Certificate2 signingCert)
        {
            if (claims == null) throw new ArgumentNullException("claims");
            if (signingCert == null) throw new ArgumentNullException("signingCert");
            Validate(claims);

            using (RSA rsa = signingCert.GetRSAPrivateKey())
            {
                if (rsa == null) throw new ArgumentException("Signing certificate has no usable RSA private key.");
                if (rsa.KeySize < AssertionContract.MinRsaKeySize) throw new ArgumentException("RSA key is too small.");

                var header = new List<KeyValuePair<string, object>>
                {
                    new KeyValuePair<string, object>("alg", AssertionContract.Algorithm),
                    new KeyValuePair<string, object>("typ", AssertionContract.TokenType),
                    new KeyValuePair<string, object>("kid", CertThumbprint.Sha256(signingCert))
                };
                var payload = new List<KeyValuePair<string, object>>
                {
                    new KeyValuePair<string, object>("iss", claims.Issuer),
                    new KeyValuePair<string, object>("aud", claims.Audience),
                    new KeyValuePair<string, object>("org", claims.Org),
                    new KeyValuePair<string, object>("mach", claims.Mach),
                    new KeyValuePair<string, object>("iat", claims.IssuedAt),
                    new KeyValuePair<string, object>("nbf", claims.NotBefore),
                    new KeyValuePair<string, object>("exp", claims.Expires),
                    new KeyValuePair<string, object>("jti", claims.Jti)
                };
                string signingInput = Base64Url.Encode(Encoding.UTF8.GetBytes(FlatJson.Write(header))) + "." +
                                      Base64Url.Encode(Encoding.UTF8.GetBytes(FlatJson.Write(payload)));
                byte[] sig = rsa.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return signingInput + "." + Base64Url.Encode(sig);
            }
        }

        internal static void Validate(AssertionClaims c)
        {
            if (c.Issuer != AssertionContract.Issuer) throw new ArgumentException("Invalid issuer.");
            if (c.Audience != AssertionContract.Audience) throw new ArgumentException("Invalid audience.");
            if (!IsSimpleValue(c.Org) || !IsSimpleValue(c.Mach)) throw new ArgumentException("Invalid org or mach.");
            Guid g;
            if (string.IsNullOrEmpty(c.Jti) || !Guid.TryParse(c.Jti, out g)) throw new ArgumentException("Invalid jti.");
            if (c.Expires <= c.IssuedAt) throw new ArgumentException("exp must be after iat.");
            if (c.Expires - c.IssuedAt > AssertionContract.MaxLifetimeSeconds) throw new ArgumentException("Assertion lifetime exceeds 300 seconds.");
            if (c.NotBefore < c.IssuedAt || c.NotBefore >= c.Expires) throw new ArgumentException("Invalid nbf.");
        }

        /// <summary>Non-empty, bounded, and not URL/path-like.</summary>
        internal static bool IsSimpleValue(string v)
        {
            if (string.IsNullOrWhiteSpace(v) || v.Length > 256) return false;
            return v.IndexOf("://", StringComparison.Ordinal) < 0 && v.IndexOf('/') < 0 && v.IndexOf('\\') < 0;
        }
    }
}
