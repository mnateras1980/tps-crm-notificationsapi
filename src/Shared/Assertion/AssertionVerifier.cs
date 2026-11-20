using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Tps.Crm.Assertion
{
    /// <summary>
    /// Verifies assertions. Trust is limited to the pinned public certificates supplied by configuration
    /// (current + next); certificates or keys embedded in a token are never used. Fail closed.
    /// </summary>
    public sealed class AssertionVerifier
    {
        private const int MaxReplayEntries = 100000;
        private static readonly string[] UrlClaimNames = { "crmorgurl", "url", "uri", "host" };
        private static readonly string[] KnownClaims = { "iss", "aud", "org", "mach", "iat", "nbf", "exp", "jti" };

        private readonly Dictionary<string, X509Certificate2> _trusted;
        private readonly Func<DateTimeOffset> _clock;
        private readonly ConcurrentDictionary<string, long> _seen = new ConcurrentDictionary<string, long>(StringComparer.Ordinal);
        private readonly object _purgeLock = new object();

        /// <param name="pinnedCertificates">Public certificates pinned by config. Empty means every token is rejected.</param>
        /// <param name="clock">Optional UTC clock (tests).</param>
        public AssertionVerifier(IEnumerable<X509Certificate2> pinnedCertificates, Func<DateTimeOffset> clock = null)
        {
            if (pinnedCertificates == null) throw new ArgumentNullException("pinnedCertificates");
            _trusted = new Dictionary<string, X509Certificate2>(StringComparer.Ordinal);
            foreach (X509Certificate2 c in pinnedCertificates)
            {
                if (c != null) _trusted[CertThumbprint.Sha256(c)] = c;
            }
            _clock = clock ?? (() => DateTimeOffset.UtcNow);
        }

        public AssertionResult Verify(string token)
        {
            try
            {
                return VerifyCore(token);
            }
            catch (Exception)
            {
                return AssertionResult.Fail(AssertionReason.Malformed); // fail closed, no detail
            }
        }

        private AssertionResult VerifyCore(string token)
        {
            if (_trusted.Count == 0) return AssertionResult.Fail(AssertionReason.VerifierUnavailable);
            if (string.IsNullOrEmpty(token) || token.Length > AssertionContract.MaxTokenLength) return AssertionResult.Fail(AssertionReason.Malformed);
            string[] parts = token.Split('.');
            if (parts.Length != 3) return AssertionResult.Fail(AssertionReason.Malformed);

            byte[] headerBytes = Base64Url.Decode(parts[0]);
            byte[] payloadBytes = Base64Url.Decode(parts[1]);
            byte[] sig = Base64Url.Decode(parts[2]);
            if (headerBytes == null || payloadBytes == null || sig == null) return AssertionResult.Fail(AssertionReason.Malformed);

            var header = FlatJson.Parse(StrictUtf8(headerBytes));
            if (header == null) return AssertionResult.Fail(AssertionReason.Malformed);

            object alg;
            if (!header.TryGetValue("alg", out alg) || !(alg is string) || (string)alg != AssertionContract.Algorithm)
                return AssertionResult.Fail(AssertionReason.UnsupportedAlgorithm);
            object typ, kid;
            if (!header.TryGetValue("typ", out typ) || !(typ is string) || (string)typ != AssertionContract.TokenType)
                return AssertionResult.Fail(AssertionReason.InvalidHeader);
            if (!header.TryGetValue("kid", out kid) || !(kid is string)) return AssertionResult.Fail(AssertionReason.InvalidHeader);
            // Only alg/typ/kid are allowed: rejects jku, x5c, x5u, jwk, crit, etc.
            if (header.Keys.Any(k => k != "alg" && k != "typ" && k != "kid")) return AssertionResult.Fail(AssertionReason.InvalidHeader);

            X509Certificate2 cert;
            if (!_trusted.TryGetValue(((string)kid).ToLowerInvariant(), out cert)) return AssertionResult.Fail(AssertionReason.UnknownKey);

            DateTimeOffset now = _clock();
            if (now < cert.NotBefore || now > cert.NotAfter) return AssertionResult.Fail(AssertionReason.UnknownKey);

            using (RSA rsa = cert.GetRSAPublicKey())
            {
                if (rsa == null || rsa.KeySize < AssertionContract.MinRsaKeySize) return AssertionResult.Fail(AssertionReason.UnknownKey);
                byte[] input = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
                if (!rsa.VerifyData(input, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                    return AssertionResult.Fail(AssertionReason.BadSignature);
            }

            // Signature is valid; now claims.
            var payload = FlatJson.Parse(StrictUtf8(payloadBytes));
            if (payload == null) return AssertionResult.Fail(AssertionReason.Malformed);
            foreach (string name in payload.Keys)
            {
                if (UrlClaimNames.Contains(name.ToLowerInvariant())) return AssertionResult.Fail(AssertionReason.UrlClaim);
            }
            if (payload.Keys.Any(k => !KnownClaims.Contains(k))) return AssertionResult.Fail(AssertionReason.UnknownClaim);
            if (payload.Count != KnownClaims.Length) return AssertionResult.Fail(AssertionReason.InvalidClaims);

            var claims = new AssertionClaims();
            string iss = payload["iss"] as string, aud = payload["aud"] as string;
            claims.Org = payload["org"] as string;
            claims.Mach = payload["mach"] as string;
            claims.Jti = payload["jti"] as string;
            if (!(payload["iat"] is long) || !(payload["nbf"] is long) || !(payload["exp"] is long)) return AssertionResult.Fail(AssertionReason.InvalidClaims);
            claims.IssuedAt = (long)payload["iat"];
            claims.NotBefore = (long)payload["nbf"];
            claims.Expires = (long)payload["exp"];
            claims.Issuer = iss;
            claims.Audience = aud;

            if (iss != AssertionContract.Issuer) return AssertionResult.Fail(AssertionReason.InvalidIssuer);
            if (aud != AssertionContract.Audience) return AssertionResult.Fail(AssertionReason.InvalidAudience);
            Guid g;
            if (!AssertionSigner.IsSimpleValue(claims.Org) || !AssertionSigner.IsSimpleValue(claims.Mach) ||
                string.IsNullOrEmpty(claims.Jti) || !Guid.TryParse(claims.Jti, out g))
                return AssertionResult.Fail(AssertionReason.InvalidClaims);
            if (claims.Expires <= claims.IssuedAt || claims.Expires - claims.IssuedAt > AssertionContract.MaxLifetimeSeconds ||
                claims.NotBefore < claims.IssuedAt || claims.NotBefore >= claims.Expires)
                return AssertionResult.Fail(AssertionReason.InvalidClaims);

            long t = now.ToUnixTimeSeconds();
            if (t - AssertionContract.MaxSkewSeconds >= claims.Expires) return AssertionResult.Fail(AssertionReason.Expired);
            if (claims.NotBefore - AssertionContract.MaxSkewSeconds > t || claims.IssuedAt - AssertionContract.MaxSkewSeconds > t)
                return AssertionResult.Fail(AssertionReason.NotYetValid);

            // Replay: only record after every other check passed. Entries live until exp + skew.
            if (!RegisterJti(claims.Jti, claims.Expires + AssertionContract.MaxSkewSeconds, t))
                return AssertionResult.Fail(AssertionReason.Replayed);

            return AssertionResult.Ok(claims);
        }

        private bool RegisterJti(string jti, long keepUntil, long nowUnix)
        {
            string key = jti.ToLowerInvariant();
            if (_seen.Count >= MaxReplayEntries)
            {
                lock (_purgeLock)
                {
                    foreach (var kv in _seen.ToArray())
                    {
                        long ignored;
                        if (kv.Value < nowUnix) _seen.TryRemove(kv.Key, out ignored);
                    }
                }
                if (_seen.Count >= MaxReplayEntries) return false; // fail closed when saturated
            }
            return _seen.TryAdd(key, keepUntil);
        }

        private static string StrictUtf8(byte[] bytes)
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
    }
}
