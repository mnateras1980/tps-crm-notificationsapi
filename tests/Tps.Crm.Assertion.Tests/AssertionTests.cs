using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tps.Crm.Assertion.Tests
{
    [TestClass]
    public class AssertionTests
    {
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);
        private static X509Certificate2 _key1, _key2, _unpinned;

        [ClassInitialize]
        public static void Init(TestContext ctx)
        {
            _key1 = NewCert("CN=test-assert-1");
            _key2 = NewCert("CN=test-assert-2");
            _unpinned = NewCert("CN=test-rogue");
        }

        [ClassCleanup]
        public static void Cleanup()
        {
            _key1.Dispose(); _key2.Dispose(); _unpinned.Dispose();
        }

        private static X509Certificate2 NewCert(string subject)
        {
            using (RSA rsa = RSA.Create(2048))
            {
                var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using (X509Certificate2 c = req.CreateSelfSigned(Now.AddYears(-1), Now.AddYears(1)))
                {
                    // Round-trip to get a cert with its own exportable in-memory key copy.
                    return new X509Certificate2(c.Export(X509ContentType.Pfx, "t"), "t", X509KeyStorageFlags.Exportable);
                }
            }
        }

        private static X509Certificate2 PublicOnly(X509Certificate2 c) { return new X509Certificate2(c.RawData); }

        private static AssertionVerifier Verifier(params X509Certificate2[] pinned)
        {
            var list = new List<X509Certificate2>();
            foreach (var c in pinned) list.Add(PublicOnly(c));
            return new AssertionVerifier(list, () => Now);
        }

        private static string Good(X509Certificate2 key = null)
        {
            return AssertionSigner.Sign(AssertionSigner.NewClaims("orgA", "CRM01", Now, 120), key ?? _key1);
        }

        private static string B64(string s) { return Base64Url.Encode(Encoding.UTF8.GetBytes(s)); }

        private static string Raw(string headerJson, string payloadJson, X509Certificate2 key)
        {
            string input = B64(headerJson) + "." + B64(payloadJson);
            using (RSA rsa = key.GetRSAPrivateKey())
                return input + "." + Base64Url.Encode(rsa.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        private static string Header(X509Certificate2 key, string alg = "RS256", string typ = "tps-org+jwt", string extra = "")
        {
            return "{\"alg\":\"" + alg + "\",\"typ\":\"" + typ + "\",\"kid\":\"" + CertThumbprint.Sha256(key) + "\"" + extra + "}";
        }

        private static string Payload(long iat, long nbf, long exp, string iss = "tps-crm-workflow", string aud = "tps-crm-whoami-api",
            string jti = null, string extra = "", string org = "orgA")
        {
            return "{\"iss\":\"" + iss + "\",\"aud\":\"" + aud + "\",\"org\":\"" + org + "\",\"mach\":\"CRM01\",\"iat\":" + iat +
                   ",\"nbf\":" + nbf + ",\"exp\":" + exp + ",\"jti\":\"" + (jti ?? Guid.NewGuid().ToString()) + "\"" + extra + "}";
        }

        private static long T { get { return Now.ToUnixTimeSeconds(); } }

        private static void AssertRejected(string token, AssertionReason reason, params X509Certificate2[] pinned)
        {
            var r = Verifier(pinned.Length == 0 ? new[] { _key1 } : pinned).Verify(token);
            Assert.IsFalse(r.Success);
            Assert.IsNull(r.Claims);
            Assert.AreEqual(reason, r.Reason);
        }

        [TestMethod]
        public void ValidTokenRoundTripsAndMatchesContract()
        {
            string token = Good();
            string[] parts = token.Split('.');
            Assert.AreEqual(3, parts.Length);
            var header = FlatJson.Parse(Encoding.UTF8.GetString(Base64Url.Decode(parts[0])));
            Assert.AreEqual("RS256", header["alg"]);
            Assert.AreEqual("tps-org+jwt", header["typ"]);
            Assert.AreEqual(CertThumbprint.Sha256(_key1), header["kid"]);
            Assert.AreEqual(3, header.Count);

            var r = Verifier(_key1).Verify(token);
            Assert.IsTrue(r.Success);
            Assert.AreEqual("orgA", r.Claims.Org);
            Assert.AreEqual("CRM01", r.Claims.Mach);
            Assert.AreEqual(AssertionContract.Issuer, r.Claims.Issuer);
            Assert.AreEqual(AssertionContract.Audience, r.Claims.Audience);
        }

        [TestMethod]
        public void CurrentAndNextPinnedKeysBothAccepted()
        {
            var v = Verifier(_key1, _key2);
            Assert.IsTrue(v.Verify(Good(_key1)).Success);
            Assert.IsTrue(v.Verify(Good(_key2)).Success);
        }

        [TestMethod]
        public void SigningRejectsLifetimeOver300Seconds()
        {
            Assert.ThrowsException<ArgumentException>(() => AssertionSigner.Sign(AssertionSigner.NewClaims("o", "m", Now, 301), _key1));
            Assert.IsNotNull(AssertionSigner.Sign(AssertionSigner.NewClaims("o", "m", Now, 300), _key1));
        }

        [TestMethod]
        public void SigningRejectsBadClaims()
        {
            var c = AssertionSigner.NewClaims("http://evil/x", "m", Now, 60);
            Assert.ThrowsException<ArgumentException>(() => AssertionSigner.Sign(c, _key1));
            c = AssertionSigner.NewClaims("o", "m", Now, 60); c.Audience = "other";
            Assert.ThrowsException<ArgumentException>(() => AssertionSigner.Sign(c, _key1));
            c = AssertionSigner.NewClaims("o", "m", Now, 60);
            Assert.ThrowsException<ArgumentException>(() => AssertionSigner.Sign(c, PublicOnly(_key1)));
        }

        [TestMethod]
        public void TamperedPayloadRejected()
        {
            string[] p = Good().Split('.');
            string forged = B64(Payload(T, T, T + 120, org: "orgB"));
            AssertRejected(p[0] + "." + forged + "." + p[2], AssertionReason.BadSignature);
        }

        [TestMethod]
        public void TamperedSignatureRejected()
        {
            string[] p = Good().Split('.');
            byte[] sig = Base64Url.Decode(p[2]); sig[0] ^= 0x01;
            AssertRejected(p[0] + "." + p[1] + "." + Base64Url.Encode(sig), AssertionReason.BadSignature);
        }

        [TestMethod]
        public void ExpiredRejectedButWithinSkewAccepted()
        {
            AssertRejected(Raw(Header(_key1), Payload(T - 300, T - 300, T - 61), _key1), AssertionReason.Expired);
            Assert.IsTrue(Verifier(_key1).Verify(Raw(Header(_key1), Payload(T - 300, T - 300, T - 30), _key1)).Success);
        }

        [TestMethod]
        public void NotYetValidRejectedButWithinSkewAccepted()
        {
            AssertRejected(Raw(Header(_key1), Payload(T + 120, T + 120, T + 200), _key1), AssertionReason.NotYetValid);
            Assert.IsTrue(Verifier(_key1).Verify(Raw(Header(_key1), Payload(T + 30, T + 30, T + 100), _key1)).Success);
        }

        [TestMethod]
        public void WrongIssuerAndAudienceRejected()
        {
            AssertRejected(Raw(Header(_key1), Payload(T, T, T + 60, iss: "evil"), _key1), AssertionReason.InvalidIssuer);
            AssertRejected(Raw(Header(_key1), Payload(T, T, T + 60, aud: "evil"), _key1), AssertionReason.InvalidAudience);
        }

        [TestMethod]
        public void LifetimeOver300SecondsRejectedByVerifier()
        {
            AssertRejected(Raw(Header(_key1), Payload(T, T, T + 301), _key1), AssertionReason.InvalidClaims);
        }

        [TestMethod]
        public void AlgorithmOtherThanRs256Rejected()
        {
            foreach (string alg in new[] { "none", "None", "HS256", "RS384", "ES256", "" })
                AssertRejected(Raw(Header(_key1, alg: alg), Payload(T, T, T + 60), _key1), AssertionReason.UnsupportedAlgorithm);
            AssertRejected(B64(Header(_key1, alg: "none")) + "." + B64(Payload(T, T, T + 60)) + ".", AssertionReason.Malformed);
        }

        [TestMethod]
        public void WrongTypAndForbiddenHeadersRejected()
        {
            AssertRejected(Raw(Header(_key1, typ: "JWT"), Payload(T, T, T + 60), _key1), AssertionReason.InvalidHeader);
            foreach (string extra in new[] { ",\"jku\":\"https://x/k\"", ",\"x5c\":\"AAAA\"", ",\"jwk\":\"x\"", ",\"crit\":\"x\"" })
                AssertRejected(Raw(Header(_key1, extra: extra), Payload(T, T, T + 60), _key1), AssertionReason.InvalidHeader);
        }

        [TestMethod]
        public void UnpinnedKeyRejectedEvenWithSelfConsistentKid()
        {
            AssertRejected(Good(_unpinned), AssertionReason.UnknownKey);
            // kid claims the pinned thumbprint but signed by the rogue key.
            AssertRejected(Raw(Header(_key1), Payload(T, T, T + 60), _unpinned), AssertionReason.BadSignature);
        }

        [TestMethod]
        public void NoPinnedKeysFailsClosed()
        {
            var r = new AssertionVerifier(new X509Certificate2[0], () => Now).Verify(Good());
            Assert.IsFalse(r.Success);
            Assert.AreEqual(AssertionReason.VerifierUnavailable, r.Reason);
        }

        [TestMethod]
        public void ReplayedJtiRejected()
        {
            var v = Verifier(_key1);
            string token = Good();
            Assert.IsTrue(v.Verify(token).Success);
            Assert.AreEqual(AssertionReason.Replayed, v.Verify(token).Reason);
        }

        [TestMethod]
        public void RejectedTokenDoesNotBurnJti()
        {
            var v = Verifier(_key1);
            string jti = Guid.NewGuid().ToString();
            Assert.AreEqual(AssertionReason.InvalidAudience, v.Verify(Raw(Header(_key1), Payload(T, T, T + 60, aud: "x", jti: jti), _key1)).Reason);
            Assert.IsTrue(v.Verify(Raw(Header(_key1), Payload(T, T, T + 60, jti: jti), _key1)).Success);
        }

        [TestMethod]
        public void UrlLikeClaimsRejected()
        {
            foreach (string n in new[] { "CrmOrgUrl", "crmorgurl", "url", "uri", "host" })
                AssertRejected(Raw(Header(_key1), Payload(T, T, T + 60, extra: ",\"" + n + "\":\"https://x\""), _key1), AssertionReason.UrlClaim);
        }

        [TestMethod]
        public void UnknownClaimAndUrlLikeValuesRejected()
        {
            AssertRejected(Raw(Header(_key1), Payload(T, T, T + 60, extra: ",\"role\":\"admin\""), _key1), AssertionReason.UnknownClaim);
            AssertRejected(Raw(Header(_key1), Payload(T, T, T + 60, org: "https://evil.example/org"), _key1), AssertionReason.InvalidClaims);
        }

        [TestMethod]
        public void MissingClaimAndDuplicateKeysRejected()
        {
            string noJti = "{\"iss\":\"tps-crm-workflow\",\"aud\":\"tps-crm-whoami-api\",\"org\":\"o\",\"mach\":\"m\",\"iat\":" + T + ",\"nbf\":" + T + ",\"exp\":" + (T + 60) + "}";
            AssertRejected(Raw(Header(_key1), noJti, _key1), AssertionReason.InvalidClaims);
            AssertRejected(Raw(Header(_key1), Payload(T, T, T + 60).TrimEnd('}') + ",\"org\":\"orgB\"}", _key1), AssertionReason.Malformed);
        }

        [TestMethod]
        public void MalformedInputsRejectedWithoutThrowing()
        {
            foreach (string t in new[] { null, "", "a", "a.b", "a.b.c.d", "!!!.???.***", new string('a', 5000), "e30.e30.AAAA" })
            {
                var r = Verifier(_key1).Verify(t);
                Assert.IsFalse(r.Success);
                Assert.IsNull(r.Claims);
            }
        }

        [TestMethod]
        public void ReasonCodesDoNotLeakDetails()
        {
            var r = Verifier(_key1).Verify(Raw(Header(_key1), Payload(T, T, T + 60, org: "https://secret"), _key1));
            Assert.IsFalse(r.ToString().Contains("secret"));
            Assert.IsFalse(r.Reason.ToString().Contains("secret"));
        }
    }
}
