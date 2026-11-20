using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.Threading;
using System.Web.Http;
using System.Web.Http.Controllers;
using Microsoft.Crm.Sdk.Messages;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Query;
using Tps.Crm.Assertion;
using Tps.Crm.WhoAmI.Api.Controllers;
using Tps.Crm.WhoAmI.Api.EarlyBound;
using Tps.Crm.WhoAmI.Api.Services;

namespace Tps.Crm.WhoAmI.Api.Tests
{
    [TestClass]
    public class CrmWhoAmIControllerTests
    {
        private const string CrmUrl = "https://crm.example.test/OrgA/XRMServices/2011/Organization.svc";
        private static readonly Guid UserId = Guid.Parse("11111111-2222-3333-4444-555555555555");

        private sealed class FakeService : IOrganizationService
        {
            public Exception Failure;
            public string RetrievedEntity;
            public string[] RetrievedColumns;
            public Guid RetrievedId;

            public OrganizationResponse Execute(OrganizationRequest request)
            {
                if (Failure != null) throw Failure;
                Assert.IsInstanceOfType(request, typeof(WhoAmIRequest));
                var response = new WhoAmIResponse();
                response.Results = new ParameterCollection();
                response.Results["UserId"] = UserId;
                return response;
            }

            public Entity Retrieve(string entityName, Guid id, ColumnSet columnSet)
            {
                RetrievedEntity = entityName;
                RetrievedId = id;
                RetrievedColumns = new List<string>(columnSet.Columns).ToArray();
                var u = new SystemUser();
                u.systemuserid = id;
                u.fullname = "Test User";
                return u;
            }

            public Guid Create(Entity entity) { throw new NotSupportedException(); }
            public void Update(Entity entity) { throw new NotSupportedException(); }
            public void Delete(string entityName, Guid id) { throw new NotSupportedException(); }
            public void Associate(string entityName, Guid entityId, Relationship relationship, EntityReferenceCollection relatedEntities) { throw new NotSupportedException(); }
            public void Disassociate(string entityName, Guid entityId, Relationship relationship, EntityReferenceCollection relatedEntities) { throw new NotSupportedException(); }
            public EntityCollection RetrieveMultiple(QueryBase query) { throw new NotSupportedException(); }
        }

        private sealed class FakeFactory : ICrmConnectionFactory, ICrmConnection
        {
            public readonly FakeService Fake = new FakeService();
            public int Calls;
            public int Disposed;
            public Uri LastUrl;
            public IOrganizationService Service { get { return Fake; } }
            public ICrmConnection Create(Uri url) { Calls++; LastUrl = url; return this; }
            public void Dispose() { Disposed++; }
        }

        private sealed class Env
        {
            public X509Certificate2 Signer;
            public FakeFactory Factory = new FakeFactory();
            public AssertionVerifier Verifier;
            public OrgAllowList List;

            public Env()
            {
                Signer = NewCert();
                Verifier = new AssertionVerifier(new[] { new X509Certificate2(Signer.RawData) });
                List = OrgAllowList.Build(new[] { Tuple.Create("OrgA", "MACH1", CrmUrl) });
            }

            public string Token(string org, string mach, X509Certificate2 cert = null)
            {
                return AssertionSigner.Sign(AssertionSigner.NewClaims(org, mach, DateTimeOffset.UtcNow, 120), cert ?? Signer);
            }

            public HttpResponseMessage Call(string token, string query = "", bool authenticated = true,
                string headerName = AssertionContract.HeaderName, Action<HttpRequestMessage> tweak = null, AssertionVerifier verifier = null)
            {
                var controller = new CrmWhoAmIController(verifier ?? Verifier, List, Factory);
                var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost/api/whoami/crm" + query);
                var cfg = new HttpConfiguration();
                request.SetConfiguration(cfg);
                controller.ControllerContext = new HttpControllerContext(cfg, new System.Web.Http.Routing.HttpRouteData(new System.Web.Http.Routing.HttpRoute()), request);
                if (token != null) request.Headers.TryAddWithoutValidation(headerName, token);
                if (tweak != null) tweak(request);
                controller.Request = request;
                IIdentity id = authenticated ? new GenericIdentity("CORP\\alice", "Negotiate") : new GenericIdentity(string.Empty);
                controller.RequestContext = new HttpRequestContext { Principal = new GenericPrincipal(id, null), Configuration = cfg };
                return controller.Get().ExecuteAsync(CancellationToken.None).Result;
            }
        }

        private static X509Certificate2 NewCert()
        {
            RSA rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=test-assertion", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        }

        private static string Body(HttpResponseMessage r) { return r.Content.ReadAsStringAsync().Result; }

        private static void AssertNoLeak(HttpResponseMessage r)
        {
            string b = Body(r);
            Assert.IsFalse(b.Contains("example.test"), "CRM URL leaked");
            Assert.IsFalse(b.Contains(" at "), "stack trace leaked");
            Assert.IsFalse(b.Contains("Exception"), "exception text leaked");
        }

        [TestMethod]
        public void ValidAssertion_AllowListed_ReturnsWhoAmIAndFullName()
        {
            var env = new Env();
            var r = env.Call(env.Token("OrgA", "MACH1"));

            Assert.AreEqual(HttpStatusCode.OK, r.StatusCode);
            string b = Body(r);
            StringAssert.Contains(b, "\"org\":\"OrgA\"");
            StringAssert.Contains(b, "\"machine\":\"MACH1\"");
            StringAssert.Contains(b, UserId.ToString());
            StringAssert.Contains(b, "\"fullName\":\"Test User\"");
            Assert.IsFalse(b.Contains("example.test"));
            Assert.AreEqual(1, env.Factory.Calls);
            Assert.AreEqual(1, env.Factory.Disposed);
            Assert.AreEqual(new Uri(CrmUrl), env.Factory.LastUrl);
            Assert.AreEqual("systemuser", env.Factory.Fake.RetrievedEntity);
            Assert.AreEqual(UserId, env.Factory.Fake.RetrievedId);
            CollectionAssert.AreEqual(new[] { "fullname" }, env.Factory.Fake.RetrievedColumns);
        }

        [TestMethod]
        public void ValidAssertion_DifferentCase_IsAllowListed()
        {
            var env = new Env();
            Assert.AreEqual(HttpStatusCode.OK, env.Call(env.Token("orga", "mach1")).StatusCode);
        }

        [TestMethod]
        public void MissingAssertion_Returns401_NoCrmCall()
        {
            var env = new Env();
            var r = env.Call(null);
            Assert.AreEqual(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void GarbageAssertion_Returns401_NoReasonText()
        {
            var env = new Env();
            var r = env.Call("not.a.token");
            Assert.AreEqual(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.IsFalse(Body(r).Contains("Malformed"));
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void AssertionSignedByUntrustedKey_Returns401()
        {
            var env = new Env();
            var r = env.Call(env.Token("OrgA", "MACH1", NewCert()));
            Assert.AreEqual(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void ReplayedAssertion_SecondUseReturns401()
        {
            var env = new Env();
            string token = env.Token("OrgA", "MACH1");
            Assert.AreEqual(HttpStatusCode.OK, env.Call(token).StatusCode);
            Assert.AreEqual(HttpStatusCode.Unauthorized, env.Call(token).StatusCode);
            Assert.AreEqual(1, env.Factory.Calls);
        }

        [TestMethod]
        public void AssertionInAuthorizationHeader_IsIgnored_Returns401()
        {
            var env = new Env();
            var r = env.Call(null, tweak: req => req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + env.Token("OrgA", "MACH1")));
            Assert.AreEqual(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void TwoAssertionHeaders_Returns401()
        {
            var env = new Env();
            var r = env.Call(env.Token("OrgA", "MACH1"), tweak: req => req.Headers.TryAddWithoutValidation(AssertionContract.HeaderName, env.Token("OrgA", "MACH1")));
            Assert.AreEqual(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void VerifierWithNoPinnedKeys_FailsClosed_401()
        {
            var env = new Env();
            var r = env.Call(env.Token("OrgA", "MACH1"), verifier: new AssertionVerifier(new X509Certificate2[0]));
            Assert.AreEqual(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void AnonymousCaller_Returns401_NoCrmCall()
        {
            var env = new Env();
            var r = env.Call(env.Token("OrgA", "MACH1"), authenticated: false);
            Assert.AreEqual(HttpStatusCode.Unauthorized, r.StatusCode);
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void ValidAssertion_UnmappedMachine_Returns403()
        {
            var env = new Env();
            var r = env.Call(env.Token("OrgA", "OTHER"));
            Assert.AreEqual(HttpStatusCode.Forbidden, r.StatusCode);
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void ValidAssertion_UnmappedOrg_Returns403()
        {
            var env = new Env();
            Assert.AreEqual(HttpStatusCode.Forbidden, env.Call(env.Token("OrgB", "MACH1")).StatusCode);
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void CrmOrgUrlInQuery_AnyCase_Returns400_NotUsed()
        {
            var env = new Env();
            foreach (string q in new[] { "?CrmOrgUrl=https://evil.test", "?crmORGurl=x", "?a=1&%43rmOrgUrl=x", "?CRMORGURL" })
            {
                var r = env.Call(env.Token("OrgA", "MACH1"), query: q);
                Assert.AreEqual(HttpStatusCode.BadRequest, r.StatusCode, q);
                Assert.IsFalse(Body(r).Contains("evil"));
            }
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void CrmOrgUrlInHeader_Returns400()
        {
            var env = new Env();
            var r = env.Call(env.Token("OrgA", "MACH1"), tweak: req => req.Headers.TryAddWithoutValidation("X-CrmOrgUrl", "https://evil.test"));
            Assert.AreEqual(HttpStatusCode.BadRequest, r.StatusCode);
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void CrmOrgUrlInBody_Returns400()
        {
            var env = new Env();
            var r = env.Call(env.Token("OrgA", "MACH1"), tweak: req => req.Content = new StringContent("{\"CrmOrgUrl\":\"https://evil.test\"}"));
            Assert.AreEqual(HttpStatusCode.BadRequest, r.StatusCode);
            Assert.IsFalse(Body(r).Contains("evil"));
            Assert.AreEqual(0, env.Factory.Calls);
        }

        [TestMethod]
        public void CrmFailure_Returns502_NoStackTraceOrUrl()
        {
            var env = new Env();
            env.Factory.Fake.Failure = new FaultException("boom at " + CrmUrl + "\n   at Some.Stack.Frame()");
            var r = env.Call(env.Token("OrgA", "MACH1"));
            Assert.AreEqual(HttpStatusCode.BadGateway, r.StatusCode);
            AssertNoLeak(r);
            Assert.AreEqual(1, env.Factory.Disposed);
        }

        [TestMethod]
        public void SignedAssertionWithBadCharsetClaims_Returns401_NoCrmCall()
        {
            var env = new Env();
            foreach (string bad in new[] { "a|b", "org\n", "o rg", "../x", new string('a', 65), "\u00e9" })
            {
                HttpResponseMessage r;
                try { r = env.Call(env.Token(bad, "MACH1")); }
                catch (ArgumentException) { continue; } // signer refused to mint it: nothing reaches the API
                Assert.AreNotEqual(HttpStatusCode.OK, r.StatusCode, bad);
                Assert.AreEqual(0, env.Factory.Calls, bad);
            }
        }

        [TestMethod]
        public void IsValidName_RejectsTrailingNewlineEmptyAndNull()
        {
            Assert.IsTrue(OrgAllowList.IsValidName("Org-A_1.x"));
            Assert.IsFalse(OrgAllowList.IsValidName("OrgA\n"));
            Assert.IsFalse(OrgAllowList.IsValidName(string.Empty));
            Assert.IsFalse(OrgAllowList.IsValidName(null));
            Assert.IsFalse(OrgAllowList.IsValidName("a b"));
            Assert.IsFalse(OrgAllowList.IsValidName(new string('a', 65)));
        }

        [TestMethod]
        public void CrmEmptyUserId_Returns502_NoLeak()
        {
            var env = new Env();
            env.Factory.Fake.Failure = new InvalidOperationException("Empty UserId " + CrmUrl);
            var r = env.Call(env.Token("OrgA", "MACH1"));
            Assert.AreEqual(HttpStatusCode.BadGateway, r.StatusCode);
            AssertNoLeak(r);
        }

        [TestMethod]
        public void FailureResponses_AreGenericJsonErrorCodesOnly()
        {
            var env = new Env();
            var r = env.Call(env.Token("OrgA", "OTHER"));
            Assert.AreEqual("{\"error\":\"forbidden\"}", Body(r));
            var r2 = env.Call("x.y.z");
            Assert.AreEqual("{\"error\":\"unauthorized\"}", Body(r2));
        }

        [TestMethod]
        public void AllowList_RejectsInvalidNamesNonHttpsUrlsAndDuplicates()
        {
            var list = OrgAllowList.Build(new[]
            {
                Tuple.Create("a|b", "c", CrmUrl),
                Tuple.Create("a", "b|c", CrmUrl),
                Tuple.Create("ok1", "m\n", CrmUrl),
                Tuple.Create("ok2", "m", "http://crm.example.test/Org"),
                Tuple.Create("ok3", "m", "https://user:pw@crm.example.test/Org"),
                Tuple.Create("dup", "m", CrmUrl),
                Tuple.Create("DUP", "M", CrmUrl),
                Tuple.Create("good", "m", CrmUrl)
            });
            Uri u;
            Assert.IsFalse(list.TryResolve("a|b", "c", out u));
            Assert.IsFalse(list.TryResolve("a", "b|c", out u));
            Assert.IsFalse(list.TryResolve("ok1", "m\n", out u));
            Assert.IsFalse(list.TryResolve("ok2", "m", out u));
            Assert.IsFalse(list.TryResolve("ok3", "m", out u));
            Assert.IsFalse(list.TryResolve("dup", "m", out u));
            Assert.IsTrue(list.TryResolve("GOOD", "M", out u));
            Assert.IsFalse(OrgAllowList.Empty.TryResolve("good", "m", out u));
        }
    }
}
