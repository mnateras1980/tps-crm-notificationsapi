using System;
using System.Activities;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Workflow;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tps.Crm.Assertion;

namespace Tps.Crm.WhoAmI.Activity.Tests
{
    [TestClass]
    public class OrgAssertionTests
    {
        private const string Thumb = "0123456789ABCDEF0123456789ABCDEF01234567";
        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

        private sealed class FakeSource : ISigningCertificateSource
        {
            public X509Certificate2 Cert;
            public string Seen;
            public string UseCertificate(string thumbprint, Func<X509Certificate2, string> use)
            {
                Seen = thumbprint;
                if (Cert == null) throw new InvalidOperationException("secret-detail " + thumbprint);
                return use(Cert);
            }
        }

        private static X509Certificate2 NewCert()
        {
            using (RSA rsa = RSA.Create(2048))
            {
                var req = new CertificateRequest("CN=throwaway-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return req.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
            }
        }

        private static AssertionVerifier VerifierFor(X509Certificate2 cert)
        {
            var pub = new X509Certificate2(cert.RawData);
            return new AssertionVerifier(new[] { pub }, () => Now);
        }

        [TestMethod]
        public void Issue_ClaimsEqualContextValues_AndTokenVerifies()
        {
            using (X509Certificate2 cert = NewCert())
            {
                var issuer = new OrgAssertionIssuer(new FakeSource { Cert = cert }, () => Now);
                string token = issuer.Issue("OrgA", "CRMAPP01", Thumb);

                AssertionResult r = VerifierFor(cert).Verify(token);
                Assert.IsTrue(r.Success, r.Reason.ToString());
                Assert.AreEqual("OrgA", r.Claims.Org);
                Assert.AreEqual("CRMAPP01", r.Claims.Mach);
                Assert.AreEqual(AssertionContract.Issuer, r.Claims.Issuer);
                Assert.AreEqual(AssertionContract.Audience, r.Claims.Audience);
                Assert.IsTrue(r.Claims.Expires - r.Claims.IssuedAt <= AssertionContract.MaxLifetimeSeconds);
            }
        }

        [TestMethod]
        public void Issue_PassesThumbprintToSource()
        {
            using (X509Certificate2 cert = NewCert())
            {
                var src = new FakeSource { Cert = cert };
                new OrgAssertionIssuer(src, () => Now).Issue("OrgA", "M1", Thumb);
                Assert.AreEqual(Thumb, src.Seen);
            }
        }

        [TestMethod]
        public void Issue_CertMissing_FailsClosedWithGenericMessage()
        {
            var ex = Assert.ThrowsException<InvalidPluginExecutionException>(
                () => new OrgAssertionIssuer(new FakeSource(), () => Now).Issue("OrgA", "M1", Thumb));
            Assert.AreEqual(OrgAssertionIssuer.FailureMessage, ex.Message);
            Assert.IsFalse(ex.Message.Contains(Thumb));
            Assert.IsFalse(ex.Message.Contains("secret-detail"));
            Assert.IsNull(ex.InnerException);
        }

        [TestMethod]
        public void Issue_KeyUnreadable_FailsClosedWithGenericMessage()
        {
            using (X509Certificate2 full = NewCert())
            using (var publicOnly = new X509Certificate2(full.RawData))
            {
                var ex = Assert.ThrowsException<InvalidPluginExecutionException>(
                    () => new OrgAssertionIssuer(new FakeSource { Cert = publicOnly }, () => Now).Issue("OrgA", "M1", Thumb));
                Assert.AreEqual(OrgAssertionIssuer.FailureMessage, ex.Message);
                Assert.IsNull(ex.InnerException);
            }
        }

        [TestMethod]
        public void Issue_EmptyOrgMachineOrThumbprint_Denies()
        {
            using (X509Certificate2 cert = NewCert())
            {
                var issuer = new OrgAssertionIssuer(new FakeSource { Cert = cert }, () => Now);
                Assert.ThrowsException<InvalidPluginExecutionException>(() => issuer.Issue("", "M1", Thumb));
                Assert.ThrowsException<InvalidPluginExecutionException>(() => issuer.Issue("OrgA", null, Thumb));
                Assert.ThrowsException<InvalidPluginExecutionException>(() => issuer.Issue("OrgA", "M1", " "));
            }
        }

        [TestMethod]
        public void Issue_UrlLikeValues_Deny()
        {
            using (X509Certificate2 cert = NewCert())
            {
                var issuer = new OrgAssertionIssuer(new FakeSource { Cert = cert }, () => Now);
                Assert.ThrowsException<InvalidPluginExecutionException>(() => issuer.Issue("http://evil", "M1", Thumb));
                Assert.ThrowsException<InvalidPluginExecutionException>(() => issuer.Issue("OrgA", "a/b", Thumb));
            }
        }

        [TestMethod]
        public void Activity_HasNoInputArguments_OnlyOrgAssertionOutput()
        {
            PropertyInfo[] props = typeof(OrgAssertionActivity)
                .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);

            Assert.IsFalse(props.Any(p => typeof(InArgument).IsAssignableFrom(p.PropertyType) || typeof(InOutArgument).IsAssignableFrom(p.PropertyType)));
            Assert.IsFalse(props.Any(p => p.PropertyType == typeof(Uri) || p.PropertyType.Name.IndexOf("Uri", StringComparison.OrdinalIgnoreCase) >= 0));
            Assert.IsFalse(props.Any(p => p.GetCustomAttribute<InputAttribute>() != null));

            PropertyInfo output = props.Single();
            Assert.AreEqual(typeof(OutArgument<string>), output.PropertyType);
            Assert.AreEqual("Org Assertion", output.GetCustomAttribute<OutputAttribute>().Name);
        }

        // Hand-written minimal fake: RealProxy answers only the members Execute touches.
        private sealed class Fake : System.Runtime.Remoting.Proxies.RealProxy
        {
            private readonly Func<string, object> _answer;
            public Fake(Type t, Func<string, object> answer) : base(t) { _answer = answer; }
            public override System.Runtime.Remoting.Messaging.IMessage Invoke(System.Runtime.Remoting.Messaging.IMessage msg)
            {
                var call = (System.Runtime.Remoting.Messaging.IMethodCallMessage)msg;
                object value = call.MethodName == "GetType" ? GetProxiedType() : _answer(call.MethodName);
                return new System.Runtime.Remoting.Messaging.ReturnMessage(value, null, 0, call.LogicalCallContext, call);
            }
            public static T Make<T>(Func<string, object> answer) { return (T)new Fake(typeof(T), answer).GetTransparentProxy(); }
        }

        private static WorkflowInvoker InvokerWith(string thumbprintRow, int rows)
        {
            var entities = new EntityCollection();
            for (int i = 0; i < rows; i++)
            {
                var e = new Entity("mm360_setup");
                e["mm360_value"] = thumbprintRow;
                entities.Entities.Add(e);
            }
            var service = Fake.Make<IOrganizationService>(m => m == "RetrieveMultiple" ? entities : null);
            var factory = Fake.Make<IOrganizationServiceFactory>(m => service);
            var ctx = Fake.Make<IWorkflowContext>(m =>
                m == "get_OrganizationName" ? (object)"OrgA" : m == "get_UserId" ? (object)Guid.NewGuid() : null);
            var invoker = new WorkflowInvoker(new OrgAssertionActivity());
            invoker.Extensions.Add<IWorkflowContext>(() => ctx);
            invoker.Extensions.Add<IOrganizationServiceFactory>(() => factory);
            return invoker;
        }

        [TestMethod]
        public void Execute_ThumbprintNotInStore_ThrowsGenericErrorWithoutDetails()
        {
            const string missing = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"; // not a real certificate
            var ex = Assert.ThrowsException<InvalidPluginExecutionException>(() => InvokerWith(missing, 1).Invoke());
            Assert.AreEqual(OrgAssertionIssuer.FailureMessage, ex.Message);
            Assert.IsFalse(ex.Message.Contains(missing));
            Assert.IsNull(ex.InnerException);
        }

        [TestMethod]
        public void Execute_AmbiguousOrMissingSetupRows_Deny()
        {
            Assert.ThrowsException<InvalidPluginExecutionException>(() => InvokerWith(Thumb, 2).Invoke());
            Assert.ThrowsException<InvalidPluginExecutionException>(() => InvokerWith(Thumb, 0).Invoke());
        }

        [TestMethod]
        public void Execute_NoWorkflowContextExtension_DeniesGenerically()
        {
            var ex = Assert.ThrowsException<InvalidPluginExecutionException>(() => new WorkflowInvoker(new OrgAssertionActivity()).Invoke());
            Assert.AreEqual(OrgAssertionIssuer.FailureMessage, ex.Message);
        }

        [TestMethod]
        public void Normalize_RequiresExactly40HexDigits()
        {
            Assert.AreEqual(Thumb, LocalMachineCertificateSource.Normalize("\u200e01 23456789abcdef0123456789ABCDEF01234567"));
            Assert.IsNull(LocalMachineCertificateSource.Normalize("abc"));
            Assert.IsNull(LocalMachineCertificateSource.Normalize(null));
        }
    }
}




