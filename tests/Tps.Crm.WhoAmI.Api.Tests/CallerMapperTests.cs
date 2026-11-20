using System.Security.Principal;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tps.Crm.WhoAmI.Api.Services;

namespace Tps.Crm.WhoAmI.Api.Tests
{
    [TestClass]
    public class CallerMapperTests
    {
        [TestMethod]
        public void Map_AuthenticatedDomainUser_ReturnsNameAndAuthenticated()
        {
            var principal = new GenericPrincipal(new GenericIdentity("CORP\\alice", "Negotiate"), null);

            var result = CallerMapper.Map(principal);

            Assert.IsNotNull(result);
            Assert.AreEqual("CORP\\alice", result.Name);
            Assert.IsTrue(result.IsAuthenticated);
        }

        [TestMethod]
        public void Map_NullPrincipal_Denies()
        {
            Assert.IsNull(CallerMapper.Map(null));
        }

        [TestMethod]
        public void Map_AnonymousIdentity_Denies()
        {
            var principal = new GenericPrincipal(new GenericIdentity(string.Empty), null);

            Assert.IsNull(CallerMapper.Map(principal));
        }

        [TestMethod]
        public void Map_AuthenticatedButNoName_Denies()
        {
            var principal = new GenericPrincipal(new GenericIdentity(" ", "Negotiate"), null);

            Assert.IsNull(CallerMapper.Map(principal));
        }

        [TestMethod]
        public void Map_NullIdentity_Denies()
        {
            Assert.IsNull(CallerMapper.Map(new NullIdentityPrincipal()));
        }

        private sealed class NullIdentityPrincipal : IPrincipal
        {
            public IIdentity Identity { get { return null; } }

            public bool IsInRole(string role) { return false; }
        }
    }
}
