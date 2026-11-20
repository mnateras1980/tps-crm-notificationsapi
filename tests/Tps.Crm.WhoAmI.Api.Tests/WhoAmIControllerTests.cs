using System.Reflection;
using System.Security.Principal;
using System.Web.Http;
using System.Web.Http.Results;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tps.Crm.WhoAmI.Api.Controllers;
using Tps.Crm.WhoAmI.Api.Models;

namespace Tps.Crm.WhoAmI.Api.Tests
{
    [TestClass]
    public class WhoAmIControllerTests
    {
        private static WhoAmIController Create(IPrincipal principal)
        {
            var controller = new WhoAmIController();
            controller.RequestContext = new System.Web.Http.Controllers.HttpRequestContext { Principal = principal };
            return controller;
        }

        [TestMethod]
        public void Get_AuthenticatedCaller_ReturnsOkWithCaller()
        {
            var controller = Create(new GenericPrincipal(new GenericIdentity("CORP\\alice", "Negotiate"), null));

            var result = controller.Get() as OkNegotiatedContentResult<CallerInfo>;

            Assert.IsNotNull(result);
            Assert.AreEqual("CORP\\alice", result.Content.Name);
            Assert.IsTrue(result.Content.IsAuthenticated);
        }

        [TestMethod]
        public void Get_AnonymousCaller_ReturnsUnauthorized()
        {
            var controller = Create(new GenericPrincipal(new GenericIdentity(string.Empty), null));

            Assert.IsInstanceOfType(controller.Get(), typeof(UnauthorizedResult));
        }

        [TestMethod]
        public void Get_NullPrincipal_ReturnsUnauthorized()
        {
            var controller = Create(null);

            Assert.IsInstanceOfType(controller.Get(), typeof(UnauthorizedResult));
        }

        [TestMethod]
        public void Controller_RequiresAuthorization()
        {
            Assert.IsTrue(typeof(WhoAmIController).IsDefined(typeof(AuthorizeAttribute), true));
            Assert.IsFalse(typeof(WhoAmIController).IsDefined(typeof(AllowAnonymousAttribute), true));
            Assert.IsFalse(typeof(WhoAmIController).GetMethod("Get").IsDefined(typeof(AllowAnonymousAttribute), true));
        }
    }
}
