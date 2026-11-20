using System.Web;
using System.Web.Http;

namespace Tps.Crm.WhoAmI.Api
{
    public class WebApiApplication : HttpApplication
    {
        protected void Application_Start()
        {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
            GlobalConfiguration.Configure(WebApiConfig.Register);
        }
    }
}
