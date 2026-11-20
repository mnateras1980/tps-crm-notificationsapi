using System.Web;
using System.Web.Http;

namespace Tps.Crm.WhoAmI.Api
{
    public class WebApiApplication : HttpApplication
    {
        protected void Application_Start()
        {
            GlobalConfiguration.Configure(WebApiConfig.Register);
        }
    }
}
