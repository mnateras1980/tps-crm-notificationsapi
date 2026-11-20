using System.Net.Http.Formatting;
using System.Web.Http;
using Newtonsoft.Json.Serialization;

namespace Tps.Crm.WhoAmI.Api
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Fail closed: every endpoint requires an authenticated caller unless explicitly opted out.
            config.Filters.Add(new AuthorizeAttribute());

            config.Formatters.Clear();
            var json = new JsonMediaTypeFormatter();
            json.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
            config.Formatters.Add(json);

            config.MapHttpAttributeRoutes();
        }
    }
}
