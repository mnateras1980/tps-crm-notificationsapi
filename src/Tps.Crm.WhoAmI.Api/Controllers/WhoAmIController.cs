using System.Web.Http;
using Tps.Crm.WhoAmI.Api.Services;

namespace Tps.Crm.WhoAmI.Api.Controllers
{
    [Authorize]
    [RoutePrefix("api/whoami")]
    public class WhoAmIController : ApiController
    {
        [HttpGet]
        [Route("")]
        public IHttpActionResult Get()
        {
            var caller = CallerMapper.Map(User);
            if (caller == null)
            {
                return Unauthorized();
            }

            return Ok(caller);
        }
    }
}
