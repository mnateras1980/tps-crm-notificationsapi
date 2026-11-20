using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using Microsoft.Crm.Sdk.Messages;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Query;
using Newtonsoft.Json;
using Tps.Crm.Assertion;
using Tps.Crm.WhoAmI.Api.EarlyBound;
using Tps.Crm.WhoAmI.Api.Services;

namespace Tps.Crm.WhoAmI.Api.Controllers
{
    public sealed class CrmWhoAmIResult
    {
        [JsonProperty("org")] public string Org { get; set; }
        [JsonProperty("machine")] public string Machine { get; set; }
        [JsonProperty("userId")] public Guid UserId { get; set; }
        [JsonProperty("fullName")] public string FullName { get; set; }
    }

    public sealed class ApiError
    {
        [JsonProperty("error")] public string Error { get; set; }
    }

    /// <summary>
    /// GET api/whoami/crm: Windows auth (global) + signed org assertion + server-side allow-list, then a
    /// read-only CRM WhoAmI and early-bound SystemUser lookup. Order: auth, CrmOrgUrl guard, assertion, allow-list, CRM.
    /// </summary>
    [Authorize]
    [RoutePrefix("api/whoami/crm")]
    public class CrmWhoAmIController : ApiController
    {
        private const string ForbiddenInputName = "crmorgurl";

        private readonly AssertionVerifier _verifier;
        private readonly IOrgAllowList _allowList;
        private readonly ICrmConnectionFactory _crm;

        public CrmWhoAmIController() : this(ApiServices.Verifier, ApiServices.AllowList, ApiServices.CrmFactory)
        {
        }

        public CrmWhoAmIController(AssertionVerifier verifier, IOrgAllowList allowList, ICrmConnectionFactory crm)
        {
            if (verifier == null) throw new ArgumentNullException("verifier");
            if (allowList == null) throw new ArgumentNullException("allowList");
            if (crm == null) throw new ArgumentNullException("crm");
            _verifier = verifier;
            _allowList = allowList;
            _crm = crm;
        }

        [HttpGet]
        [Route("")]
        public IHttpActionResult Get()
        {
            if (User == null || User.Identity == null || !User.Identity.IsAuthenticated)
                return Fail(HttpStatusCode.Unauthorized, "unauthorized");

            // Never read, use or echo a client-supplied CRM URL: names are checked, values are not.
            if (HasForbiddenInput(Request)) return Fail(HttpStatusCode.BadRequest, "bad_request");

            string token = ReadAssertionHeader(Request);
            AssertionResult result = _verifier.Verify(token);
            if (!result.Success)
            {
                // Reason code only (no token content) at a low level; the client gets no reason.
                Trace.TraceInformation("Assertion rejected: {0}", result.Reason);
                return Fail(HttpStatusCode.Unauthorized, "unauthorized");
            }

            string org = result.Claims.Org, mach = result.Claims.Mach;
            Uri url;
            if (!OrgAllowList.IsValidName(org) || !OrgAllowList.IsValidName(mach))
            {
                Trace.TraceInformation("Assertion rejected: claim format");
                return Fail(HttpStatusCode.Unauthorized, "unauthorized");
            }
            if (!_allowList.TryResolve(org, mach, out url) || url == null)
            {
                Trace.TraceWarning("Org/machine not on allow-list: {0}/{1}", org, mach);
                return Fail(HttpStatusCode.Forbidden, "forbidden");
            }

            try
            {
                using (ICrmConnection conn = _crm.Create(url))
                {
                    var who = (WhoAmIResponse)conn.Service.Execute(new WhoAmIRequest());
                    if (who.UserId == Guid.Empty) throw new InvalidOperationException("Empty UserId");
                    Entity entity = conn.Service.Retrieve(SystemUser.EntityLogicalName, who.UserId, new ColumnSet("fullname"));
                    SystemUser user = entity.ToEntity<SystemUser>();
                    return Ok(new CrmWhoAmIResult { Org = org, Machine = mach, UserId = who.UserId, FullName = user.fullname });
                }
            }
            catch (Exception ex)
            {
                // Type name only: FaultException messages can contain URLs or server detail.
                Trace.TraceWarning("CRM call failed: {0}", ex.GetType().Name);
                return Fail(HttpStatusCode.BadGateway, "upstream_unavailable");
            }
        }

        private IHttpActionResult Fail(HttpStatusCode status, string code)
        {
            return Content(status, new ApiError { Error = code });
        }

        private static string ReadAssertionHeader(HttpRequestMessage request)
        {
            IEnumerable<string> values;
            if (request == null || !request.Headers.TryGetValues(AssertionContract.HeaderName, out values)) return null;
            string[] all = values.ToArray();
            return all.Length == 1 ? all[0] : null; // exactly one header value
        }

        private static bool HasForbiddenInput(HttpRequestMessage request)
        {
            if (request == null) return true;

            // Any body on this GET is rejected without reading it (covers a CrmOrgUrl in the body).
            long? length = request.Content == null ? null : request.Content.Headers.ContentLength;
            if ((length.HasValue && length.Value > 0) || request.Headers.TransferEncodingChunked == true) return true;

            // Header names.
            if (request.Headers.Any(h => h.Key.IndexOf(ForbiddenInputName, StringComparison.OrdinalIgnoreCase) >= 0)) return true;

            // Query parameter names only.
            string query = request.RequestUri == null ? string.Empty : request.RequestUri.Query;
            foreach (string pair in query.TrimStart('?').Split('&'))
            {
                int eq = pair.IndexOf('=');
                string name = eq < 0 ? pair : pair.Substring(0, eq);
                string decoded;
                try { decoded = Uri.UnescapeDataString(name.Replace('+', ' ')); }
                catch (UriFormatException) { return true; }
                if (decoded.IndexOf(ForbiddenInputName, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }
    }
}
