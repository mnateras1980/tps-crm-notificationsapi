using System.Security.Principal;
using Tps.Crm.WhoAmI.Api.Models;

namespace Tps.Crm.WhoAmI.Api.Services
{
    public static class CallerMapper
    {
        /// <summary>
        /// Maps a principal to caller info. Returns null (deny) when the identity is
        /// missing, unauthenticated, anonymous, guest, or has no name.
        /// </summary>
        public static CallerInfo Map(IPrincipal principal)
        {
            var identity = principal == null ? null : principal.Identity;
            if (identity == null || !identity.IsAuthenticated || string.IsNullOrWhiteSpace(identity.Name))
            {
                return null;
            }

            var windows = identity as WindowsIdentity;
            if (windows != null && (windows.IsAnonymous || windows.IsGuest))
            {
                return null;
            }

            return new CallerInfo(identity.Name, true);
        }
    }
}
