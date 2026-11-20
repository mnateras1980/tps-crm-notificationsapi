using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.ServiceModel.Description;
using System.Text.RegularExpressions;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Client;

namespace Tps.Crm.WhoAmI.Api.Services
{
    /// <summary>A per-request CRM connection. Disposing releases the channel.</summary>
    public interface ICrmConnection : IDisposable
    {
        IOrganizationService Service { get; }
    }

    /// <summary>Creates a connection to a server-resolved organization service URL (fakeable in tests).</summary>
    public interface ICrmConnectionFactory
    {
        ICrmConnection Create(Uri organizationServiceUrl);
    }

    /// <summary>
    /// Real factory. Credentials are the app-pool identity (DefaultNetworkCredentials) ONLY:
    /// no username/password settings exist. Requires that ASP.NET impersonation stays off.
    /// </summary>
    public sealed class CrmConnectionFactory : ICrmConnectionFactory
    {
        public ICrmConnection Create(Uri organizationServiceUrl)
        {
            if (organizationServiceUrl == null) throw new ArgumentNullException("organizationServiceUrl");
            var credentials = new ClientCredentials();
            credentials.Windows.ClientCredential = CredentialCache.DefaultNetworkCredentials;

            var proxy = new OrganizationServiceProxy(organizationServiceUrl, null, credentials, null);
            try
            {
                proxy.EnableProxyTypes(); // calling assembly = this API assembly (early-bound SystemUser)
                proxy.Timeout = TimeSpan.FromSeconds(30);
                return new ProxyConnection(proxy);
            }
            catch
            {
                proxy.Dispose();
                throw;
            }
        }

        private sealed class ProxyConnection : ICrmConnection
        {
            private readonly OrganizationServiceProxy _proxy;
            public ProxyConnection(OrganizationServiceProxy proxy) { _proxy = proxy; }
            public IOrganizationService Service { get { return _proxy; } }
            public void Dispose() { _proxy.Dispose(); }
        }
    }

    /// <summary>Structured allow-list key: (org, machine), compared case-insensitively and ordinally. No delimiter joining.</summary>
    public struct OrgKey : IEquatable<OrgKey>
    {
        private readonly string _org;
        private readonly string _mach;

        public OrgKey(string org, string mach) { _org = org ?? string.Empty; _mach = mach ?? string.Empty; }
        public string Org { get { return _org; } }
        public string Mach { get { return _mach; } }

        public bool Equals(OrgKey other)
        {
            return string.Equals(_org, other._org, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(_mach, other._mach, StringComparison.OrdinalIgnoreCase);
        }

        public override bool Equals(object obj) { return obj is OrgKey && Equals((OrgKey)obj); }

        public override int GetHashCode()
        {
            unchecked
            {
                return (StringComparer.OrdinalIgnoreCase.GetHashCode(_org) * 397) ^ StringComparer.OrdinalIgnoreCase.GetHashCode(_mach);
            }
        }
    }

    public interface IOrgAllowList
    {
        bool TryResolve(string org, string mach, out Uri organizationServiceUrl);
    }

    /// <summary>Server-side (org, machine) -> CRM URL map. Invalid or duplicate entries are dropped (fail closed).</summary>
    public sealed class OrgAllowList : IOrgAllowList
    {
        // \z (not $) so a trailing newline cannot pass.
        private static readonly Regex NamePattern = new Regex(@"^[A-Za-z0-9._-]{1,64}\z", RegexOptions.CultureInvariant);
        private readonly Dictionary<OrgKey, Uri> _map;

        private OrgAllowList(Dictionary<OrgKey, Uri> map) { _map = map; }

        public static OrgAllowList Empty { get { return new OrgAllowList(new Dictionary<OrgKey, Uri>()); } }

        public static bool IsValidName(string value)
        {
            return value != null && NamePattern.IsMatch(value);
        }

        public static OrgAllowList Build(IEnumerable<Tuple<string, string, string>> entries)
        {
            var map = new Dictionary<OrgKey, Uri>();
            var duplicates = new HashSet<OrgKey>();
            foreach (var e in entries ?? Enumerable.Empty<Tuple<string, string, string>>())
            {
                Uri url;
                if (!IsValidName(e.Item1) || !IsValidName(e.Item2) || !TryParseUrl(e.Item3, out url))
                {
                    Trace.TraceWarning("Allow-list entry ignored: invalid org, machine or URL.");
                    continue;
                }
                var key = new OrgKey(e.Item1, e.Item2);
                if (map.ContainsKey(key)) duplicates.Add(key);
                else map[key] = url;
            }
            foreach (var d in duplicates)
            {
                map.Remove(d); // ambiguous mapping: deny both
                Trace.TraceWarning("Allow-list duplicate entry removed.");
            }
            return new OrgAllowList(map);
        }

        public static OrgAllowList FromConfig()
        {
            try
            {
                var section = ConfigurationManager.GetSection(OrgAllowListSection.SectionName) as OrgAllowListSection;
                if (section == null) return Empty;
                return Build(section.Entries.Cast<OrgAllowListElement>()
                    .Select(x => Tuple.Create(x.Org, x.Machine, x.CrmUrl)).ToList());
            }
            catch (Exception ex)
            {
                Trace.TraceError("Allow-list configuration failed: {0}", ex.GetType().Name);
                return Empty; // deny all
            }
        }

        public bool TryResolve(string org, string mach, out Uri organizationServiceUrl)
        {
            organizationServiceUrl = null;
            if (!IsValidName(org) || !IsValidName(mach)) return false;
            return _map.TryGetValue(new OrgKey(org, mach), out organizationServiceUrl);
        }

        private static bool TryParseUrl(string s, out Uri url)
        {
            return Uri.TryCreate(s, UriKind.Absolute, out url) && url.Scheme == Uri.UriSchemeHttps &&
                   string.IsNullOrEmpty(url.UserInfo) && string.IsNullOrEmpty(url.Query) && string.IsNullOrEmpty(url.Fragment);
        }
    }

    public sealed class OrgAllowListSection : ConfigurationSection
    {
        public const string SectionName = "tpsOrgAllowList";

        [ConfigurationProperty("", IsDefaultCollection = true)]
        public OrgAllowListCollection Entries { get { return (OrgAllowListCollection)base[""]; } }
    }

    public sealed class OrgAllowListCollection : ConfigurationElementCollection
    {
        protected override ConfigurationElement CreateNewElement() { return new OrgAllowListElement(); }

        protected override object GetElementKey(ConfigurationElement element)
        {
            var e = (OrgAllowListElement)element;
            return new OrgKey(e.Org, e.Machine); // duplicates (case-insensitive) fail the section load
        }
    }

    public sealed class OrgAllowListElement : ConfigurationElement
    {
        [ConfigurationProperty("org", IsRequired = true)]
        public string Org { get { return (string)this["org"]; } }

        [ConfigurationProperty("machine", IsRequired = true)]
        public string Machine { get { return (string)this["machine"]; } }

        [ConfigurationProperty("crmUrl", IsRequired = true)]
        public string CrmUrl { get { return (string)this["crmUrl"]; } }
    }
}
