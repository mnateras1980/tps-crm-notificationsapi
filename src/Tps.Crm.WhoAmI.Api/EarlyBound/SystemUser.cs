using System;
using System.Runtime.Serialization;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Client;

// Lets OrganizationServiceProxy.EnableProxyTypes() find the early-bound classes in this assembly.
[assembly: ProxyTypesAssembly]

namespace Tps.Crm.WhoAmI.Api.EarlyBound
{
    /// <summary>
    /// Trimmed, generated-style early-bound "systemuser" (pattern: crm-testapp EarlyBound\SystemUser.cs).
    /// Only the attributes this API needs. Regenerate with pac modelbuilder if more are needed.
    /// </summary>
    [DataContract]
    [EntityLogicalName(EntityLogicalName)]
    public class SystemUser : Entity
    {
        public const string EntityLogicalName = "systemuser";

        public SystemUser() : base(EntityLogicalName)
        {
        }

        [AttributeLogicalName("systemuserid")]
        public Guid? systemuserid
        {
            get { return GetAttributeValue<Guid?>("systemuserid"); }
            set
            {
                SetAttributeValue("systemuserid", value);
                Id = value.GetValueOrDefault();
            }
        }

        [AttributeLogicalName("fullname")]
        public string fullname
        {
            get { return GetAttributeValue<string>("fullname"); }
            set { SetAttributeValue("fullname", value); }
        }

        [AttributeLogicalName("domainname")]
        public string domainname
        {
            get { return GetAttributeValue<string>("domainname"); }
            set { SetAttributeValue("domainname", value); }
        }
    }
}
