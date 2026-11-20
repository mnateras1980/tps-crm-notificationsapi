using System;
using System.Activities;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Query;
using Microsoft.Xrm.Sdk.Workflow;

namespace Tps.Crm.WhoAmI.Activity
{
    /// <summary>
    /// Outputs a signed org assertion. Org and machine come ONLY from the execution context and the host;
    /// the activity deliberately has no input arguments.
    /// </summary>
    public sealed class OrgAssertionActivity : CodeActivity
    {
        internal const string ThumbprintSetupName = "OrgAssertionCertThumbprint";

        [Output("Org Assertion")]
        public OutArgument<string> OrgAssertion { get; set; }

        protected override void Execute(CodeActivityContext executionContext)
        {
            try
            {
                var workflowContext = executionContext.GetExtension<IWorkflowContext>();
                var factory = executionContext.GetExtension<IOrganizationServiceFactory>();
                if (workflowContext == null || factory == null) throw new InvalidOperationException();

                string thumbprint = ReadThumbprint(factory, workflowContext.UserId);
                var issuer = new OrgAssertionIssuer(new LocalMachineCertificateSource());
                string token = issuer.Issue(workflowContext.OrganizationName, Environment.MachineName, thumbprint);
                OrgAssertion.Set(executionContext, token);
            }
            catch (Exception)
            {
                throw new InvalidPluginExecutionException(OrgAssertionIssuer.FailureMessage);
            }
        }

        private static string ReadThumbprint(IOrganizationServiceFactory factory, Guid userId)
        {
            IOrganizationService service = factory.CreateOrganizationService(userId);
            if (service == null) throw new InvalidOperationException();

            var query = new QueryExpression("mm360_setup") { ColumnSet = new ColumnSet("mm360_value"), TopCount = 2, NoLock = true };
            query.Criteria.AddCondition("mm360_name", ConditionOperator.Equal, ThumbprintSetupName);
            query.Criteria.AddCondition("statecode", ConditionOperator.Equal, 0);

            EntityCollection result = service.RetrieveMultiple(query);
            // Zero or ambiguous rows deny.
            if (result == null || result.Entities.Count != 1) throw new InvalidOperationException();

            string value = result.Entities[0].GetAttributeValue<string>("mm360_value");
            if (string.IsNullOrWhiteSpace(value)) throw new InvalidOperationException();
            return value;
        }
    }
}
