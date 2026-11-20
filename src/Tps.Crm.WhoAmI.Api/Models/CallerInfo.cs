namespace Tps.Crm.WhoAmI.Api.Models
{
    public sealed class CallerInfo
    {
        public CallerInfo(string name, bool isAuthenticated)
        {
            Name = name;
            IsAuthenticated = isAuthenticated;
        }

        public string Name { get; private set; }

        public bool IsAuthenticated { get; private set; }
    }
}
