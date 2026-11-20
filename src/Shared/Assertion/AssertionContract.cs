using System;

namespace Tps.Crm.Assertion
{
    /// <summary>Constants of the org-assertion contract (compact JWS, RS256).</summary>
    public static class AssertionContract
    {
        public const string HeaderName = "X-Tps-Org-Assertion";
        public const string Algorithm = "RS256";
        public const string TokenType = "tps-org+jwt";
        public const string Issuer = "tps-crm-workflow";
        public const string Audience = "tps-crm-whoami-api";
        public const int MaxLifetimeSeconds = 300;
        public const int MaxSkewSeconds = 60;
        public const int MaxTokenLength = 4096;
        public const int MinRsaKeySize = 2048;
    }

    /// <summary>Stable, non-leaking rejection codes.</summary>
    public enum AssertionReason
    {
        None = 0,
        Malformed,
        UnsupportedAlgorithm,
        InvalidHeader,
        UnknownKey,
        BadSignature,
        InvalidClaims,
        UnknownClaim,
        UrlClaim,
        InvalidIssuer,
        InvalidAudience,
        Expired,
        NotYetValid,
        Replayed,
        VerifierUnavailable
    }

    /// <summary>Claim set carried by the assertion.</summary>
    public sealed class AssertionClaims
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string Org { get; set; }
        public string Mach { get; set; }
        public long IssuedAt { get; set; }
        public long NotBefore { get; set; }
        public long Expires { get; set; }
        public string Jti { get; set; }
    }

    public sealed class AssertionResult
    {
        private AssertionResult(AssertionReason reason, AssertionClaims claims)
        {
            Reason = reason;
            Claims = claims;
        }

        public bool Success { get { return Reason == AssertionReason.None; } }
        public AssertionReason Reason { get; private set; }

        /// <summary>Non-null only when Success.</summary>
        public AssertionClaims Claims { get; private set; }

        internal static AssertionResult Ok(AssertionClaims claims) { return new AssertionResult(AssertionReason.None, claims); }
        internal static AssertionResult Fail(AssertionReason reason) { return new AssertionResult(reason, null); }
    }
}
