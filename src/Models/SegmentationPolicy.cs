using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace ZeroTrustAuditor.Models
{
    public enum PolicyAction { Deny = 0, Allow = 1 }

    /// <summary>
    /// A declared, owned exception to default-deny.
    ///
    /// Rules carry owner / reviewedOn / expiresOn so the policy file doubles as the
    /// auditable record of approved cross-zone flows -- which is the artifact an
    /// assessor asks for when you claim a path is intentional.
    /// </summary>
    public sealed class PolicyRule
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("from")]
        [JsonConverter(typeof(StringOrArrayConverter))]
        public List<string> From { get; set; } = new();

        [JsonPropertyName("to")]
        [JsonConverter(typeof(StringOrArrayConverter))]
        public List<string> To { get; set; } = new();

        [JsonPropertyName("services")]
        [JsonConverter(typeof(StringOrArrayConverter))]
        public List<string> Services { get; set; } = new();

        [JsonPropertyName("action")]
        public string Action { get; set; } = "allow";

        [JsonPropertyName("justification")]
        public string Justification { get; set; } = string.Empty;

        [JsonPropertyName("owner")]
        public string Owner { get; set; } = string.Empty;

        [JsonPropertyName("reviewedOn")]
        public string ReviewedOn { get; set; } = string.Empty;

        [JsonPropertyName("expiresOn")]
        public string ExpiresOn { get; set; } = string.Empty;

        [JsonIgnore]
        public PolicyAction ResolvedAction =>
            Action.Equals("allow", StringComparison.OrdinalIgnoreCase)
                ? PolicyAction.Allow
                : PolicyAction.Deny;

        /// <summary>Specificity, used to break ties: an exact rule beats a wildcard one.</summary>
        [JsonIgnore]
        public int Specificity =>
            (From.Contains("*")     ? 0 : 1) +
            (To.Contains("*")       ? 0 : 1) +
            (Services.Contains("*") ? 0 : 1);

        public bool IsExpiredAsOf(DateTimeOffset when)
        {
            if (string.IsNullOrWhiteSpace(ExpiresOn)) return false;
            return DateTimeOffset.TryParse(ExpiresOn, out var expiry) && expiry < when;
        }

        public bool Matches(string fromZone, string toZone, string serviceClass) =>
            ListMatches(From, fromZone) &&
            ListMatches(To, toZone) &&
            ListMatches(Services, serviceClass);

        private static bool ListMatches(List<string> list, string value)
        {
            if (list.Count == 0) return false;
            foreach (var item in list)
            {
                if (item == "*") return true;
                if (item.Equals(value, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    /// <summary>Outcome of evaluating one (from, to, service) tuple against the policy.</summary>
    public sealed class PolicyDecision
    {
        public PolicyAction Action     { get; init; }
        public PolicyRule?  MatchedRule { get; init; }
        public bool         IsExpired  { get; init; }
        public string       Reason     { get; init; } = string.Empty;

        [JsonIgnore]
        public bool HasExplicitRule => MatchedRule != null;
    }

    /// <summary>Root of policy.json. Default-deny with explicit, owned allows.</summary>
    public sealed class SegmentationPolicy
    {
        [JsonPropertyName("defaultAction")]
        public string DefaultAction { get; set; } = "deny";

        [JsonPropertyName("rules")]
        public List<PolicyRule> Rules { get; set; } = new();

        [JsonIgnore]
        public PolicyAction ResolvedDefaultAction =>
            DefaultAction.Equals("allow", StringComparison.OrdinalIgnoreCase)
                ? PolicyAction.Allow
                : PolicyAction.Deny;

        [JsonIgnore]
        public bool IsEmpty => Rules.Count == 0;

        /// <summary>
        /// Evaluates a flow. The most specific matching rule wins; among equally
        /// specific matches, deny beats allow, because a policy file that both
        /// permits and forbids a flow should fail closed.
        ///
        /// An expired allow rule does NOT authorise the flow -- it is reported as an
        /// expired exception so stale approvals surface instead of lingering forever.
        /// </summary>
        public PolicyDecision Evaluate(
            string fromZone, string toZone, string serviceClass, DateTimeOffset asOf)
        {
            var matches = Rules
                .Where(r => r.Matches(fromZone, toZone, serviceClass))
                .OrderByDescending(r => r.Specificity)
                .ThenBy(r => r.ResolvedAction == PolicyAction.Deny ? 0 : 1)
                .ToList();

            if (matches.Count == 0)
            {
                return new PolicyDecision
                {
                    Action = ResolvedDefaultAction,
                    Reason = $"No rule covers {fromZone} -> {toZone} for {serviceClass}; " +
                             $"default action is {DefaultAction}.",
                };
            }

            var rule    = matches[0];
            var expired = rule.IsExpiredAsOf(asOf);

            if (rule.ResolvedAction == PolicyAction.Allow && expired)
            {
                return new PolicyDecision
                {
                    Action      = PolicyAction.Deny,
                    MatchedRule = rule,
                    IsExpired   = true,
                    Reason      = $"Rule '{RuleLabel(rule)}' permitted this flow but expired on " +
                                  $"{rule.ExpiresOn}. Expired exceptions do not authorise traffic.",
                };
            }

            return new PolicyDecision
            {
                Action      = rule.ResolvedAction,
                MatchedRule = rule,
                IsExpired   = expired,
                Reason      = $"Rule '{RuleLabel(rule)}' {rule.Action}s {fromZone} -> {toZone} " +
                              $"for {serviceClass}." +
                              (rule.Justification.Length > 0 ? $" ({rule.Justification})" : ""),
            };
        }

        internal static string RuleLabel(PolicyRule rule) =>
            rule.Id.Length > 0
                ? rule.Id
                : $"{string.Join(",", rule.From)} -> {string.Join(",", rule.To)}";
    }
}
