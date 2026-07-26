using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ZeroTrustAuditor.Models
{
    /// <summary>
    /// Ordered ASCENDING by seriousness, with explicit values.
    ///
    /// This ordering is load-bearing: deduplication and report sorting compare
    /// Severity directly, so `OrderByDescending(f =&gt; f.Severity)` must yield the
    /// MOST severe finding first. The previous declaration ran the other way
    /// (Critical = 0 ... Informational = 4), which silently made deduplication
    /// keep the LEAST severe member of every group.
    ///
    /// Values are pinned so that reordering the members cannot reintroduce the bug.
    /// </summary>
    public enum Severity
    {
        Informational = 0,
        Low           = 1,
        Medium        = 2,
        High          = 3,
        Critical      = 4
    }

    public class Finding
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
        public string Host { get; set; } = string.Empty;
        public string Module { get; set; } = string.Empty;
        public string CheckName { get; set; } = string.Empty;
        public Severity Severity { get; set; }

        /// <summary>
        /// The specific entity this finding is about -- an account, principal, share,
        /// firewall profile, or protocol.
        ///
        /// Domain-wide checks (all of AdAuditor, SYSVOL, local-admin overlap) stamp
        /// Host with the DOMAIN name, so Host+CheckName is not a unique key. Without
        /// Subject in the dedup key, every Kerberoastable account in the domain
        /// collapses into one finding, as do all three firewall profiles on a host
        /// and every cross-segment protocol on a target.
        /// </summary>
        public string Subject { get; set; } = string.Empty;

        /// <summary>
        /// Hosts this finding affects beyond <see cref="Host"/>.
        ///
        /// Correlation matches findings that share a host. A domain-scoped finding
        /// such as LOCAL_ADMIN_OVERLAP is anchored on the domain but actually touches
        /// many hosts; without this list it can never correlate with host-scoped
        /// findings like SMB_SIGNING_DISABLED, which is why four of the six shipped
        /// correlation rules were impossible to trigger.
        /// </summary>
        public List<string> AffectedHosts { get; set; } = new();
        public string Description { get; set; } = string.Empty;
        public string Evidence { get; set; } = string.Empty;
        public string RemediationGuidance { get; set; } = string.Empty;
        public Dictionary<string, string> Tags { get; set; } = new();
        public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;
        public List<string> RelatedFindingIds { get; set; } = new();
        public double RiskScore { get; set; }
    }

    public class AuditReport
    {
        public string ReportId { get; set; } = Guid.NewGuid().ToString();
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
        public string[] TargetHosts { get; set; } = Array.Empty<string>();
        public string Domain { get; set; } = string.Empty;
        public List<Finding> Findings { get; set; } = new();
        public Dictionary<Severity, int> SeveritySummary { get; set; } = new();
        public string AuditorVersion { get; set; } = "2.0.0";
    }
}
