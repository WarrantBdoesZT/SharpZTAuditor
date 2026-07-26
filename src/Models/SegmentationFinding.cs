using System;
using System.Collections.Generic;

namespace ZeroTrustAuditor.Models
{
    /// <summary>
    /// What a probe established about one (vantage, target, port) path.
    ///
    /// The Closed/Filtered split is the whole point. A TCP connect has three
    /// meaningful outcomes and the old bool collapsed all of them:
    ///   SYN/ACK -> Open      the path is open and something is listening
    ///   RST     -> Closed    the host answered; nothing is FILTERING between us
    ///   timeout -> Filtered  the packet was dropped; a control is enforcing
    ///
    /// Without that distinction the tool cannot tell a working firewall from a
    /// powered-off host, which is precisely the question it exists to answer.
    /// </summary>
    public enum ReachabilityVerdict
    {
        /// <summary>Could not be determined. Never a violation and never a pass.</summary>
        Unknown  = 0,
        /// <summary>Connection refused: reachable, but no listener. Nothing is blocking.</summary>
        Closed   = 1,
        /// <summary>Dropped or administratively prohibited. Segmentation is enforcing.</summary>
        Filtered = 2,
        /// <summary>Connection established.</summary>
        Open     = 3
    }

    /// <summary>How an observation compares with declared policy.</summary>
    public enum PolicyStatus
    {
        /// <summary>No policy covers this flow.</summary>
        NoPolicyDefined = 0,
        /// <summary>Reachable and permitted. Proves the approved path works.</summary>
        Compliant       = 1,
        /// <summary>Blocked and meant to be blocked. Evidence the control works.</summary>
        Enforced        = 2,
        /// <summary>
        /// Nothing listening, but nothing blocking either. One service install away
        /// from a violation -- the difference between being safe and being lucky.
        /// </summary>
        Unenforced      = 3,
        /// <summary>An approved flow is broken. Will become an outage ticket.</summary>
        Drift           = 4,
        /// <summary>Reachable and NOT permitted. The headline finding.</summary>
        Violation       = 5
    }

    /// <summary>Raw probe result, kept so a finding can be independently re-checked.</summary>
    public sealed class ProbeEvidence
    {
        /// <summary>"tcp-connect", "udp-probe", "passive", ...</summary>
        public string Method { get; init; } = string.Empty;

        /// <summary>"syn-ack", "rst", "timeout", "icmp-admin-prohibited", "not-probed".</summary>
        public string Response { get; init; } = string.Empty;

        public int  RttMs    { get; init; }
        public int  Attempts { get; init; }

        public string? Banner              { get; init; }
        public string? TlsSubject          { get; init; }
        public string? ServiceConfirmation { get; init; }

        public override string ToString()
        {
            var parts = new List<string>
            {
                $"method={Method}",
                $"response={Response}",
                $"rttMs={RttMs}",
                $"attempts={Attempts}",
            };
            if (!string.IsNullOrEmpty(ServiceConfirmation)) parts.Add($"confirmed={ServiceConfirmation}");
            if (!string.IsNullOrEmpty(TlsSubject))          parts.Add($"tlsSubject={TlsSubject}");
            if (!string.IsNullOrEmpty(Banner))              parts.Add($"banner={Banner}");
            return string.Join("; ", parts);
        }
    }

    /// <summary>A reference to authoritative guidance, attached to a finding.</summary>
    public sealed class GuidanceRef
    {
        public string Source    { get; init; } = string.Empty;   // "NSA", "CISA", "MITRE"
        public string Document  { get; init; } = string.Empty;
        public string Section   { get; init; } = string.Empty;
        public string Url       { get; init; } = string.Empty;

        public override string ToString() =>
            Section.Length > 0 ? $"{Source} {Document} -- {Section}" : $"{Source} {Document}";
    }

    /// <summary>
    /// A segmentation observation, keyed on a PATH rather than a host.
    ///
    /// This is the central modelling change of the rearchitecture. A segmentation
    /// flaw is a property of an ordered (source zone -> destination endpoint : port)
    /// triple; the legacy Finding type has no field for the source at all, so it
    /// could only ever describe reachability as though it were a property of the
    /// target.
    /// </summary>
    public sealed class SegmentationFinding
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];

        // ── The path ──────────────────────────────────────────────────────────
        public string  VantageHost   { get; set; } = string.Empty;
        public string  VantageIp     { get; set; } = string.Empty;
        public string  VantageZoneId { get; set; } = string.Empty;

        public string  TargetIp       { get; set; } = string.Empty;
        public string? TargetHostname { get; set; }
        public string  TargetZoneId   { get; set; } = string.Empty;
        public string? TargetRole     { get; set; }

        public int    Port         { get; set; }
        public string Transport    { get; set; } = "tcp";
        public string ServiceClass { get; set; } = string.Empty;

        // ── What was observed ─────────────────────────────────────────────────
        public ReachabilityVerdict Verdict  { get; set; } = ReachabilityVerdict.Unknown;
        public ProbeEvidence       Evidence { get; set; } = new();

        /// <summary>0..1. Degraded by retries, absent service confirmation, or inference.</summary>
        public double Confidence { get; set; } = 1.0;

        // ── What it means ─────────────────────────────────────────────────────
        public PolicyStatus Policy        { get; set; } = PolicyStatus.NoPolicyDefined;
        public string?      MatchedRuleId { get; set; }
        public string       PolicyReason  { get; set; } = string.Empty;

        public Severity Severity  { get; set; } = Severity.Informational;
        public double   RiskScore { get; set; }

        /// <summary>
        /// Host-level configuration facts that make this specific reachable path
        /// worse -- unsigned SMB on a reachable 445, no LAPS on a reachable RDP,
        /// and so on.
        ///
        /// This is the correlation the original tool advertised but could never
        /// perform: it grouped by a host key that host-scoped and domain-scoped
        /// checks never shared. Keying on the endpoint makes it work, and makes it
        /// mean something -- reachability plus a weakness on the thing you can
        /// reach is a different finding from either alone.
        /// </summary>
        public List<string> EnrichmentNotes { get; set; } = new();

        /// <summary>Legacy finding IDs that contributed to <see cref="EnrichmentNotes"/>.</summary>
        public List<string> RelatedFindingIds { get; set; } = new();

        // ── How to fix it ─────────────────────────────────────────────────────
        public List<GuidanceRef> Guidance    { get; set; } = new();
        public string            Remediation { get; set; } = string.Empty;
        public string            Description { get; set; } = string.Empty;

        public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset LastSeen  { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Identity of the observation, for deduplication and run-over-run diffing.
        /// Deliberately includes the vantage zone: the same target reachable from two
        /// different source zones is two distinct facts, not a duplicate.
        /// </summary>
        public string IdentityKey =>
            $"{VantageZoneId}|{TargetIp}|{Transport}|{Port}";

        public override string ToString() =>
            $"{VantageZoneId} -> {TargetIp}:{Port}/{Transport} " +
            $"({ServiceClass}) {Verdict}/{Policy}";
    }
}
