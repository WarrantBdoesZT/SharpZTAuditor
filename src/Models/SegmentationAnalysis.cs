using System;
using System.Collections.Generic;
using System.Linq;

namespace ZeroTrustAuditor.Models
{
    /// <summary>One high-risk service found reachable (or not) on an endpoint.</summary>
    public sealed class ExposedService
    {
        public string   ServiceClassId { get; init; } = string.Empty;
        public int      Port           { get; init; }
        public string   Transport      { get; init; } = "tcp";
        public ReachabilityVerdict Verdict { get; init; }
        public PolicyStatus        Policy  { get; init; }
        public Severity Severity       { get; init; }
        public string?  Banner         { get; init; }
        public string?  Confirmation   { get; init; }

        public bool IsHighRisk =>
            Verdict == ReachabilityVerdict.Open &&
            Policy  == PolicyStatus.Violation;
    }

    /// <summary>
    /// One endpoint and everything reachable on it.
    ///
    /// This is the register the assessment exists to produce: which servers and
    /// endpoints allow high-risk ports, from where, and how badly.
    /// </summary>
    public sealed class EndpointExposure
    {
        public string  TargetIp   { get; init; } = string.Empty;
        public string? Hostname   { get; init; }
        public string  ZoneId     { get; init; } = string.Empty;
        public string  ZoneName   { get; init; } = string.Empty;
        public string  ZoneRole   { get; init; } = string.Empty;
        public int     ZoneTier   { get; init; }

        public List<ExposedService> Services { get; init; } = new();

        /// <summary>Source zones this endpoint was proven reachable from.</summary>
        public List<string> ReachableFromZones { get; init; } = new();

        public Severity WorstSeverity =>
            Services.Count == 0 ? Severity.Informational : Services.Max(s => s.Severity);

        /// <summary>How many distinct source zones can reach it -- the blast radius.</summary>
        public int BlastRadius => ReachableFromZones.Count;

        public IEnumerable<ExposedService> OpenHighRiskServices =>
            Services.Where(s => s.IsHighRisk);

        public string OpenServiceSummary =>
            string.Join(", ", Services
                .Where(s => s.Verdict == ReachabilityVerdict.Open)
                .OrderByDescending(s => s.Severity)
                .Select(s => $"{s.ServiceClassId}({s.Port})"));
    }

    /// <summary>One cell of the zone-to-zone reachability matrix.</summary>
    public sealed class ZoneMatrixCell
    {
        public string FromZoneId { get; init; } = string.Empty;
        public string ToZoneId   { get; init; } = string.Empty;

        /// <summary>
        /// False when no probe was made from this source zone. Rendered distinctly:
        /// an unmeasured pair is NOT a clean one, and conflating the two is the error
        /// that gets people breached.
        /// </summary>
        public bool Assessed { get; set; }

        public int OpenCount     { get; set; }
        public int ClosedCount   { get; set; }
        public int FilteredCount { get; set; }
        public int UnknownCount  { get; set; }

        public int ViolationCount { get; set; }
        public int UnenforcedCount { get; set; }

        public Severity WorstSeverity { get; set; } = Severity.Informational;

        public SortedSet<string> CrossingServices { get; } =
            new(StringComparer.OrdinalIgnoreCase);

        public int TotalProbes => OpenCount + ClosedCount + FilteredCount + UnknownCount;

        /// <summary>True when every denied path was actually blocked.</summary>
        public bool FullyEnforced =>
            Assessed && ViolationCount == 0 && UnenforcedCount == 0 && FilteredCount > 0;
    }

    public sealed class ZoneMatrix
    {
        public List<ZoneDefinition> Zones { get; init; } = new();
        public List<ZoneMatrixCell> Cells { get; init; } = new();

        public ZoneMatrixCell? Cell(string from, string to) =>
            Cells.FirstOrDefault(c =>
                c.FromZoneId.Equals(from, StringComparison.OrdinalIgnoreCase) &&
                c.ToZoneId.Equals(to, StringComparison.OrdinalIgnoreCase));

        public int AssessedPairs   => Cells.Count(c => c.Assessed);
        public int TotalPairs      => Cells.Count;
        public int ViolatingPairs  => Cells.Count(c => c.ViolationCount > 0);
        public int EnforcedPairs   => Cells.Count(c => c.FullyEnforced);
    }

    /// <summary>CISA Zero Trust Maturity Model stages.</summary>
    public enum ZtmmStage { Traditional = 0, Initial = 1, Advanced = 2, Optimal = 3 }

    public sealed class ZtmmFunctionScore
    {
        public string    Function  { get; init; } = string.Empty;
        public ZtmmStage Stage     { get; init; }
        public string    Evidence  { get; init; } = string.Empty;
        public string    NextStep  { get; init; } = string.Empty;

        /// <summary>False when the assessment gathered no data bearing on this function.</summary>
        public bool Assessed { get; init; } = true;
    }

    public sealed class ZtmmScorecard
    {
        public List<ZtmmFunctionScore> Functions { get; init; } = new();
        public string Caveat { get; init; } = string.Empty;
    }

    /// <summary>Everything the segmentation report renders.</summary>
    public sealed class SegmentationAnalysis
    {
        public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

        public string VantageHost   { get; init; } = string.Empty;
        public string VantageIp     { get; init; } = string.Empty;

        /// <summary>Single zone id, or "N zones" when the input was merged.</summary>
        public string VantageZoneId { get; init; } = string.Empty;

        /// <summary>
        /// Every source zone represented. More than one means merged input, and the
        /// coverage statement in the report changes accordingly.
        /// </summary>
        public List<string> VantageZones { get; init; } = new();

        public List<SegmentationFinding> Findings  { get; init; } = new();
        public List<EndpointExposure>    Exposures { get; init; } = new();
        public ZoneMatrix                Matrix    { get; init; } = new();

        /// <summary>Settable: scoring reads the assembled analysis, so it is filled in last.</summary>
        public ZtmmScorecard             Scorecard { get; set; } = new();

        public List<GuidanceRef> ProgramGuidance { get; init; } = new();

        public IEnumerable<SegmentationFinding> Violations =>
            Findings.Where(f => f.Policy == PolicyStatus.Violation)
                    .OrderByDescending(f => f.Severity)
                    .ThenByDescending(f => f.RiskScore);

        public IEnumerable<SegmentationFinding> Unenforced =>
            Findings.Where(f => f.Policy == PolicyStatus.Unenforced);

        public IEnumerable<SegmentationFinding> EnforcementEvidence =>
            Findings.Where(f => f.Policy == PolicyStatus.Enforced);

        public IEnumerable<SegmentationFinding> Drift =>
            Findings.Where(f => f.Policy == PolicyStatus.Drift);

        public int UnmappedEndpointCount =>
            Exposures.Count(e => e.ZoneId.Equals("unknown", StringComparison.OrdinalIgnoreCase));
    }
}
