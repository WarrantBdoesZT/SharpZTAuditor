using System;
using System.Collections.Generic;
using System.Linq;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Models
{
    /// <summary>
    /// The on-disk shape of reachability-TIMESTAMP.json.
    ///
    /// Shared by the writer and the merge command so the two cannot drift: a merge
    /// that silently failed to read half its input would produce a confident report
    /// about coverage it never had.
    /// </summary>
    public sealed class ReachabilityDocument
    {
        public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>Zone the run was performed from. Informational once merged.</summary>
        public string VantageZone { get; set; } = string.Empty;

        public string VantageHost { get; set; } = string.Empty;

        /// <summary>Every vantage zone represented, populated on merged documents.</summary>
        public List<string> VantageZones { get; set; } = new();

        /// <summary>Files that fed a merged document, in the order supplied.</summary>
        public List<string> SourceFiles { get; set; } = new();

        public ProbeStatisticsSnapshot? Statistics { get; set; }

        public Dictionary<string, int> VerdictSummary { get; set; } = new();

        public List<ReachabilityObservation> Observations { get; set; } = new();

        /// <summary>
        /// Observations that disagreed between source files for the same
        /// (vantage, target, port). Surfaced rather than silently resolved -- a flow
        /// that was open in one run and filtered in another is a real signal, either
        /// of a firewall change or of an unstable control.
        /// </summary>
        public List<MergeConflict> Conflicts { get; set; } = new();

        public IEnumerable<string> DistinctVantageZones =>
            Observations.Select(o => o.VantageZoneId)
                        .Where(z => !string.IsNullOrEmpty(z))
                        .Distinct(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Plain snapshot of probe counters, so the document has no live dependency.</summary>
    public sealed class ProbeStatisticsSnapshot
    {
        public int Planned  { get; set; }
        public int Sent     { get; set; }
        public int Skipped  { get; set; }
        public int Open     { get; set; }
        public int Closed   { get; set; }
        public int Filtered { get; set; }
        public int Unknown  { get; set; }
    }

    public sealed class MergeConflict
    {
        public string Key          { get; set; } = string.Empty;
        public string KeptVerdict  { get; set; } = string.Empty;
        public string OtherVerdict { get; set; } = string.Empty;
        public string KeptFrom     { get; set; } = string.Empty;
        public string Reason       { get; set; } = string.Empty;
    }
}
