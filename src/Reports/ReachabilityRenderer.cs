using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Reports
{
    /// <summary>
    /// Persists raw tri-state reachability observations.
    ///
    /// Findings only cover what is wrong. This file records every probe outcome
    /// including Filtered, which is the evidence that a boundary control WORKS.
    /// It is also the input the Phase 3 zone matrix and run-over-run diffing read.
    /// </summary>
    public class ReachabilityRenderer
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            Converters    = { new JsonStringEnumConverter() },
        };

        public void Write(
            IReadOnlyList<ReachabilityObservation> observations,
            ProbeStatistics? statistics,
            string vantageZoneId,
            string path)
        {
            var byVerdict = observations
                .GroupBy(o => o.Verdict)
                .ToDictionary(g => g.Key.ToString(), g => g.Count());

            var document = new
            {
                GeneratedAt = DateTimeOffset.UtcNow,
                // Recorded explicitly: an observation is only meaningful relative to
                // where it was made from. Zone pairs not measured from this vantage
                // are UNKNOWN, never "clean".
                VantageZone = vantageZoneId,
                Statistics = statistics == null ? null : new
                {
                    statistics.Planned,
                    statistics.Sent,
                    statistics.Skipped,
                    statistics.Open,
                    statistics.Closed,
                    statistics.Filtered,
                    statistics.Unknown,
                },
                VerdictSummary = byVerdict,
                Observations   = observations,
            };

            File.WriteAllText(
                path, JsonSerializer.Serialize(document, JsonOpts), ReportRenderer.Utf8NoBom);

            Console.WriteLine($"[+] Reachability: {path} ({observations.Count} observation(s))");
        }
    }
}
