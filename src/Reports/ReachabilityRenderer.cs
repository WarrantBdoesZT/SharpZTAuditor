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
    /// It is also the input to the merge command and to run-over-run comparison.
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
            string path,
            string vantageHost = "")
        {
            var document = Build(observations, statistics, vantageZoneId, vantageHost);
            Write(document, path);
        }

        /// <summary>Writes an already-assembled document, as produced by the merge command.</summary>
        public void Write(ReachabilityDocument document, string path)
        {
            File.WriteAllText(
                path, JsonSerializer.Serialize(document, JsonOpts), ReportRenderer.Utf8NoBom);

            Console.WriteLine(
                $"[+] Reachability: {path} ({document.Observations.Count} observation(s))");
        }

        internal static ReachabilityDocument Build(
            IReadOnlyList<ReachabilityObservation> observations,
            ProbeStatistics? statistics,
            string vantageZoneId,
            string vantageHost)
        {
            return new ReachabilityDocument
            {
                GeneratedAt = DateTimeOffset.UtcNow,

                // Recorded explicitly: an observation is only meaningful relative to
                // where it was made from. Zone pairs not measured from this vantage
                // are UNKNOWN, never "clean".
                VantageZone  = vantageZoneId,
                VantageHost  = vantageHost,
                VantageZones = observations
                    .Select(o => o.VantageZoneId)
                    .Where(z => !string.IsNullOrEmpty(z))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .DefaultIfEmpty(vantageZoneId)
                    .Where(z => !string.IsNullOrEmpty(z))
                    .OrderBy(z => z, StringComparer.OrdinalIgnoreCase)
                    .ToList(),

                Statistics = statistics == null ? null : new ProbeStatisticsSnapshot
                {
                    Planned  = statistics.Planned,
                    Sent     = statistics.Sent,
                    Skipped  = statistics.Skipped,
                    Open     = statistics.Open,
                    Closed   = statistics.Closed,
                    Filtered = statistics.Filtered,
                    Unknown  = statistics.Unknown,
                },

                VerdictSummary = observations
                    .GroupBy(o => o.Verdict.ToString())
                    .ToDictionary(g => g.Key, g => g.Count()),

                Observations = observations.ToList(),
            };
        }
    }
}
