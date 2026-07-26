using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Analysis
{
    public sealed class MergeResult
    {
        public ReachabilityDocument Document { get; init; } = new();
        public List<string> Errors   { get; } = new();
        public List<string> Warnings { get; } = new();

        public int FilesRead     { get; set; }
        public int TotalRead     { get; set; }
        public int Deduplicated  { get; set; }

        public bool HasErrors => Errors.Count > 0;
    }

    /// <summary>
    /// Unions reachability observations captured from several vantage points.
    ///
    /// A single run measures one source zone, so one row of the zone matrix. The
    /// honest way to fill in the rest is to run from a host in each zone and merge
    /// the results -- no agents, no deployed infrastructure, nothing that needs a
    /// change window. This is that merge.
    ///
    /// It deliberately does NOT infer anything about pairs nobody measured. Merging
    /// four runs gives you four rows, not a complete matrix, and the report says so.
    /// </summary>
    public static class ObservationMerger
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling         = JsonCommentHandling.Skip,
            AllowTrailingCommas         = true,
            Converters                  = { new JsonStringEnumConverter() },
        };

        public static MergeResult Merge(IReadOnlyList<string> paths)
        {
            var result = new MergeResult();
            var merged = new Dictionary<string, (ReachabilityObservation Obs, string Source)>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var path in paths)
            {
                var document = ReadDocument(path, result);
                if (document == null) continue;

                result.FilesRead++;
                result.Document.SourceFiles.Add(Path.GetFileName(path));

                var fileVantage = document.VantageZone;

                if (string.IsNullOrWhiteSpace(fileVantage) &&
                    document.Observations.All(o => string.IsNullOrEmpty(o.VantageZoneId)))
                {
                    result.Warnings.Add(
                        $"'{Path.GetFileName(path)}' records no vantage zone. Its observations " +
                        "cannot be attributed to a source segment and are excluded -- an " +
                        "unattributed measurement cannot fill a matrix row.");
                    continue;
                }

                foreach (var observation in document.Observations)
                {
                    result.TotalRead++;

                    // Older files carry the vantage only at document level.
                    if (string.IsNullOrEmpty(observation.VantageZoneId))
                        observation.VantageZoneId = fileVantage;
                    if (string.IsNullOrEmpty(observation.VantageHost))
                        observation.VantageHost = document.VantageHost;

                    var key = Key(observation);

                    if (!merged.TryGetValue(key, out var existing))
                    {
                        merged[key] = (observation, Path.GetFileName(path));
                        continue;
                    }

                    result.Deduplicated++;

                    var (keep, reason) = Resolve(existing.Obs, observation);

                    if (existing.Obs.Verdict != observation.Verdict)
                    {
                        result.Document.Conflicts.Add(new MergeConflict
                        {
                            Key          = key,
                            KeptVerdict  = keep.Verdict.ToString(),
                            OtherVerdict = (ReferenceEquals(keep, observation)
                                                ? existing.Obs : observation).Verdict.ToString(),
                            KeptFrom     = ReferenceEquals(keep, observation)
                                                ? Path.GetFileName(path) : existing.Source,
                            Reason       = reason,
                        });
                    }

                    merged[key] = ReferenceEquals(keep, observation)
                        ? (observation, Path.GetFileName(path))
                        : existing;
                }
            }

            var observations = merged.Values
                .Select(v => v.Obs)
                .OrderBy(o => o.VantageZoneId, StringComparer.OrdinalIgnoreCase)
                .ThenBy(o => o.TargetIp, StringComparer.OrdinalIgnoreCase)
                .ThenBy(o => o.Port)
                .ToList();

            result.Document.Observations = observations;
            result.Document.VantageZones = observations
                .Select(o => o.VantageZoneId)
                .Where(z => !string.IsNullOrEmpty(z))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(z => z, StringComparer.OrdinalIgnoreCase)
                .ToList();

            result.Document.VantageZone = result.Document.VantageZones.Count == 1
                ? result.Document.VantageZones[0]
                : $"merged ({result.Document.VantageZones.Count} zones)";

            result.Document.VerdictSummary = observations
                .GroupBy(o => o.Verdict.ToString())
                .ToDictionary(g => g.Key, g => g.Count());

            result.Document.Statistics = new ProbeStatisticsSnapshot
            {
                Planned  = observations.Count,
                Sent     = observations.Count(o => o.Evidence.Attempts > 0),
                Skipped  = observations.Count(o => o.Evidence.Method == "not-probed"),
                Open     = observations.Count(o => o.Verdict == ReachabilityVerdict.Open),
                Closed   = observations.Count(o => o.Verdict == ReachabilityVerdict.Closed),
                Filtered = observations.Count(o => o.Verdict == ReachabilityVerdict.Filtered),
                Unknown  = observations.Count(o => o.Verdict == ReachabilityVerdict.Unknown),
            };

            if (result.FilesRead == 0)
                result.Errors.Add("No readable reachability files were supplied.");

            if (result.Document.VantageZones.Count == 1 && result.FilesRead > 1)
                result.Warnings.Add(
                    $"All {result.FilesRead} files were captured from the same vantage zone " +
                    $"('{result.Document.VantageZones[0]}'). Merging them adds depth but no " +
                    "additional matrix coverage -- run from a host in each source zone.");

            return result;
        }

        /// <summary>Identity of a measurement: source zone, target, transport, port.</summary>
        internal static string Key(ReachabilityObservation o) =>
            $"{o.VantageZoneId}|{o.TargetIp}|{o.Transport}|{o.Port}";

        /// <summary>
        /// Picks between two measurements of the same path.
        ///
        /// Recency wins, because the network's current state is what matters. Where
        /// timestamps tie, the more definitive answer wins: Open and Closed are the
        /// host speaking for itself, while Filtered is inferred from silence and
        /// Unknown is nothing at all.
        ///
        /// Disagreements are never averaged or hidden -- they are recorded as
        /// conflicts, because a path that was open in one run and filtered in another
        /// is telling you something.
        /// </summary>
        internal static (ReachabilityObservation Keep, string Reason) Resolve(
            ReachabilityObservation existing, ReachabilityObservation candidate)
        {
            if (candidate.ObservedAt > existing.ObservedAt)
                return (candidate, "kept the more recent measurement");

            if (existing.ObservedAt > candidate.ObservedAt)
                return (existing, "kept the more recent measurement");

            var existingRank  = Definitiveness(existing.Verdict);
            var candidateRank = Definitiveness(candidate.Verdict);

            if (candidateRank > existingRank)
                return (candidate, "same timestamp; kept the more definitive verdict");
            if (existingRank > candidateRank)
                return (existing, "same timestamp; kept the more definitive verdict");

            return candidate.Confidence > existing.Confidence
                ? (candidate, "same timestamp and verdict class; kept the higher confidence")
                : (existing, "same timestamp and verdict class; kept the first seen");
        }

        /// <summary>Open and Closed are answers from the host; Filtered is an inference.</summary>
        private static int Definitiveness(ReachabilityVerdict verdict) => verdict switch
        {
            ReachabilityVerdict.Open     => 3,
            ReachabilityVerdict.Closed   => 3,
            ReachabilityVerdict.Filtered => 2,
            _                            => 0,
        };

        private static ReachabilityDocument? ReadDocument(string path, MergeResult result)
        {
            if (!File.Exists(path))
            {
                result.Errors.Add($"File not found: {path}");
                return null;
            }

            try
            {
                var document = JsonSerializer.Deserialize<ReachabilityDocument>(
                    File.ReadAllText(path), JsonOpts);

                if (document == null)
                {
                    result.Errors.Add($"'{path}' deserialized to nothing.");
                    return null;
                }

                if (document.Observations.Count == 0)
                    result.Warnings.Add($"'{Path.GetFileName(path)}' contains no observations.");

                return document;
            }
            catch (JsonException ex)
            {
                result.Errors.Add($"'{path}' is not a valid reachability file: {ex.Message}");
                return null;
            }
        }
    }
}
