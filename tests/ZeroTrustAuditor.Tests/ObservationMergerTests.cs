using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using Xunit;
using ZeroTrustAuditor.Analysis;
using ZeroTrustAuditor.Config;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Network;
using ZeroTrustAuditor.Reports;

namespace ZeroTrustAuditor.Tests
{
    public class ObservationMergerTests : IDisposable
    {
        private readonly string _dir;

        public ObservationMergerTests()
        {
            _dir = Path.Combine(Path.GetTempPath(), "zta-merge-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { }
        }

        private static ReachabilityObservation Obs(
            string vantage, string ip, int port,
            ReachabilityVerdict verdict = ReachabilityVerdict.Open,
            DateTimeOffset? at = null, double confidence = 1.0) => new()
        {
            Host           = ip,
            TargetIp       = ip,
            Port           = port,
            Transport      = "tcp",
            ServiceClassId = "SMB",
            Verdict        = verdict,
            Confidence     = confidence,
            VantageZoneId  = vantage,
            VantageHost    = "aud-" + vantage,
            ObservedAt     = at ?? new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero),
            Evidence       = new ProbeEvidence { Method = "tcp-connect", Response = "syn-ack", Attempts = 1 },
        };

        /// <summary>Writes through the real renderer, so the file format is round-tripped.</summary>
        private string WriteCapture(string name, string vantage, params ReachabilityObservation[] obs)
        {
            var path = Path.Combine(_dir, name);
            new ReachabilityRenderer().Write(obs, null, vantage, path, "aud-" + vantage);
            return path;
        }

        [Fact]
        public void MergeUnionsObservationsFromDifferentVantageZones()
        {
            var a = WriteCapture("a.json", "user-vlan", Obs("user-vlan", "10.30.1.10", 445));
            var b = WriteCapture("b.json", "dmz",       Obs("dmz",       "10.30.1.10", 445));

            var result = ObservationMerger.Merge(new[] { a, b });

            Assert.False(result.HasErrors);
            Assert.Equal(2, result.FilesRead);
            Assert.Equal(2, result.Document.Observations.Count);
            Assert.Equal(new[] { "dmz", "user-vlan" }, result.Document.VantageZones.ToArray());
        }

        [Fact]
        public void SameVantageAndTarget_IsDeduplicated()
        {
            var a = WriteCapture("a.json", "user-vlan", Obs("user-vlan", "10.30.1.10", 445));
            var b = WriteCapture("b.json", "user-vlan", Obs("user-vlan", "10.30.1.10", 445));

            var result = ObservationMerger.Merge(new[] { a, b });

            Assert.Single(result.Document.Observations);
            Assert.Equal(1, result.Deduplicated);
        }

        [Fact]
        public void SameTargetFromDifferentZones_IsNotADuplicate()
        {
            // Reachability is a property of an ordered PAIR. The same host reached
            // from two zones is two distinct facts.
            var a = WriteCapture("a.json", "user-vlan", Obs("user-vlan", "10.30.1.10", 445));
            var b = WriteCapture("b.json", "mgmt",      Obs("mgmt",      "10.30.1.10", 445));

            var result = ObservationMerger.Merge(new[] { a, b });

            Assert.Equal(2, result.Document.Observations.Count);
            Assert.Equal(0, result.Deduplicated);
        }

        [Fact]
        public void MoreRecentMeasurementWins()
        {
            var older = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
            var newer = new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero);

            var a = WriteCapture("a.json", "user-vlan",
                Obs("user-vlan", "10.30.1.10", 445, ReachabilityVerdict.Open, older));
            var b = WriteCapture("b.json", "user-vlan",
                Obs("user-vlan", "10.30.1.10", 445, ReachabilityVerdict.Filtered, newer));

            var result = ObservationMerger.Merge(new[] { a, b });

            Assert.Equal(ReachabilityVerdict.Filtered,
                result.Document.Observations.Single().Verdict);
        }

        [Fact]
        public void DisagreementIsRecordedAsAConflict_NotSilentlyResolved()
        {
            // A path open in one capture and filtered in another means the control
            // changed or is unstable. Hiding that would be the wrong call.
            var older = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
            var newer = new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero);

            var a = WriteCapture("a.json", "user-vlan",
                Obs("user-vlan", "10.30.1.10", 445, ReachabilityVerdict.Open, older));
            var b = WriteCapture("b.json", "user-vlan",
                Obs("user-vlan", "10.30.1.10", 445, ReachabilityVerdict.Filtered, newer));

            var result = ObservationMerger.Merge(new[] { a, b });

            var conflict = Assert.Single(result.Document.Conflicts);
            Assert.Equal("Filtered", conflict.KeptVerdict);
            Assert.Equal("Open",     conflict.OtherVerdict);
            Assert.Contains("recent", conflict.Reason);
        }

        [Fact]
        public void IdenticalVerdictsProduceNoConflict()
        {
            var a = WriteCapture("a.json", "user-vlan", Obs("user-vlan", "10.30.1.10", 445));
            var b = WriteCapture("b.json", "user-vlan", Obs("user-vlan", "10.30.1.10", 445));

            var result = ObservationMerger.Merge(new[] { a, b });

            Assert.Empty(result.Document.Conflicts);
        }

        [Fact]
        public void OnEqualTimestamps_TheMoreDefinitiveVerdictWins()
        {
            var when = new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero);

            // Closed is the host answering; Filtered is inferred from silence.
            var existing  = Obs("z", "10.0.0.1", 445, ReachabilityVerdict.Filtered, when);
            var candidate = Obs("z", "10.0.0.1", 445, ReachabilityVerdict.Closed,   when);

            var (keep, reason) = ObservationMerger.Resolve(existing, candidate);

            Assert.Equal(ReachabilityVerdict.Closed, keep.Verdict);
            Assert.Contains("definitive", reason);
        }

        [Fact]
        public void UnknownNeverBeatsARealVerdict()
        {
            var when = new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero);

            var real    = Obs("z", "10.0.0.1", 445, ReachabilityVerdict.Filtered, when);
            var unknown = Obs("z", "10.0.0.1", 445, ReachabilityVerdict.Unknown,  when);

            var (keep, _) = ObservationMerger.Resolve(real, unknown);
            Assert.Equal(ReachabilityVerdict.Filtered, keep.Verdict);
        }

        [Fact]
        public void MissingFileIsAnErrorNotACrash()
        {
            var good = WriteCapture("a.json", "user-vlan", Obs("user-vlan", "10.30.1.10", 445));

            var result = ObservationMerger.Merge(new[] { good, Path.Combine(_dir, "nope.json") });

            Assert.Contains(result.Errors, e => e.Contains("not found"));
            Assert.Single(result.Document.Observations);   // the good file still merged
        }

        [Fact]
        public void MalformedFileIsReportedAndSkipped()
        {
            var bad = Path.Combine(_dir, "bad.json");
            File.WriteAllText(bad, "{ not json ");

            var good = WriteCapture("a.json", "user-vlan", Obs("user-vlan", "10.30.1.10", 445));

            var result = ObservationMerger.Merge(new[] { bad, good });

            Assert.Contains(result.Errors, e => e.Contains("not a valid reachability file"));
            Assert.Single(result.Document.Observations);
        }

        [Fact]
        public void MergingOneZoneRepeatedly_WarnsThatCoverageDidNotImprove()
        {
            var a = WriteCapture("a.json", "user-vlan", Obs("user-vlan", "10.30.1.10", 445));
            var b = WriteCapture("b.json", "user-vlan", Obs("user-vlan", "10.30.1.11", 445));

            var result = ObservationMerger.Merge(new[] { a, b });

            Assert.Contains(result.Warnings, w => w.Contains("same vantage zone"));
        }

        [Fact]
        public void UnattributedObservationsAreExcluded()
        {
            // A measurement that does not know where it was taken from cannot fill a
            // matrix row, and guessing would fabricate coverage.
            var path = Path.Combine(_dir, "novantage.json");
            File.WriteAllText(path, """
            { "GeneratedAt":"2026-07-01T00:00:00+00:00", "VantageZone":"", "Observations":[
              { "Host":"h","TargetIp":"10.0.0.1","Port":445,"Transport":"tcp",
                "ServiceClassId":"SMB","Verdict":"Open","VantageZoneId":"" } ] }
            """);

            var result = ObservationMerger.Merge(new[] { path });

            Assert.Contains(result.Warnings, w => w.Contains("no vantage zone"));
            Assert.Empty(result.Document.Observations);
        }

        [Fact]
        public void DocumentLevelVantageBackfillsOlderFiles()
        {
            // Captures written before per-observation vantage existed.
            var path = Path.Combine(_dir, "legacy.json");
            File.WriteAllText(path, """
            { "GeneratedAt":"2026-07-01T00:00:00+00:00", "VantageZone":"legacy-zone",
              "Observations":[
              { "Host":"h","TargetIp":"10.0.0.1","Port":445,"Transport":"tcp",
                "ServiceClassId":"SMB","Verdict":"Open" } ] }
            """);

            var result = ObservationMerger.Merge(new[] { path });

            Assert.Equal("legacy-zone", result.Document.Observations.Single().VantageZoneId);
            Assert.Equal(new[] { "legacy-zone" }, result.Document.VantageZones.ToArray());
        }

        [Fact]
        public void VerdictSummaryAndStatisticsAreRecomputed()
        {
            var a = WriteCapture("a.json", "z1",
                Obs("z1", "10.0.0.1", 445, ReachabilityVerdict.Open),
                Obs("z1", "10.0.0.2", 445, ReachabilityVerdict.Filtered));
            var b = WriteCapture("b.json", "z2",
                Obs("z2", "10.0.0.1", 445, ReachabilityVerdict.Closed));

            var result = ObservationMerger.Merge(new[] { a, b });

            Assert.Equal(1, result.Document.VerdictSummary["Open"]);
            Assert.Equal(1, result.Document.VerdictSummary["Filtered"]);
            Assert.Equal(1, result.Document.VerdictSummary["Closed"]);
            Assert.Equal(3, result.Document.Statistics!.Planned);
        }
    }

    /// <summary>End-to-end: merged observations must populate several matrix rows.</summary>
    public class MultiVantageAnalysisTests
    {
        private static ZoneDefinition Zone(string id, int tier, string role, string cidr)
        {
            var z = new ZoneDefinition
            {
                Id = id, Name = id, Tier = tier, Role = role,
                Cidrs = new List<string> { cidr },
            };
            z.Ranges.Add(IpRange.Parse(cidr));
            return z;
        }

        private static SegmentationContext Context()
        {
            var catalog = SegmentationConfigLoader.BuiltInCatalog();
            catalog.Index();

            return new SegmentationContext
            {
                Zones = new ZoneResolver(new[]
                {
                    Zone("user-vlan", TrustTier.User,         ZoneRoles.User,  "10.10.0.0/16"),
                    Zone("dmz",       TrustTier.Perimeter,    ZoneRoles.Dmz,   "192.168.200.0/24"),
                    Zone("tier0",     TrustTier.ControlPlane, ZoneRoles.Tier0, "10.30.1.0/24"),
                }),
                Policy   = new SegmentationPolicy { DefaultAction = "deny" },
                Services = catalog,
            };
        }

        private static ReachabilityObservation Obs(string vantage, string ip) => new()
        {
            Host = ip, TargetIp = ip, Port = 445, Transport = "tcp",
            ServiceClassId = "SMB", Verdict = ReachabilityVerdict.Open,
            Confidence = 1.0, VantageZoneId = vantage,
            Evidence = new ProbeEvidence { Method = "tcp-connect", Response = "syn-ack" },
        };

        [Fact]
        public void MergedObservationsPopulateMultipleMatrixRows()
        {
            var analysis = new PolicyEvaluator(Context()).Analyze(
                new[] { Obs("user-vlan", "10.30.1.10"), Obs("dmz", "10.30.1.10") },
                "merged", vantageIp: null);

            Assert.True(analysis.Matrix.Cell("user-vlan", "tier0")!.Assessed);
            Assert.True(analysis.Matrix.Cell("dmz", "tier0")!.Assessed);
            // A row nobody measured stays unassessed.
            Assert.False(analysis.Matrix.Cell("tier0", "user-vlan")!.Assessed);

            Assert.Equal(2, analysis.VantageZones.Count);
            Assert.Equal("2 zones", analysis.VantageZoneId);
        }

        [Fact]
        public void BlastRadiusCountsEveryZoneProvenToReachTheHost()
        {
            var analysis = new PolicyEvaluator(Context()).Analyze(
                new[] { Obs("user-vlan", "10.30.1.10"), Obs("dmz", "10.30.1.10") },
                "merged", vantageIp: null);

            var dc = analysis.Exposures.Single(e => e.TargetIp == "10.30.1.10");

            Assert.Equal(2, dc.BlastRadius);
            Assert.Contains("user-vlan", dc.ReachableFromZones);
            Assert.Contains("dmz", dc.ReachableFromZones);
        }

        [Fact]
        public void SingleVantageStillReportsASingleZoneId()
        {
            var analysis = new PolicyEvaluator(Context()).Analyze(
                new[] { Obs("user-vlan", "10.30.1.10") }, "single", vantageIp: null);

            Assert.Equal("user-vlan", analysis.VantageZoneId);
            Assert.Single(analysis.VantageZones);
        }
    }
}
