using System.Collections.Generic;
using System.Linq;
using Xunit;
using ZeroTrustAuditor.Analysis;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Tests
{
    /// <summary>
    /// The correlation the original tool advertised but could never perform. It
    /// grouped by a host key that host-scoped and domain-scoped checks never
    /// shared, so four of six shipped rules were impossible to trigger and the two
    /// that fired were vacuous. Keying on the reachable endpoint makes it work.
    /// </summary>
    public class EnrichmentCorrelatorTests
    {
        private static SegmentationFinding Reachable(
            string host, string ip, string serviceClass, int port,
            Severity severity = Severity.Medium,
            ReachabilityVerdict verdict = ReachabilityVerdict.Open) => new()
        {
            VantageZoneId  = "user-vlan",
            TargetHostname = host,
            TargetIp       = ip,
            TargetZoneId   = "server-tier1",
            ServiceClass   = serviceClass,
            Port           = port,
            Verdict        = verdict,
            Policy         = PolicyStatus.Violation,
            Severity       = severity,
            RiskScore      = 5.0,
            Description    = "reachable.",
        };

        private static Finding Legacy(
            string host, string checkName, params string[] affectedHosts) => new()
        {
            Host          = host,
            CheckName     = checkName,
            Severity      = Severity.High,
            AffectedHosts = affectedHosts.ToList(),
        };

        private static SegmentationAnalysis Analysis(params SegmentationFinding[] findings) =>
            new() { Findings = findings.ToList() };

        [Fact]
        public void UnsignedSmbOnAReachableHost_EscalatesThePath()
        {
            var analysis = Analysis(Reachable("SRV01", "10.20.0.5", "SMB", 445));
            var legacy   = new[] { Legacy("SRV01", "SMB_SIGNING_DISABLED") };

            var enriched = EnrichmentCorrelator.Apply(analysis, legacy);

            Assert.Equal(1, enriched);
            var finding = analysis.Findings.Single();
            Assert.Equal(Severity.High, finding.Severity);       // Medium -> High
            Assert.Single(finding.EnrichmentNotes);
            Assert.Contains("relay", finding.EnrichmentNotes[0]);
            Assert.Contains(legacy[0].Id, finding.RelatedFindingIds);
        }

        [Fact]
        public void WeaknessOnADifferentHost_DoesNotEscalate()
        {
            var analysis = Analysis(Reachable("SRV01", "10.20.0.5", "SMB", 445));

            var enriched = EnrichmentCorrelator.Apply(
                analysis, new[] { Legacy("SRV99", "SMB_SIGNING_DISABLED") });

            Assert.Equal(0, enriched);
            Assert.Equal(Severity.Medium, analysis.Findings.Single().Severity);
            Assert.Empty(analysis.Findings.Single().EnrichmentNotes);
        }

        [Fact]
        public void WeaknessIsMatchedToTheServiceItActuallyAffects()
        {
            // RDP_NLA_DISABLED must not escalate a reachable SMB path.
            var analysis = Analysis(Reachable("SRV01", "10.20.0.5", "SMB", 445));

            var enriched = EnrichmentCorrelator.Apply(
                analysis, new[] { Legacy("SRV01", "RDP_NLA_DISABLED") });

            Assert.Equal(0, enriched);
        }

        [Fact]
        public void HostWideWeaknessAppliesToAnyReachableService()
        {
            // A disabled firewall is not tied to one protocol.
            var analysis = Analysis(Reachable("SRV01", "10.20.0.5", "MSSQL", 1433));

            var enriched = EnrichmentCorrelator.Apply(
                analysis, new[] { Legacy("SRV01", "WINDOWS_FIREWALL_DISABLED") });

            Assert.Equal(1, enriched);
        }

        [Fact]
        public void FilteredPathsAreNotEscalated()
        {
            // A weakness behind a working boundary is a finding in its own right,
            // not an escalation of a path that does not exist.
            var analysis = Analysis(Reachable(
                "SRV01", "10.20.0.5", "SMB", 445, verdict: ReachabilityVerdict.Filtered));

            var enriched = EnrichmentCorrelator.Apply(
                analysis, new[] { Legacy("SRV01", "SMB_SIGNING_DISABLED") });

            Assert.Equal(0, enriched);
            Assert.Empty(analysis.Findings.Single().EnrichmentNotes);
        }

        [Fact]
        public void DomainAnchoredOverlapAttachesToTheHostsItSpans()
        {
            // LOCAL_ADMIN_OVERLAP is stamped with the DOMAIN as its host but lists
            // the machines it actually covers. This is precisely the pairing the
            // original correlation engine could never make.
            var analysis = Analysis(
                Reachable("SRV01", "10.20.0.5", "SMB", 445),
                Reachable("SRV42", "10.20.0.9", "SMB", 445));

            var overlap = Legacy("corp.local", "LOCAL_ADMIN_OVERLAP", "SRV01", "SRV07");

            var enriched = EnrichmentCorrelator.Apply(analysis, new[] { overlap });

            Assert.Equal(1, enriched);

            var spanned = analysis.Findings.Single(f => f.TargetHostname == "SRV01");
            Assert.Single(spanned.EnrichmentNotes);
            Assert.Contains("pivots", spanned.EnrichmentNotes[0]);

            var untouched = analysis.Findings.Single(f => f.TargetHostname == "SRV42");
            Assert.Empty(untouched.EnrichmentNotes);
        }

        [Fact]
        public void MultipleWeaknessesEscalateOnlyOnce()
        {
            // A pile of medium issues must not outrank a genuine critical.
            var analysis = Analysis(Reachable("SRV01", "10.20.0.5", "SMB", 445));

            var enriched = EnrichmentCorrelator.Apply(analysis, new[]
            {
                Legacy("SRV01", "SMB_SIGNING_DISABLED"),
                Legacy("SRV01", "LAPS_NOT_DEPLOYED"),
                Legacy("SRV01", "OPEN_SMB_SHARE_WRITE"),
            });

            Assert.Equal(1, enriched);

            var finding = analysis.Findings.Single();
            Assert.Equal(3, finding.EnrichmentNotes.Count);   // all recorded...
            Assert.Equal(Severity.High, finding.Severity);    // ...one escalation
        }

        [Fact]
        public void SeverityIsCappedAtCritical()
        {
            var analysis = Analysis(Reachable(
                "SRV01", "10.20.0.5", "SMB", 445, severity: Severity.Critical));

            EnrichmentCorrelator.Apply(analysis, new[] { Legacy("SRV01", "SMB_SIGNING_DISABLED") });

            Assert.Equal(Severity.Critical, analysis.Findings.Single().Severity);
            Assert.True(analysis.Findings.Single().RiskScore <= 10.0);
        }

        [Fact]
        public void FqdnAndShortNameAreTheSameMachine()
        {
            var analysis = Analysis(Reachable("SRV01.corp.local", "10.20.0.5", "SMB", 445));

            var enriched = EnrichmentCorrelator.Apply(
                analysis, new[] { Legacy("SRV01", "SMB_SIGNING_DISABLED") });

            Assert.Equal(1, enriched);
        }

        [Fact]
        public void MatchingByIpWorksWhenTargetsWereGivenAsAddresses()
        {
            var analysis = Analysis(Reachable("10.20.0.5", "10.20.0.5", "SMB", 445));

            var enriched = EnrichmentCorrelator.Apply(
                analysis, new[] { Legacy("10.20.0.5", "SMB_SIGNING_DISABLED") });

            Assert.Equal(1, enriched);
        }

        [Fact]
        public void NoLegacyFindings_IsANoOp()
        {
            var analysis = Analysis(Reachable("SRV01", "10.20.0.5", "SMB", 445));

            Assert.Equal(0, EnrichmentCorrelator.Apply(analysis, new List<Finding>()));
            Assert.Equal(Severity.Medium, analysis.Findings.Single().Severity);
        }

        [Fact]
        public void EveryRuleNamesAServiceOrIsExplicitlyHostWide()
        {
            // Guards against a rule silently applying to everything because its
            // AppliesTo list was forgotten.
            foreach (var rule in EnrichmentCorrelator.Rules)
            {
                Assert.False(string.IsNullOrWhiteSpace(rule.CheckName));
                Assert.False(string.IsNullOrWhiteSpace(rule.Rationale));
            }

            var hostWide = EnrichmentCorrelator.Rules.Count(r => r.AppliesTo.Length == 0);
            Assert.True(hostWide <= 2,
                $"{hostWide} rules apply to every service; host-wide escalation should be rare.");
        }

        [Theory]
        [InlineData("SRV01.corp.local", "SRV01")]
        [InlineData("SRV01", "SRV01")]
        [InlineData("", "")]
        public void ShortNameStripsTheDomainSuffix(string input, string expected)
        {
            Assert.Equal(expected, EnrichmentCorrelator.ShortName(input));
        }
    }
}
