using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Xunit;
using ZeroTrustAuditor.Analysis;
using ZeroTrustAuditor.Config;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Tests
{
    /// <summary>
    /// The observed/expected cross-product. Each combination is a distinct
    /// operational message, which is the reason the tri-state verdict exists.
    /// </summary>
    public class PolicyStatusClassificationTests
    {
        [Theory]
        // Denied by policy...
        [InlineData(ReachabilityVerdict.Open,     PolicyAction.Deny,  PolicyStatus.Violation)]
        [InlineData(ReachabilityVerdict.Closed,   PolicyAction.Deny,  PolicyStatus.Unenforced)]
        [InlineData(ReachabilityVerdict.Filtered, PolicyAction.Deny,  PolicyStatus.Enforced)]
        // ...and permitted by policy.
        [InlineData(ReachabilityVerdict.Open,     PolicyAction.Allow, PolicyStatus.Compliant)]
        [InlineData(ReachabilityVerdict.Closed,   PolicyAction.Allow, PolicyStatus.Compliant)]
        [InlineData(ReachabilityVerdict.Filtered, PolicyAction.Allow, PolicyStatus.Drift)]
        public void StatusIsTheCrossProductOfVerdictAndPolicy(
            ReachabilityVerdict verdict, PolicyAction action, PolicyStatus expected)
        {
            Assert.Equal(expected, PolicyEvaluator.ClassifyStatus(verdict, action));
        }

        [Theory]
        [InlineData(PolicyAction.Deny)]
        [InlineData(PolicyAction.Allow)]
        public void UnknownVerdict_IsNeverAViolationAndNeverAPass(PolicyAction action)
        {
            // Not probing, or failing to probe, tells us nothing. Recording it as
            // either enforced or violated would be an outright false statement.
            Assert.Equal(PolicyStatus.NoPolicyDefined,
                PolicyEvaluator.ClassifyStatus(ReachabilityVerdict.Unknown, action));
        }

        [Fact]
        public void UnenforcedIsRankedBelowTheViolationItWouldBecome()
        {
            // A latent hole is real but not currently exploitable.
            Assert.Equal(Severity.High,
                PolicyEvaluator.SeverityFor(PolicyStatus.Unenforced, Severity.Critical));
            Assert.Equal(Severity.Medium,
                PolicyEvaluator.SeverityFor(PolicyStatus.Unenforced, Severity.High));
            // Floored at Low -- it never disappears entirely.
            Assert.Equal(Severity.Low,
                PolicyEvaluator.SeverityFor(PolicyStatus.Unenforced, Severity.Low));
        }

        [Fact]
        public void ViolationKeepsTheZonePairSeverity()
        {
            Assert.Equal(Severity.Critical,
                PolicyEvaluator.SeverityFor(PolicyStatus.Violation, Severity.Critical));
        }

        [Fact]
        public void EnforcedAndCompliantAreInformational()
        {
            Assert.Equal(Severity.Informational,
                PolicyEvaluator.SeverityFor(PolicyStatus.Enforced, Severity.Critical));
            Assert.Equal(Severity.Informational,
                PolicyEvaluator.SeverityFor(PolicyStatus.Compliant, Severity.Critical));
        }

        [Fact]
        public void DriftIsOperationalNotSecurity()
        {
            // An approved path that is blocked becomes an outage ticket, not an
            // incident -- it must not outrank a real exposure.
            Assert.Equal(Severity.Low,
                PolicyEvaluator.SeverityFor(PolicyStatus.Drift, Severity.Critical));
        }
    }

    public class PolicyEvaluatorAnalysisTests
    {
        private const string UserCidr   = "10.10.0.0/16";
        private const string Tier0Cidr  = "10.30.1.0/24";
        private const string ServerCidr = "10.20.0.0/16";

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

        private static SegmentationContext Context(SegmentationPolicy? policy = null)
        {
            var zones = new[]
            {
                Zone("user-vlan",    TrustTier.User,         ZoneRoles.User,   UserCidr),
                Zone("tier0",        TrustTier.ControlPlane, ZoneRoles.Tier0,  Tier0Cidr),
                Zone("server-tier1", TrustTier.Server,       ZoneRoles.Server, ServerCidr),
            };

            var catalog = SegmentationConfigLoader.BuiltInCatalog();
            catalog.Index();

            return new SegmentationContext
            {
                Zones    = new ZoneResolver(zones),
                Policy   = policy ?? new SegmentationPolicy { DefaultAction = "deny" },
                Services = catalog,
            };
        }

        private static ReachabilityObservation Obs(
            string ip, int port, string serviceId, ReachabilityVerdict verdict) => new()
        {
            Host           = "target",
            TargetIp       = ip,
            Port           = port,
            Transport      = "tcp",
            ServiceClassId = serviceId,
            Verdict        = verdict,
            Confidence     = 1.0,
            Evidence       = new ProbeEvidence { Method = "tcp-connect", Response = "syn-ack" },
        };

        private static SegmentationAnalysis Analyze(
            SegmentationContext ctx, params ReachabilityObservation[] observations) =>
            new PolicyEvaluator(ctx).Analyze(
                observations, "auditor01", IPAddress.Parse("10.10.5.5"));

        [Fact]
        public void UserToTier0_OverSmb_IsACriticalViolation()
        {
            var analysis = Analyze(Context(),
                Obs("10.30.1.10", 445, "SMB", ReachabilityVerdict.Open));

            var finding = Assert.Single(analysis.Violations);
            Assert.Equal(Severity.Critical, finding.Severity);
            Assert.Equal("user-vlan", finding.VantageZoneId);
            Assert.Equal("tier0",     finding.TargetZoneId);
        }

        [Fact]
        public void ApprovedFlowIsCompliant_NotAViolation()
        {
            // Without a policy baseline this would be reported as a violation, and
            // the operator would re-triage the same approved path every run.
            var policy = new SegmentationPolicy
            {
                DefaultAction = "deny",
                Rules = new List<PolicyRule>
                {
                    new()
                    {
                        Id = "approved", From = new List<string> { "user-vlan" },
                        To = new List<string> { "server-tier1" },
                        Services = new List<string> { "SMB" }, Action = "allow",
                    },
                },
            };

            var analysis = Analyze(Context(policy),
                Obs("10.20.4.11", 445, "SMB", ReachabilityVerdict.Open));

            Assert.Empty(analysis.Violations);
            Assert.Equal(PolicyStatus.Compliant, analysis.Findings.Single().Policy);
            Assert.Equal("approved", analysis.Findings.Single().MatchedRuleId);
        }

        [Fact]
        public void FilteredPathBecomesEnforcementEvidence_NotAFinding()
        {
            var analysis = Analyze(Context(),
                Obs("10.30.1.10", 445, "SMB", ReachabilityVerdict.Filtered));

            Assert.Empty(analysis.Violations);
            var evidence = Assert.Single(analysis.EnforcementEvidence);
            Assert.Equal(Severity.Informational, evidence.Severity);
        }

        [Fact]
        public void ClosedPathAcrossABoundaryIsReportedAsUnenforced()
        {
            var analysis = Analyze(Context(),
                Obs("10.30.1.10", 445, "SMB", ReachabilityVerdict.Closed));

            var unenforced = Assert.Single(analysis.Unenforced);
            Assert.Equal(PolicyStatus.Unenforced, unenforced.Policy);
            Assert.Contains("nothing listening", unenforced.Description,
                StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void ExposureRegisterGroupsServicesByEndpoint()
        {
            var analysis = Analyze(Context(),
                Obs("10.30.1.10", 445,  "SMB", ReachabilityVerdict.Open),
                Obs("10.30.1.10", 3389, "RDP", ReachabilityVerdict.Open),
                Obs("10.20.4.11", 445,  "SMB", ReachabilityVerdict.Filtered));

            var dc = analysis.Exposures.Single(e => e.TargetIp == "10.30.1.10");

            Assert.Equal(2, dc.Services.Count);
            Assert.Equal("tier0", dc.ZoneId);
            Assert.Equal(Severity.Critical, dc.WorstSeverity);
            Assert.Contains("SMB", dc.OpenServiceSummary);
            Assert.Contains("RDP", dc.OpenServiceSummary);

            // Blast radius counts only zones PROVEN to reach it.
            Assert.Equal(1, dc.BlastRadius);
            var filteredHost = analysis.Exposures.Single(e => e.TargetIp == "10.20.4.11");
            Assert.Equal(0, filteredHost.BlastRadius);
        }

        [Fact]
        public void ExposuresAreSortedBySeverityThenBlastRadius()
        {
            var analysis = Analyze(Context(),
                Obs("10.20.4.11", 445,  "SMB", ReachabilityVerdict.Closed),
                Obs("10.30.1.10", 445,  "SMB", ReachabilityVerdict.Open));

            Assert.Equal("10.30.1.10", analysis.Exposures.First().TargetIp);
        }

        [Fact]
        public void UnmeasuredZonePairsAreMarkedUnassessed_NotClean()
        {
            // The single most dangerous misreading of this report would be treating
            // a row nobody probed as evidence of segmentation.
            var analysis = Analyze(Context(),
                Obs("10.30.1.10", 445, "SMB", ReachabilityVerdict.Open));

            var measured = analysis.Matrix.Cell("user-vlan", "tier0");
            Assert.NotNull(measured);
            Assert.True(measured!.Assessed);

            var neverProbed = analysis.Matrix.Cell("tier0", "user-vlan");
            Assert.NotNull(neverProbed);
            Assert.False(neverProbed!.Assessed);

            Assert.True(analysis.Matrix.AssessedPairs < analysis.Matrix.TotalPairs);
        }

        [Fact]
        public void MatrixCellRecordsViolationCountAndCrossingServices()
        {
            var analysis = Analyze(Context(),
                Obs("10.30.1.10", 445,  "SMB", ReachabilityVerdict.Open),
                Obs("10.30.1.10", 3389, "RDP", ReachabilityVerdict.Open));

            var cell = analysis.Matrix.Cell("user-vlan", "tier0")!;
            Assert.Equal(2, cell.ViolationCount);
            Assert.Equal(2, cell.OpenCount);
            Assert.Contains("SMB", cell.CrossingServices);
            Assert.Contains("RDP", cell.CrossingServices);
            Assert.Equal(Severity.Critical, cell.WorstSeverity);
        }

        [Fact]
        public void UnmappedTargetIsCountedAndCitesDataFlowMapping()
        {
            var analysis = Analyze(Context(),
                Obs("172.31.9.9", 445, "SMB", ReachabilityVerdict.Open));

            Assert.Equal(1, analysis.UnmappedEndpointCount);

            var finding = analysis.Findings.Single();
            Assert.Contains(finding.Guidance,
                g => g.Section.Contains("Data flow mapping", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void FindingsCarryNsaOrCisaGuidance()
        {
            var analysis = Analyze(Context(),
                Obs("10.30.1.10", 445, "SMB", ReachabilityVerdict.Open));

            var finding = analysis.Violations.Single();

            Assert.NotEmpty(finding.Guidance);
            Assert.Contains(finding.Guidance, g => g.Source.Contains("NSA"));
            Assert.Contains(finding.Guidance, g => g.Source.Contains("CISA"));
            // The specific segmentation misconfiguration, not a generic reference.
            Assert.Contains(finding.Guidance, g => g.Document.Contains("AA23-278A"));
        }

        [Fact]
        public void RemediationNamesTheActualBoundaryChange()
        {
            var analysis = Analyze(Context(),
                Obs("10.30.1.10", 445, "SMB", ReachabilityVerdict.Open));

            var remediation = analysis.Violations.Single().Remediation;

            Assert.Contains("user-vlan", remediation);
            Assert.Contains("tier0", remediation);
            Assert.Contains("445", remediation);
        }

        [Fact]
        public void LowConfidenceReducesRiskScore()
        {
            var ctx = Context();

            var confident = Obs("10.30.1.10", 445, "SMB", ReachabilityVerdict.Open);
            var unsure = new ReachabilityObservation
            {
                Host = "t", TargetIp = "10.30.1.11", Port = 445, Transport = "tcp",
                ServiceClassId = "SMB", Verdict = ReachabilityVerdict.Open,
                Confidence = 0.6,
                Evidence = new ProbeEvidence { Method = "tcp-connect", Response = "syn-ack" },
            };

            var analysis = Analyze(ctx, confident, unsure);

            var high = analysis.Findings.Single(f => f.TargetIp == "10.30.1.10");
            var low  = analysis.Findings.Single(f => f.TargetIp == "10.30.1.11");

            Assert.True(low.RiskScore < high.RiskScore);
        }
    }

    public class ZtmmScorerTests
    {
        private static SegmentationAnalysis WithFindings(params SegmentationFinding[] findings)
        {
            var matrix = new ZoneMatrix
            {
                Zones = new List<ZoneDefinition> { new() { Id = "a" }, new() { Id = "b" } },
                Cells = new List<ZoneMatrixCell>
                {
                    new() { FromZoneId = "a", ToZoneId = "b", Assessed = true },
                    new() { FromZoneId = "b", ToZoneId = "a" },
                },
            };

            return new SegmentationAnalysis
            {
                VantageZoneId = "a",
                Findings      = findings.ToList(),
                Matrix        = matrix,
            };
        }

        private static SegmentationFinding F(PolicyStatus status, Severity severity) => new()
        {
            Policy = status, Severity = severity, ServiceClass = "SMB",
            Verdict = status == PolicyStatus.Violation
                ? ReachabilityVerdict.Open
                : ReachabilityVerdict.Filtered,
        };

        [Fact]
        public void CriticalViolationsScoreTraditional()
        {
            var score = ZtmmScorer.Score(WithFindings(F(PolicyStatus.Violation, Severity.Critical)))
                .Functions.Single(f => f.Function == "Network Segmentation");

            Assert.Equal(ZtmmStage.Traditional, score.Stage);
            Assert.True(score.Assessed);
        }

        [Fact]
        public void NonCriticalViolationsScoreInitial()
        {
            var score = ZtmmScorer.Score(WithFindings(F(PolicyStatus.Violation, Severity.Medium)))
                .Functions.Single(f => f.Function == "Network Segmentation");

            Assert.Equal(ZtmmStage.Initial, score.Stage);
        }

        [Fact]
        public void UnenforcedButNoViolationsScoresAdvanced_NotOptimal()
        {
            // Safe by accident is not the same as safe by policy.
            var score = ZtmmScorer.Score(WithFindings(F(PolicyStatus.Unenforced, Severity.Medium)))
                .Functions.Single(f => f.Function == "Network Segmentation");

            Assert.Equal(ZtmmStage.Advanced, score.Stage);
        }

        [Fact]
        public void FullyEnforcedScoresOptimal()
        {
            var score = ZtmmScorer.Score(WithFindings(F(PolicyStatus.Enforced, Severity.Informational)))
                .Functions.Single(f => f.Function == "Network Segmentation");

            Assert.Equal(ZtmmStage.Optimal, score.Stage);
        }

        [Fact]
        public void UnobservableFunctionsAreMarkedNotAssessed_NotGivenAFlatteringDefault()
        {
            var scorecard = ZtmmScorer.Score(WithFindings(F(PolicyStatus.Enforced, Severity.Informational)));

            var resilience = scorecard.Functions.Single(f => f.Function == "Network Resilience");
            Assert.False(resilience.Assessed);

            var visibility = scorecard.Functions.Single(f => f.Function == "Visibility and Analytics");
            Assert.False(visibility.Assessed);
        }

        [Fact]
        public void CaveatStatesTheCoverageLimit()
        {
            var scorecard = ZtmmScorer.Score(WithFindings(F(PolicyStatus.Enforced, Severity.Informational)));

            Assert.Contains("1 of 2 zone pairs", scorecard.Caveat);
            Assert.Contains("UNASSESSED, not clean", scorecard.Caveat);
        }

        [Fact]
        public void NoAssessedPairs_ScoresNothing()
        {
            var analysis = new SegmentationAnalysis
            {
                Matrix = new ZoneMatrix
                {
                    Cells = new List<ZoneMatrixCell> { new() { FromZoneId = "a", ToZoneId = "b" } },
                },
            };

            var score = ZtmmScorer.Score(analysis)
                .Functions.Single(f => f.Function == "Network Segmentation");

            Assert.False(score.Assessed);
        }

        [Fact]
        public void CleartextServiceDropsEncryptionToTraditional()
        {
            var telnet = new SegmentationFinding
            {
                Policy = PolicyStatus.Violation, Severity = Severity.High,
                ServiceClass = "TELNET", Verdict = ReachabilityVerdict.Open,
            };

            var score = ZtmmScorer.Score(WithFindings(telnet))
                .Functions.Single(f => f.Function == "Network Encryption");

            Assert.Equal(ZtmmStage.Traditional, score.Stage);
            Assert.Contains("TELNET", score.Evidence);
        }
    }
}
