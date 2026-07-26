using System;
using System.Collections.Generic;
using System.Linq;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Analysis
{
    /// <summary>
    /// Scores the CISA Zero Trust Maturity Model v2.0 Networks pillar from what the
    /// assessment actually measured.
    ///
    /// Two rules govern this scorer:
    ///
    ///   1. Only functions with supporting evidence are scored. Functions this tool
    ///      cannot observe (encryption in transit, resilience, automation) are
    ///      returned marked "not assessed" rather than given a flattering default.
    ///      A scorecard that invents scores for things it never looked at is worse
    ///      than no scorecard.
    ///
    ///   2. Scoring covers assessed zone pairs only. One run measures one vantage
    ///      zone, so the result describes that source segment, not the estate.
    /// </summary>
    public static class ZtmmScorer
    {
        public static ZtmmScorecard Score(SegmentationAnalysis analysis)
        {
            var functions = new List<ZtmmFunctionScore>
            {
                ScoreNetworkSegmentation(analysis),
                ScoreNetworkTrafficManagement(analysis),
                ScoreNetworkEncryption(analysis),
                NotAssessed("Network Resilience",
                    "This assessment does not measure failover, capacity, or " +
                    "distributed-denial-of-service resistance."),
                NotAssessed("Visibility and Analytics",
                    "Requires log and telemetry review, which this tool does not perform. " +
                    "Note that AA23-278A lists insufficient internal network monitoring as " +
                    "a top-ten misconfiguration in its own right."),
                NotAssessed("Automation and Orchestration",
                    "Requires review of change and policy-deployment tooling."),
            };

            var assessedPairs = analysis.Matrix.AssessedPairs;
            var totalPairs    = analysis.Matrix.TotalPairs;

            return new ZtmmScorecard
            {
                Functions = functions,
                Caveat =
                    $"Scored from {assessedPairs} of {totalPairs} zone pairs, measured from " +
                    $"'{analysis.VantageZoneId}'. Pairs with no probe are UNASSESSED, not clean. " +
                    "Run from a host in each source zone and merge the results for full coverage.",
            };
        }

        // ── Network Segmentation ──────────────────────────────────────────────

        private static ZtmmFunctionScore ScoreNetworkSegmentation(SegmentationAnalysis analysis)
        {
            var violations   = analysis.Violations.ToList();
            var unenforced   = analysis.Unenforced.Count();
            var enforced     = analysis.EnforcementEvidence.Count();
            var criticalHits = violations.Count(v => v.Severity == Severity.Critical);

            if (analysis.Matrix.AssessedPairs == 0)
            {
                return NotAssessed("Network Segmentation",
                    "No cross-zone probes completed, so no evidence of segmentation exists " +
                    "either way.");
            }

            ZtmmStage stage;
            string    evidence;
            string    nextStep;

            if (criticalHits > 0)
            {
                stage = ZtmmStage.Traditional;
                evidence =
                    $"{criticalHits} critical cross-zone violation(s): administrative or " +
                    "high-risk services reach protected zones from a lower trust tier. " +
                    "Boundaries exist on paper but do not constrain traffic.";
                nextStep =
                    "Close the critical paths first, starting with anything reaching a " +
                    "tier-0 or OT zone. Target the ZTMM Initial stage: isolate critical " +
                    "workloads and constrain connectivity to least function.";
            }
            else if (violations.Count > 0)
            {
                stage = ZtmmStage.Initial;
                evidence =
                    $"{violations.Count} cross-zone violation(s), none critical. Some " +
                    "boundaries are enforced; others permit undeclared flows.";
                nextStep =
                    "Eliminate the remaining violations, then move toward Advanced: " +
                    "ingress/egress micro-perimeters and service-specific interconnections " +
                    "rather than broad zone-to-zone permits.";
            }
            else if (unenforced > 0)
            {
                stage = ZtmmStage.Advanced;
                evidence =
                    $"No violations. However {unenforced} path(s) are unenforced -- the host " +
                    "answered with RST, so nothing is listening but nothing is blocking " +
                    "either. Those boundaries are currently safe by accident.";
                nextStep =
                    "Convert incidental safety into enforced policy: add explicit denies so " +
                    "the boundary holds when a service is next installed. That is the " +
                    "difference between Advanced and Optimal.";
            }
            else if (enforced > 0)
            {
                stage = ZtmmStage.Optimal;
                evidence =
                    $"No violations and no unenforced paths. {enforced} probe(s) were " +
                    "actively filtered, which is positive evidence that denied flows are " +
                    "blocked by policy rather than by the absence of a listener.";
                nextStep =
                    "Maintain. Extend coverage by running from additional vantage zones, " +
                    "and move toward per-workflow micro-segmentation.";
            }
            else
            {
                return NotAssessed("Network Segmentation",
                    "Probes completed but produced no conclusive verdicts.");
            }

            return new ZtmmFunctionScore
            {
                Function = "Network Segmentation",
                Stage    = stage,
                Evidence = evidence,
                NextStep = nextStep,
            };
        }

        // ── Network Traffic Management ────────────────────────────────────────

        private static ZtmmFunctionScore ScoreNetworkTrafficManagement(SegmentationAnalysis analysis)
        {
            var hasPolicy = analysis.Findings.Any(f => f.MatchedRuleId != null);
            var drift     = analysis.Drift.Count();

            if (!hasPolicy)
            {
                return new ZtmmFunctionScore
                {
                    Function = "Network Traffic Management",
                    Stage    = ZtmmStage.Traditional,
                    Evidence =
                        "No declared policy rule matched any observed flow. Traffic is " +
                        "governed by whatever the firewalls happen to contain rather than by " +
                        "a stated, reviewable policy.",
                    NextStep =
                        "Declare approved cross-zone flows in policy.json with an owner and " +
                        "an expiry for each. That file becomes the auditable record of " +
                        "intentional exceptions.",
                };
            }

            return new ZtmmFunctionScore
            {
                Function = "Network Traffic Management",
                Stage    = drift > 0 ? ZtmmStage.Initial : ZtmmStage.Advanced,
                Evidence = drift > 0
                    ? $"Policy is declared, but {drift} approved flow(s) are blocked in " +
                      "practice -- the stated policy and the deployed configuration disagree."
                    : "Declared policy matches observed behaviour on every approved flow.",
                NextStep = drift > 0
                    ? "Reconcile the drift: either restore the path or retire the rule."
                    : "Tighten broad rules toward service-specific interconnections.",
            };
        }

        // ── Network Encryption ────────────────────────────────────────────────

        private static ZtmmFunctionScore ScoreNetworkEncryption(SegmentationAnalysis analysis)
        {
            var cleartext = analysis.Findings
                .Where(f => f.Verdict == ReachabilityVerdict.Open)
                .Where(f => IsCleartext(f.ServiceClass))
                .ToList();

            if (cleartext.Count == 0)
            {
                return new ZtmmFunctionScore
                {
                    Function = "Network Encryption",
                    Stage    = ZtmmStage.Advanced,
                    Evidence = "No cleartext legacy protocols were observed reachable. " +
                               "Note this covers only the probed ports, not traffic content.",
                    NextStep = "Confirm encryption in transit for application traffic; that " +
                               "is outside what a port sweep can establish.",
                };
            }

            return new ZtmmFunctionScore
            {
                Function = "Network Encryption",
                Stage    = ZtmmStage.Traditional,
                Evidence = $"{cleartext.Count} cleartext service(s) reachable: " +
                           string.Join(", ", cleartext.Select(c => c.ServiceClass).Distinct()) +
                           ". Credentials and data on these paths are readable by anyone in between.",
                NextStep = "Retire Telnet, FTP, TFTP and r-services, or tunnel them. " +
                           "Where retirement is not possible, confine them to a dedicated " +
                           "segment with no path to user networks.",
            };
        }

        private static bool IsCleartext(string serviceId) =>
            serviceId is "TELNET" or "FTP" or "TFTP" or "RSERVICES" or "LDAP_CLEAR";

        private static ZtmmFunctionScore NotAssessed(string function, string why) => new()
        {
            Function = function,
            Assessed = false,
            Evidence = why,
            NextStep = "Assess separately; this tool provides no evidence either way.",
        };
    }
}
