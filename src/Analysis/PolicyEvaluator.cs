using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using ZeroTrustAuditor.Config;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Analysis
{
    /// <summary>
    /// Turns raw reachability observations into policy-classified findings.
    ///
    /// This is where "observed" meets "expected". Without it, every reachable port
    /// across a boundary is reported, including the approved administration paths --
    /// so triage stays manual on every run and the report is mostly noise.
    /// </summary>
    public sealed class PolicyEvaluator
    {
        private readonly SegmentationContext _context;
        private readonly DateTimeOffset _asOf;

        public PolicyEvaluator(SegmentationContext context, DateTimeOffset? asOf = null)
        {
            _context = context;
            _asOf    = asOf ?? DateTimeOffset.UtcNow;
        }

        public SegmentationAnalysis Analyze(
            IReadOnlyList<ReachabilityObservation> observations,
            string vantageHost,
            IPAddress? vantageIp)
        {
            var vantageZone = _context.Zones.Resolve(vantageIp);

            var findings  = new List<SegmentationFinding>();
            var exposures = new Dictionary<string, EndpointExposure>(StringComparer.OrdinalIgnoreCase);
            var matrix    = BuildEmptyMatrix(vantageZone);

            foreach (var observation in observations)
            {
                if (!IPAddress.TryParse(observation.TargetIp, out var targetIp))
                    continue;

                var targetKnown = _context.Zones.TryResolve(targetIp, out var targetZone);
                var service     = ResolveService(observation);

                var decision = _context.Policy.Evaluate(
                    vantageZone.Id, targetZone.Id, service.Id, _asOf);

                var status = ClassifyStatus(observation.Verdict, decision.Action);
                var risk   = ZonePairRisk.Assess(vantageZone, targetZone, service);
                var sev    = SeverityFor(status, risk.Severity);

                var finding = BuildFinding(
                    observation, vantageHost, vantageIp, vantageZone,
                    targetIp, targetZone, targetKnown, service,
                    decision, status, sev, risk);

                findings.Add(finding);

                Accumulate(exposures, observation, targetIp, targetZone,
                           service, status, sev, vantageZone);

                UpdateMatrix(matrix, vantageZone.Id, targetZone.Id,
                             observation.Verdict, status, sev, service);
            }

            var analysis = new SegmentationAnalysis
            {
                VantageHost     = vantageHost,
                VantageIp       = vantageIp?.ToString() ?? "unknown",
                VantageZoneId   = vantageZone.Id,
                Findings        = findings,
                Exposures       = exposures.Values
                                    .OrderByDescending(e => e.WorstSeverity)
                                    .ThenByDescending(e => e.BlastRadius)
                                    .ThenBy(e => e.TargetIp)
                                    .ToList(),
                Matrix          = matrix,
                ProgramGuidance = GuidanceCatalog.ProgramLevel(),
            };

            analysis.Scorecard = ZtmmScorer.Score(analysis);
            return analysis;
        }

        // ── Classification ────────────────────────────────────────────────────

        /// <summary>
        /// The observed/expected cross-product. Each cell is a distinct operational
        /// message, which is why the tri-state verdict was worth building.
        /// </summary>
        internal static PolicyStatus ClassifyStatus(
            ReachabilityVerdict verdict, PolicyAction action)
        {
            if (verdict == ReachabilityVerdict.Unknown)
                return PolicyStatus.NoPolicyDefined;

            if (action == PolicyAction.Allow)
            {
                return verdict switch
                {
                    // An approved path that is blocked is an outage waiting to happen,
                    // not a security finding.
                    ReachabilityVerdict.Filtered => PolicyStatus.Drift,
                    _                            => PolicyStatus.Compliant,
                };
            }

            return verdict switch
            {
                ReachabilityVerdict.Open     => PolicyStatus.Violation,
                // Nothing listening, but nothing blocking either.
                ReachabilityVerdict.Closed   => PolicyStatus.Unenforced,
                ReachabilityVerdict.Filtered => PolicyStatus.Enforced,
                _                            => PolicyStatus.NoPolicyDefined,
            };
        }

        internal static Severity SeverityFor(PolicyStatus status, Severity zonePairSeverity) =>
            status switch
            {
                PolicyStatus.Violation  => zonePairSeverity,
                // A latent hole is real but not currently exploitable: one step below
                // the violation it would become, floored at Low.
                PolicyStatus.Unenforced => Demote(zonePairSeverity),
                PolicyStatus.Drift      => Severity.Low,
                _                       => Severity.Informational,
            };

        private static Severity Demote(Severity severity) => severity switch
        {
            Severity.Critical => Severity.High,
            Severity.High     => Severity.Medium,
            Severity.Medium   => Severity.Low,
            _                 => Severity.Low,
        };

        private ServiceClassDefinition ResolveService(ReachabilityObservation observation)
        {
            return _context.Services.ById(observation.ServiceClassId)
                ?? _context.Services.ByPort(observation.Port, observation.Transport).FirstOrDefault()
                ?? new ServiceClassDefinition
                {
                    Id       = observation.ServiceClassId,
                    Ports    = new List<int> { observation.Port },
                    Risk     = ServiceRisk.Medium,
                    Category = ServiceCategories.RemoteAdmin,
                };
        }

        // ── Finding construction ──────────────────────────────────────────────

        private SegmentationFinding BuildFinding(
            ReachabilityObservation observation,
            string vantageHost, IPAddress? vantageIp, ZoneDefinition vantageZone,
            IPAddress targetIp, ZoneDefinition targetZone, bool targetKnown,
            ServiceClassDefinition service, PolicyDecision decision,
            PolicyStatus status, Severity severity, ZoneRiskAssessment risk)
        {
            var (description, remediation) = Narrate(
                observation, vantageZone, targetZone, service, status, decision, risk);

            return new SegmentationFinding
            {
                VantageHost   = vantageHost,
                VantageIp     = vantageIp?.ToString() ?? "unknown",
                VantageZoneId = vantageZone.Id,

                TargetIp       = observation.TargetIp,
                TargetHostname = observation.Host,
                TargetZoneId   = targetZone.Id,
                TargetRole     = targetZone.Role,

                Port         = observation.Port,
                Transport    = observation.Transport,
                ServiceClass = service.Id,

                Verdict    = observation.Verdict,
                Evidence   = observation.Evidence,
                Confidence = observation.Confidence,

                Policy        = status,
                MatchedRuleId = decision.MatchedRule?.Id,
                PolicyReason  = decision.Reason,

                Severity  = severity,
                RiskScore = ScoreOf(severity, observation.Confidence),

                Description = description,
                Remediation = remediation,
                Guidance    = GuidanceCatalog.For(
                    vantageZone, targetZone, service, status, !targetKnown),

                FirstSeen = observation.ObservedAt,
                LastSeen  = observation.ObservedAt,
            };
        }

        private static double ScoreOf(Severity severity, double confidence)
        {
            var baseScore = severity switch
            {
                Severity.Critical => 9.0,
                Severity.High     => 7.0,
                Severity.Medium   => 5.0,
                Severity.Low      => 3.0,
                _                 => 1.0,
            };

            // A finding inferred from silence should not outrank one the host
            // confirmed itself.
            return Math.Round(baseScore * Math.Max(0.5, confidence), 1);
        }

        private static (string Description, string Remediation) Narrate(
            ReachabilityObservation observation,
            ZoneDefinition source, ZoneDefinition target,
            ServiceClassDefinition service, PolicyStatus status,
            PolicyDecision decision, ZoneRiskAssessment risk)
        {
            var path = $"{source.DisplayName} -> {target.DisplayName}";
            var svc  = $"{service.Id} ({observation.Transport}/{observation.Port})";
            var deny = $"Deny {source.Id} -> {target.Id} on {observation.Transport}/" +
                       $"{observation.Port} at the boundary firewall.";

            return status switch
            {
                PolicyStatus.Violation => (
                    $"{svc} on {observation.TargetIp} is REACHABLE across {path}, and policy " +
                    $"does not permit it. {risk.Rationale}. {decision.Reason}",
                    deny + " If this flow is in fact required, add an owned, expiring allow " +
                           "rule to policy.json so it is documented rather than undeclared."),

                PolicyStatus.Unenforced => (
                    $"{svc} on {observation.TargetIp} is not filtered across {path}. The host " +
                    "answered with RST, so packets reach it and no boundary control is " +
                    "blocking this protocol -- there is simply nothing listening today. " +
                    "The moment this service is installed or enabled, the path is open.",
                    deny + " Segmentation should be enforced by policy, not by the incidental " +
                           "absence of a listener."),

                PolicyStatus.Enforced => (
                    $"{svc} is correctly blocked across {path}. The probe was dropped, which " +
                    "is positive evidence that this boundary control works.",
                    "No action required. Retain as evidence of enforcement."),

                PolicyStatus.Drift => (
                    $"{svc} is APPROVED across {path} but was blocked. An approved flow that " +
                    "does not work will surface as an outage, and may indicate a firewall " +
                    $"change nobody recorded. {decision.Reason}",
                    "Confirm whether the rule is still needed. If it is, restore the path; " +
                    "if not, remove the now-stale allow rule from policy.json."),

                PolicyStatus.Compliant => (
                    $"{svc} across {path} matches an approved policy rule. {decision.Reason}",
                    "No action required."),

                _ => (
                    $"{svc} across {path} could not be determined " +
                    $"({observation.Evidence.Response}). No conclusion should be drawn.",
                    "Re-run against this host once it is reachable, or exclude it from scope."),
            };
        }

        // ── Aggregation ───────────────────────────────────────────────────────

        private static void Accumulate(
            Dictionary<string, EndpointExposure> exposures,
            ReachabilityObservation observation,
            IPAddress targetIp, ZoneDefinition targetZone,
            ServiceClassDefinition service, PolicyStatus status,
            Severity severity, ZoneDefinition vantageZone)
        {
            var key = observation.TargetIp;

            if (!exposures.TryGetValue(key, out var exposure))
            {
                exposure = new EndpointExposure
                {
                    TargetIp = observation.TargetIp,
                    Hostname = observation.Host,
                    ZoneId   = targetZone.Id,
                    ZoneName = targetZone.DisplayName,
                    ZoneRole = targetZone.Role,
                    ZoneTier = targetZone.Tier,
                };
                exposures[key] = exposure;
            }

            exposure.Services.Add(new ExposedService
            {
                ServiceClassId = service.Id,
                Port           = observation.Port,
                Transport      = observation.Transport,
                Verdict        = observation.Verdict,
                Policy         = status,
                Severity       = severity,
                Banner         = observation.Evidence.Banner,
                Confirmation   = observation.Evidence.ServiceConfirmation,
            });

            // Blast radius counts only zones proven to reach it.
            if (observation.Verdict == ReachabilityVerdict.Open &&
                !exposure.ReachableFromZones.Contains(vantageZone.Id, StringComparer.OrdinalIgnoreCase))
            {
                exposure.ReachableFromZones.Add(vantageZone.Id);
            }
        }

        private ZoneMatrix BuildEmptyMatrix(ZoneDefinition vantageZone)
        {
            var zones = _context.Zones.Zones.ToList();

            if (!zones.Any(z => z.Id.Equals(_context.Zones.UnclassifiedZone.Id,
                                            StringComparison.OrdinalIgnoreCase)))
                zones.Add(_context.Zones.UnclassifiedZone);

            if (!zones.Any(z => z.Id.Equals(vantageZone.Id, StringComparison.OrdinalIgnoreCase)))
                zones.Add(vantageZone);

            var cells = new List<ZoneMatrixCell>();
            foreach (var from in zones)
            foreach (var to in zones)
                cells.Add(new ZoneMatrixCell { FromZoneId = from.Id, ToZoneId = to.Id });

            return new ZoneMatrix { Zones = zones, Cells = cells };
        }

        private static void UpdateMatrix(
            ZoneMatrix matrix, string fromZone, string toZone,
            ReachabilityVerdict verdict, PolicyStatus status,
            Severity severity, ServiceClassDefinition service)
        {
            var cell = matrix.Cell(fromZone, toZone);
            if (cell == null) return;

            cell.Assessed = true;

            switch (verdict)
            {
                case ReachabilityVerdict.Open:     cell.OpenCount++;     break;
                case ReachabilityVerdict.Closed:   cell.ClosedCount++;   break;
                case ReachabilityVerdict.Filtered: cell.FilteredCount++; break;
                default:                           cell.UnknownCount++;  break;
            }

            if (status == PolicyStatus.Violation)
            {
                cell.ViolationCount++;
                cell.CrossingServices.Add(service.Id);
            }

            if (status == PolicyStatus.Unenforced) cell.UnenforcedCount++;

            if (severity > cell.WorstSeverity) cell.WorstSeverity = severity;
        }
    }
}
