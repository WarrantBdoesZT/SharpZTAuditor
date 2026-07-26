using System;
using System.Collections.Generic;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Network
{
    /// <summary>The severity of a cross-zone exposure, plus why it scored that way.</summary>
    public sealed class ZoneRiskAssessment
    {
        public Severity Severity  { get; init; }
        public int      RawScore  { get; init; }
        public string   Rationale { get; init; } = string.Empty;
    }

    /// <summary>
    /// Scores a reachable service by the ZONE PAIR it crosses, not by the port alone.
    ///
    /// This is the substantive difference from the old model, which stamped every
    /// cross-segment admin port as a flat High. SMB from the management VLAN to an
    /// application server is the designed administration path; the identical SMB
    /// from a guest VLAN to a domain controller is a domain-compromise path. Same
    /// port, same protocol, entirely different findings.
    /// </summary>
    public static class ZonePairRisk
    {
        public static ZoneRiskAssessment Assess(
            ZoneDefinition source, ZoneDefinition target, ServiceClassDefinition service)
        {
            var reasons = new List<string>();

            // Baseline: how dangerous the service is intrinsically.
            var score = service.Risk switch
            {
                ServiceRisk.Critical => 3,
                ServiceRisk.High     => 2,
                ServiceRisk.Medium   => 1,
                _                    => 0,
            };
            reasons.Add($"{service.Id} is intrinsically {service.Risk}");

            // Direction of trust. Positive delta means a LESS trusted zone is
            // reaching a MORE trusted one, which is the dangerous direction.
            var delta = source.Tier - target.Tier;

            if (target.Tier == TrustTier.ControlPlane && source.Tier > TrustTier.ControlPlane)
            {
                score += 2;
                reasons.Add($"target is control plane (tier 0) and source is tier {source.Tier}");
            }
            else if (delta >= 2)
            {
                score += 2;
                reasons.Add($"crosses {delta} trust tiers upward " +
                            $"(tier {source.Tier} -> tier {target.Tier})");
            }
            else if (delta == 1)
            {
                score += 1;
                reasons.Add($"crosses one trust tier upward " +
                            $"(tier {source.Tier} -> tier {target.Tier})");
            }
            else if (delta < 0)
            {
                // A more trusted zone reaching a less trusted one is the normal
                // administration direction (management -> servers).
                score -= 2;
                reasons.Add($"descending trust direction " +
                            $"(tier {source.Tier} -> tier {target.Tier}), typical of admin paths");
            }

            // An untrusted source reaching anything internal is severe regardless of tiers.
            if (IsRole(source, ZoneRoles.Untrusted))
            {
                score += 2;
                reasons.Add("source zone is untrusted (guest/BYOD)");
            }

            // IT -> OT. CISA/NSA AA23-278A calls out that lack of segmentation
            // between IT and OT places OT environments at risk.
            if (IsRole(target, ZoneRoles.Ot) && !IsRole(source, ZoneRoles.Ot))
            {
                score += 2;
                reasons.Add("crosses the IT/OT boundary (AA23-278A)");
            }

            // Out-of-band management planes should not be reachable from general
            // networks at all -- a BMC is a permanent, OS-independent host takeover.
            if (service.Category == ServiceCategories.OobManagement &&
                !IsRole(source, ZoneRoles.Management))
            {
                score += 1;
                reasons.Add("out-of-band management plane reachable from a non-management zone");
            }

            var severity = score switch
            {
                >= 4 => Severity.Critical,
                3    => Severity.High,
                2    => Severity.Medium,
                1    => Severity.Low,
                _    => Severity.Informational,
            };

            return new ZoneRiskAssessment
            {
                Severity  = severity,
                RawScore  = score,
                Rationale = string.Join("; ", reasons),
            };
        }

        private static bool IsRole(ZoneDefinition zone, string role) =>
            zone.Role.Equals(role, StringComparison.OrdinalIgnoreCase);
    }
}
