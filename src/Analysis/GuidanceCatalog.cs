using System;
using System.Collections.Generic;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Analysis
{
    /// <summary>
    /// Maps findings to the authoritative NSA and CISA guidance that covers them.
    ///
    /// Held in code rather than a config file: these are citations to stable
    /// government publications, and a malformed JSON file should not be able to
    /// break a report. Everything is in this one type, so updating a citation is a
    /// single-file change.
    ///
    /// URLs are included only where the document location was verified. Where a
    /// publication is cited by title alone, that is deliberate -- an invented URL in
    /// a compliance report is worse than no URL.
    /// </summary>
    public static class GuidanceCatalog
    {
        // ── Source documents ──────────────────────────────────────────────────

        private static GuidanceRef NsaNetworkEnvironmentPillar(string section) => new()
        {
            Source   = "NSA",
            Document = "CSI: Advancing Zero Trust Maturity Throughout the Network and Environment Pillar (March 2024)",
            Section  = section,
            Url      = "https://media.defense.gov/2024/Mar/05/2003405462/-1/-1/0/CSI-ZERO-TRUST-NETWORK-ENVIRONMENT-PILLAR.PDF",
        };

        private static GuidanceRef TopTenMisconfigurations(string section) => new()
        {
            Source   = "CISA/NSA",
            Document = "AA23-278A: Top Ten Cybersecurity Misconfigurations (October 2023)",
            Section  = section,
            Url      = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a",
        };

        private static GuidanceRef ZeroTrustMaturityModel(string section) => new()
        {
            Source   = "CISA",
            Document = "Zero Trust Maturity Model v2.0",
            Section  = section,
            Url      = "https://www.cisa.gov/zero-trust-maturity-model",
        };

        private static GuidanceRef PerformanceGoals(string section) => new()
        {
            Source   = "CISA",
            Document = "Cross-Sector Cybersecurity Performance Goals",
            Section  = section,
            Url      = "https://www.cisa.gov/cross-sector-cybersecurity-performance-goals",
        };

        private static GuidanceRef OutOfBandManagement() => new()
        {
            Source   = "NSA",
            Document = "CSI: Performing Out-of-Band Network Management",
            Section  = "Management traffic must ride a physically or cryptographically " +
                       "separate path from production traffic.",
        };

        private static GuidanceRef TopTenMitigations() => new()
        {
            Source   = "NSA",
            Document = "NSA Top Ten Cybersecurity Mitigation Strategies",
            Section  = "Segment Networks and Deploy Application-Aware Defenses",
        };

        // ── Selection ─────────────────────────────────────────────────────────

        /// <summary>
        /// Picks the guidance that applies to a specific exposure. Deliberately
        /// returns only what is relevant -- a report that cites all ten documents on
        /// every finding teaches the reader to skip the citations.
        /// </summary>
        public static List<GuidanceRef> For(
            ZoneDefinition sourceZone,
            ZoneDefinition targetZone,
            ServiceClassDefinition service,
            PolicyStatus status,
            bool targetZoneUnknown = false)
        {
            var refs = new List<GuidanceRef>();

            if (targetZoneUnknown)
            {
                refs.Add(NsaNetworkEnvironmentPillar(
                    "Data flow mapping is the prerequisite capability for segmentation. " +
                    "Hosts that match no declared zone cannot be segmented because they " +
                    "have not been inventoried."));
                return refs;
            }

            var crossZone = !string.Equals(
                sourceZone.Id, targetZone.Id, StringComparison.OrdinalIgnoreCase);

            // ── The core segmentation citation ────────────────────────────────
            if (status is PolicyStatus.Violation or PolicyStatus.Unenforced)
            {
                refs.Add(TopTenMisconfigurations(
                    "Misconfiguration #4 -- Lack of network segmentation: no security " +
                    "boundaries between user, production and critical system networks " +
                    "allows an actor who has compromised one resource to move laterally " +
                    "uncontested."));
            }

            // ── Macro vs micro segmentation ───────────────────────────────────
            refs.Add(crossZone
                ? NsaNetworkEnvironmentPillar(
                    "Macro-segmentation: control access between distinct network areas so " +
                    "an intrusion is contained to the segment it started in.")
                : NsaNetworkEnvironmentPillar(
                    "Micro-segmentation: isolate endpoints within a segment. " +
                    "Workstation-to-workstation administrative protocols have no " +
                    "legitimate business use in most estates and are the primary " +
                    "ransomware propagation path."));

            // ── Trust-tier crossing is a privilege separation issue ───────────
            if (targetZone.Tier == TrustTier.ControlPlane && sourceZone.Tier > TrustTier.ControlPlane)
            {
                refs.Add(TopTenMisconfigurations(
                    "Misconfiguration #2 -- Improper separation of user/administrator " +
                    "privilege. Administrative protocols reaching the identity control " +
                    "plane from a lower tier collapses the tier model."));
            }

            // ── IT/OT ─────────────────────────────────────────────────────────
            if (IsRole(targetZone, ZoneRoles.Ot) && !IsRole(sourceZone, ZoneRoles.Ot))
            {
                refs.Add(TopTenMisconfigurations(
                    "Misconfiguration #4 (IT/OT): lack of segmentation between IT and OT " +
                    "environments places OT at risk. Traffic should traverse a documented " +
                    "DMZ or conduit, never a flat path."));
                refs.Add(PerformanceGoals(
                    "Segment networks according to trust boundaries and platform type " +
                    "(IT, IoT, OT, mobile, guest), permitting only required communications " +
                    "between segments."));
            }

            // ── Out-of-band management plane ──────────────────────────────────
            if (service.Category == ServiceCategories.OobManagement &&
                !IsRole(sourceZone, ZoneRoles.Management))
            {
                refs.Add(OutOfBandManagement());
            }

            // ── Cleartext ─────────────────────────────────────────────────────
            if (service.Category == ServiceCategories.CleartextLegacy)
            {
                refs.Add(ZeroTrustMaturityModel(
                    "Networks pillar -> Network Encryption. Cleartext protocols crossing a " +
                    "segment boundary expose credentials and data to anyone on the path."));
            }

            // ── Always anchor to the maturity model ───────────────────────────
            refs.Add(ZeroTrustMaturityModel(
                "Networks pillar -> Network Segmentation. Advanced maturity requires " +
                "ingress/egress micro-perimeters and service-specific interconnections; " +
                "optimal requires distributed micro-perimeters around application workflows."));

            return refs;
        }

        /// <summary>Guidance for the report as a whole, shown once in the summary.</summary>
        public static List<GuidanceRef> ProgramLevel() => new()
        {
            TopTenMitigations(),
            PerformanceGoals(
                "Logically segment enterprise and production networks according to trust " +
                "boundaries and platform type, permitting only required communications."),
            NsaNetworkEnvironmentPillar(
                "Assume breaches occur inside the network. Employ controls that logically " +
                "and physically segment, isolate and control access through granular " +
                "policy restrictions."),
            ZeroTrustMaturityModel("Networks pillar -- overall maturity target."),
        };

        /// <summary>Guidance for the internal-monitoring gap that segmentation depends on.</summary>
        public static List<GuidanceRef> ForMonitoringGap() => new()
        {
            TopTenMisconfigurations(
                "Misconfiguration #3 -- Insufficient internal network monitoring. " +
                "A boundary that blocks but does not log gives the SOC no visibility of " +
                "attempted lateral movement."),
            ZeroTrustMaturityModel(
                "Networks pillar -> Network Traffic Management and Visibility & Analytics."),
        };

        private static bool IsRole(ZoneDefinition zone, string role) =>
            zone.Role.Equals(role, StringComparison.OrdinalIgnoreCase);
    }
}
