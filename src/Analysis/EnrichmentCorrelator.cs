using System;
using System.Collections.Generic;
using System.Linq;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Analysis
{
    /// <summary>
    /// One host-configuration weakness that makes a reachable service worse.
    /// </summary>
    public sealed class EnrichmentRule
    {
        /// <summary>Legacy CheckName emitted by the AD / protocol / share modules.</summary>
        public string CheckName { get; init; } = string.Empty;

        /// <summary>
        /// Service classes this weakness actually amplifies. Empty means any
        /// reachable service -- used for host-wide facts such as a disabled firewall.
        /// </summary>
        public string[] AppliesTo { get; init; } = Array.Empty<string>();

        /// <summary>Plain-English reason, written into the finding.</summary>
        public string Rationale { get; init; } = string.Empty;
    }

    /// <summary>
    /// Folds the legacy modules in as an ENRICHMENT tier.
    ///
    /// Before this, AdAuditor, ProtocolProbe, ShareAuditor and LateralPathAnalyzer
    /// were five co-equal modules producing standalone findings, and the correlation
    /// engine that was supposed to relate them grouped on a host key that
    /// host-scoped and domain-scoped checks never shared -- so four of six shipped
    /// rules could not fire at all.
    ///
    /// Reachability is now the spine. A host weakness only matters if an attacker
    /// can reach the service it affects, so these facts are attached to the specific
    /// reachable path they make worse, and escalate its severity. A reachable 445 is
    /// bad; a reachable 445 with SMB signing disabled on a host whose local admin
    /// account is shared across twenty machines is a different finding entirely.
    ///
    /// The legacy findings are still reported in their own right -- this adds
    /// context, it does not swallow them.
    /// </summary>
    public static class EnrichmentCorrelator
    {
        private const string Smb   = "SMB";
        private const string Rdp   = "RDP";
        private const string WinRm = "WINRM_HTTP";
        private const string WinRmS= "WINRM_HTTPS";
        private const string Rpc   = "RPC_EPM";

        internal static readonly EnrichmentRule[] Rules =
        {
            new()
            {
                CheckName = "SMB_SIGNING_DISABLED",
                AppliesTo = new[] { Smb },
                Rationale = "SMB signing is not required on this host, so a reachable 445 " +
                            "is a viable NTLM relay target -- an attacker can coerce and " +
                            "relay authentication to it without ever knowing a password.",
            },
            new()
            {
                CheckName = "NTLM_V1_ENABLED",
                AppliesTo = new[] { Smb, WinRm, WinRmS },
                Rationale = "The host accepts NTLMv1, which is crackable in seconds once " +
                            "captured. Reachability makes capture straightforward.",
            },
            new()
            {
                CheckName = "RDP_NLA_DISABLED",
                AppliesTo = new[] { Rdp },
                Rationale = "Network Level Authentication is disabled, so the logon screen " +
                            "loads before credentials are checked. A reachable 3389 without " +
                            "NLA is directly brute-forceable.",
            },
            new()
            {
                CheckName = "RDP_WEAK_ENCRYPTION",
                AppliesTo = new[] { Rdp },
                Rationale = "RDP negotiates weak encryption on this host, so a reachable " +
                            "session is interceptable.",
            },
            new()
            {
                CheckName = "WINRM_UNENCRYPTED",
                AppliesTo = new[] { WinRm },
                Rationale = "WinRM permits unencrypted traffic, so credentials on a " +
                            "reachable 5985 are readable on the wire.",
            },
            new()
            {
                CheckName = "LAPS_NOT_DEPLOYED",
                AppliesTo = new[] { Smb, Rdp, WinRm, WinRmS, Rpc },
                Rationale = "LAPS is not deployed, so this host very likely shares its local " +
                            "Administrator password with every other machine from the same " +
                            "image. Reaching one is reaching all of them.",
            },
            new()
            {
                CheckName = "LOCAL_ADMIN_OVERLAP",
                AppliesTo = new[] { Smb, Rdp, WinRm, WinRmS, Rpc },
                Rationale = "A single account holds local Administrator on this host and " +
                            "others. Compromising this one reachable service pivots to every " +
                            "host that account administers.",
            },
            new()
            {
                CheckName = "DOMAIN_GROUP_LOCAL_ADMIN",
                AppliesTo = new[] { Smb, Rdp, WinRm, WinRmS },
                Rationale = "A broad domain group grants local Administrator here, so the set " +
                            "of principals who can use this reachable service is far larger " +
                            "than the named admins.",
            },
            new()
            {
                CheckName = "OPEN_SMB_SHARE_WRITE",
                AppliesTo = new[] { Smb },
                Rationale = "A writable share is exposed on this host, giving a reachable 445 " +
                            "both an execution and a persistence path.",
            },
            new()
            {
                CheckName = "ADMIN_SHARE_OVERPERMISSIVE",
                AppliesTo = new[] { Smb },
                Rationale = "An administrative share grants write access beyond " +
                            "Administrators, which turns reachability into direct code " +
                            "execution.",
            },
            new()
            {
                CheckName = "WINDOWS_FIREWALL_DISABLED",
                AppliesTo = Array.Empty<string>(),   // host-wide
                Rationale = "The host firewall is disabled, so this host offers no local " +
                            "defence-in-depth behind the network boundary that failed.",
            },
            new()
            {
                CheckName = "DCOM_DEFAULT_LAUNCH_PERMISSION",
                AppliesTo = new[] { Rpc },
                Rationale = "DCOM launch permissions are undefined, leaving the built-in " +
                            "default that permits broad activation over a reachable RPC path.",
            },
        };

        /// <summary>
        /// Attaches host weaknesses to the reachable paths they amplify and escalates
        /// severity accordingly. Returns the number of findings enriched.
        /// </summary>
        public static int Apply(
            SegmentationAnalysis analysis, IReadOnlyList<Finding> legacyFindings)
        {
            if (legacyFindings.Count == 0) return 0;

            var index   = BuildHostIndex(legacyFindings);
            var enriched = 0;

            foreach (var finding in analysis.Findings)
            {
                // Only paths an attacker can actually use are worth amplifying.
                // A weakness behind a correctly filtered boundary is a finding in its
                // own right, not an escalation of a path that does not exist.
                if (finding.Verdict != ReachabilityVerdict.Open) continue;

                var applied = false;

                foreach (var rule in Rules)
                {
                    if (rule.AppliesTo.Length > 0 &&
                        !rule.AppliesTo.Contains(finding.ServiceClass, StringComparer.OrdinalIgnoreCase))
                        continue;

                    var matches = LookupForHost(index, finding, rule.CheckName);
                    if (matches.Count == 0) continue;

                    foreach (var legacy in matches)
                        if (!finding.RelatedFindingIds.Contains(legacy.Id))
                            finding.RelatedFindingIds.Add(legacy.Id);

                    finding.EnrichmentNotes.Add(rule.Rationale);
                    applied = true;
                }

                if (!applied) continue;

                enriched++;

                // Escalate once, however many weaknesses stacked. Repeated bumps
                // would let a pile of medium issues outrank a genuine critical.
                finding.Severity  = Escalate(finding.Severity);
                finding.RiskScore = Math.Min(10.0, finding.RiskScore + 1.5);

                finding.Description +=
                    $" Host context ({finding.EnrichmentNotes.Count} finding(s) on this " +
                    "endpoint) raises the severity of this reachable path.";
            }

            return enriched;
        }

        private static Severity Escalate(Severity severity) => severity switch
        {
            Severity.Informational => Severity.Low,
            Severity.Low           => Severity.Medium,
            Severity.Medium        => Severity.High,
            _                      => Severity.Critical,
        };

        // ── Host matching ─────────────────────────────────────────────────────

        /// <summary>
        /// Legacy findings are keyed by hostname; segmentation findings carry both a
        /// hostname and an IP. Index by every identifier a finding touches, including
        /// AffectedHosts, so a domain-anchored finding such as LOCAL_ADMIN_OVERLAP
        /// still attaches to the individual hosts it actually spans.
        /// </summary>
        private static Dictionary<string, List<Finding>> BuildHostIndex(
            IReadOnlyList<Finding> legacyFindings)
        {
            var index = new Dictionary<string, List<Finding>>(StringComparer.OrdinalIgnoreCase);

            void Add(string key, Finding finding)
            {
                if (string.IsNullOrWhiteSpace(key)) return;
                if (!index.TryGetValue(key, out var list))
                    index[key] = list = new List<Finding>();
                if (!list.Contains(finding)) list.Add(finding);
            }

            foreach (var finding in legacyFindings)
            {
                Add(finding.Host, finding);
                Add(ShortName(finding.Host), finding);

                foreach (var host in finding.AffectedHosts)
                {
                    Add(host, finding);
                    Add(ShortName(host), finding);
                }
            }

            return index;
        }

        private static List<Finding> LookupForHost(
            Dictionary<string, List<Finding>> index,
            SegmentationFinding finding, string checkName)
        {
            var keys = new[]
            {
                finding.TargetHostname,
                ShortName(finding.TargetHostname),
                finding.TargetIp,
            };

            var results = new List<Finding>();

            foreach (var key in keys)
            {
                if (string.IsNullOrWhiteSpace(key)) continue;
                if (!index.TryGetValue(key!, out var candidates)) continue;

                foreach (var candidate in candidates)
                {
                    if (!candidate.CheckName.Equals(checkName, StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (!results.Contains(candidate)) results.Add(candidate);
                }
            }

            return results;
        }

        /// <summary>SRV01.corp.local and SRV01 are the same machine.</summary>
        internal static string ShortName(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return string.Empty;
            var dot = host.IndexOf('.');
            return dot > 0 ? host[..dot] : host;
        }
    }
}
