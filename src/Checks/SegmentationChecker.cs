using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using ZeroTrustAuditor.Config;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Checks
{
    /// <summary>
    /// Network segmentation and logging gap checks.
    /// Uses TcpClient for port probing and remote registry for firewall/log config.
    /// No PowerShell, no WMI, no CIM.
    ///
    /// Segment boundaries come from the declared zone map (zones.json), resolved by
    /// CIDR longest-prefix match. If no zone map is supplied, cross-zone analysis is
    /// SKIPPED and reported as a gap rather than guessed at -- the previous
    /// third-octet heuristic produced confident findings that were wrong in both
    /// directions, which is worse than producing none.
    /// </summary>
    public class SegmentationChecker : CheckBase
    {
        private readonly string[] _hosts;
        private readonly SegmentationContext _segmentation;

        public SegmentationChecker(
            AuditConfig config, string[] hosts, SegmentationContext? segmentation = null)
            : base(config)
        {
            _hosts        = hosts;
            _segmentation = segmentation ?? new SegmentationContext();
        }

        public async Task<List<Finding>> RunAsync()
        {
            var findings = new List<Finding>();
            Log($"Checking segmentation across {_hosts.Length} host(s)");

            if (!_segmentation.IsConfigured)
            {
                Log("  No zone map configured -- cross-zone analysis skipped.");
                findings.Add(MakeFinding(
                    Config.Reporting.OrganizationName.Length > 0
                        ? Config.Reporting.OrganizationName
                        : "(environment)",
                    "ZONE_MAP_NOT_CONFIGURED", Severity.Medium,
                    "No zone map was supplied, so cross-zone exposure could not be assessed. " +
                    "Segment boundaries cannot be inferred from IP addresses alone -- a /16 and " +
                    "a /24 sharing an octet are not the same segment. Host-level checks below " +
                    "still ran; the absence of cross-zone findings is NOT evidence of good " +
                    "segmentation.",
                    "zones.json absent or empty; ZoneResolver has no CIDR ranges.",
                    "Copy zones.example.json to zones.json and declare your network segments " +
                    "with their CIDRs and trust tiers, then re-run. See REARCHITECTURE.md.",
                    subject: "zones.json"));
            }
            else
            {
                Log($"  Zone map: {_segmentation.Zones.Zones.Count} zone(s), " +
                    $"{_segmentation.Zones.RangeCount} CIDR range(s)");
            }

            // Parallel port probing across all hosts
            var probeTasks = _hosts.Select(ProbeAndCheckAsync).ToList();
            foreach (var result in await Task.WhenAll(probeTasks))
                findings.AddRange(result);

            Log($"Complete. Findings: {findings.Count}");
            return findings;
        }

        private async Task<List<Finding>> ProbeAndCheckAsync(string host)
        {
            var findings = new List<Finding>();
            Log($"  Probing: {host}");

            var ports = Config.Network.AdminPorts;
            var open  = await ProbePortsAsync(host, ports);

            // ── CHECK 1: Cross-ZONE admin port exposure ───────────────────────
            // Zone membership comes from declared CIDRs, and the vantage address is
            // the one the OS would actually route from to THIS target -- not an
            // arbitrary NIC picked by enumeration order.
            if (_segmentation.IsConfigured)
                await CheckCrossZoneExposureAsync(host, open, ports, findings);

            // ── CHECK 2: Windows Firewall state (via registry) ────────────────
            CheckFirewallState(host, findings);

            // ── CHECK 3: Security log size (via registry) ─────────────────────
            CheckSecurityLogSize(host, findings);

            // ── CHECK 4: WEF subscription configured (via registry) ───────────
            CheckWefConfig(host, findings);

            return findings;
        }

        // ── CHECK 1: Cross-zone exposure ──────────────────────────────────────

        private async Task CheckCrossZoneExposureAsync(
            string host, Dictionary<string, bool> open,
            Dictionary<string, int> ports, List<Finding> findings)
        {
            var targetIp = await ResolveAsync(host);
            if (targetIp == null)
            {
                Log($"  {host} did not resolve to an IP -- zone cannot be determined.");
                return;
            }

            var vantageIp = LocalAddressProvider.ForTarget(targetIp)
                         ?? LocalAddressProvider.Primary();

            if (vantageIp == null)
            {
                Log($"  Could not determine the local address used to reach {host}.");
                return;
            }

            var targetKnown  = _segmentation.Zones.TryResolve(targetIp, out var targetZone);
            var vantageKnown = _segmentation.Zones.TryResolve(vantageIp, out var vantageZone);

            if (!vantageKnown)
            {
                // Without knowing where we are standing, "cross-zone" is meaningless.
                findings.Add(MakeFinding(host,
                    "VANTAGE_ZONE_UNKNOWN", Severity.Medium,
                    $"The audit host's own address {vantageIp} matches no declared zone, so " +
                    "cross-zone findings for this run cannot be attributed to a source segment. " +
                    "Every result below is unanchored.",
                    $"VantageIp={vantageIp}; TargetIp={targetIp}",
                    "Add the audit workstation's subnet to zones.json so results can be " +
                    "attributed to a source zone.",
                    subject: vantageIp.ToString()));
                return;
            }

            if (!targetKnown)
            {
                findings.Add(MakeFinding(host,
                    "TARGET_ZONE_UNKNOWN", Severity.Low,
                    $"'{host}' ({targetIp}) matches no declared zone CIDR. It is being treated as " +
                    "untrusted for scoring. An unmapped host is a data-flow-mapping gap: NSA's " +
                    "Network and Environment pillar names data flow mapping as the capability " +
                    "segmentation depends on.",
                    $"TargetIp={targetIp}; VantageZone={vantageZone.Id}",
                    "Add this host's subnet to zones.json, or remove the host from scope if it " +
                    "is not part of the estate.",
                    subject: targetIp.ToString()));
            }

            // Same zone is not automatically safe, but it is not a BOUNDARY failure.
            if (string.Equals(vantageZone.Id, targetZone.Id, StringComparison.OrdinalIgnoreCase))
                return;

            var watched = new HashSet<string>(
                Config.Network.CrossSegmentAdminPorts, StringComparer.OrdinalIgnoreCase);

            var matchedRange = _segmentation.Zones.MatchingRange(targetIp);

            foreach (var proto in open.Keys.Where(k => open[k]))
            {
                if (!watched.Contains(proto)) continue;
                if (!ports.TryGetValue(proto, out var port)) continue;

                // Map the probed protocol onto a catalog service class so severity
                // reflects what the service actually is.
                var service = _segmentation.Services.ByPort(port).FirstOrDefault()
                              ?? new ServiceClassDefinition
                              {
                                  Id       = proto,
                                  Ports    = new List<int> { port },
                                  Risk     = ServiceRisk.High,
                                  Category = ServiceCategories.RemoteAdmin,
                              };

                var risk = ZonePairRisk.Assess(vantageZone, targetZone, service);

                var isRdp     = proto.Equals("RDP", StringComparison.OrdinalIgnoreCase);
                var checkName = isRdp ? "CROSS_ZONE_RDP" : "CROSS_ZONE_ADMIN_PORT";

                var remediation = isRdp
                    ? $"Deny {vantageZone.Id} -> {targetZone.Id} on tcp/{port} at the boundary " +
                      "firewall. Route RDP through a hardened jump host in the management zone " +
                      "and gate it with Just-In-Time access."
                    : $"Deny {vantageZone.Id} -> {targetZone.Id} on tcp/{port} ({service.Id}) at " +
                      "the boundary firewall. Administrative protocols should originate only " +
                      "from the management zone.";

                findings.Add(MakeFinding(host,
                    checkName, risk.Severity,
                    $"{service.Id} (tcp/{port}) on '{host}' ({targetIp}) is reachable from zone " +
                    $"'{vantageZone.DisplayName}' into zone '{targetZone.DisplayName}'. " +
                    $"Scored {risk.Severity}: {risk.Rationale}.",
                    $"VantageZone={vantageZone.Id} ({vantageIp}); " +
                    $"TargetZone={targetZone.Id} ({targetIp}" +
                    (matchedRange != null ? $" in {matchedRange}" : "") + "); " +
                    $"Service={service.Id}; Port=tcp/{port}; " +
                    $"TierDelta={vantageZone.Tier - targetZone.Tier}; RiskScore={risk.RawScore}",
                    remediation,
                    subject: $"{vantageZone.Id}->{targetZone.Id}|{service.Id}"));
            }
        }

        private static async Task<IPAddress?> ResolveAsync(string host)
        {
            if (IPAddress.TryParse(host, out var literal)) return literal;

            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host);
                return addresses.FirstOrDefault(
                           a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    ?? addresses.FirstOrDefault(
                           a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);
            }
            catch
            {
                return null;
            }
        }

        // ── CHECK 2: Firewall state ───────────────────────────────────────────

        private void CheckFirewallState(string host, List<Finding> findings)
        {
            // Firewall profiles: Domain=1, Private=2, Public=4
            var profileKeys = new Dictionary<string, string>
            {
                ["Domain"]  = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                ["Private"] = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                ["Public"]  = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
            };

            foreach (var kv in profileKeys)
            {
                var profileName = kv.Key;
                var regKey      = kv.Value;

                var enabled = GetRemoteRegInt(host, regKey, "EnableFirewall");
                if (enabled == null) continue; // key not readable

                if (enabled == 0)
                {
                    findings.Add(MakeFinding(host,
                        "WINDOWS_FIREWALL_DISABLED", Severity.High,
                        $"Windows Firewall '{profileName}' profile is DISABLED on '{host}'. " +
                        "Host-based firewall is a critical defense-in-depth layer.",
                        $"Profile={profileName}; EnableFirewall=0; " +
                        $"Key=HKLM\\{regKey}\\EnableFirewall",
                        "Re-enable Windows Firewall for all profiles via GPO. " +
                        "Never disable host firewall -- use explicit inbound rules instead.",
                        // Subject = profile. All three profiles previously shared
                        // Host+CheckName, so deduplication reported only one of them.
                        subject: profileName));
                }

                // Check log settings. Only report when we positively established that
                // logging is off -- an unreadable value used to be reported as disabled,
                // fabricating a Medium finding per profile per unreachable host.
                var logStatus = TryGetRemoteRegInt(
                    host, regKey + "\\Logging", "LogDroppedPackets", out var logDropped);

                if (logStatus == RegistryReadStatus.Unreadable) continue;

                if (logStatus == RegistryReadStatus.Absent || logDropped == 0)
                {
                    findings.Add(MakeFinding(host,
                        "FIREWALL_LOGGING_DISABLED", Severity.Medium,
                        $"Windows Firewall '{profileName}' profile on '{host}' does not log dropped packets. " +
                        "Lateral movement attempts and port scans are invisible to the SOC.",
                        $"Profile={profileName}; LogDroppedPackets=" +
                        (logStatus == RegistryReadStatus.Absent ? "<not set>" : logDropped.ToString()),
                        "Enable firewall drop logging via GPO or Set-NetFirewallProfile. " +
                        "Forward logs to SIEM via Windows Event Forwarding. " +
                        "Set log file size to at least 32768 KB.",
                        subject: profileName));
                }
            }
        }

        // ── CHECK 3: Security log size ────────────────────────────────────────

        private void CheckSecurityLogSize(string host, List<Finding> findings)
        {
            var maxSize = GetRemoteReg(host,
                @"SYSTEM\CurrentControlSet\Services\EventLog\Security",
                "MaxSize");

            if (maxSize == null) return;

            long sizeBytes;
            try { sizeBytes = Convert.ToInt64(maxSize); }
            catch { return; }

            if (sizeBytes >= Config.Thresholds.SecurityLogMinSizeBytes) return;

            var sizeMb = sizeBytes / (1024 * 1024);
            findings.Add(MakeFinding(host,
                "SECURITY_LOG_TOO_SMALL", Severity.Low,
                $"Security event log on '{host}' is only {sizeMb}MB. " +
                "A small log rotates quickly, potentially losing evidence of " +
                "brute-force or pass-the-hash activity.",
                $"SecurityLogMaxSize={sizeMb}MB (recommended minimum: 1024MB for servers)",
                "Set Security log maximum size to at least 1 GB via GPO: " +
                "Computer Configuration -> Windows Settings -> Security Settings -> " +
                "Event Log -> Maximum security log size. " +
                "Set log full behavior to archive rather than overwrite."));
        }

        // ── CHECK 4: WEF subscription ─────────────────────────────────────────

        private void CheckWefConfig(string host, List<Finding> findings)
        {
            // WEF subscription manager key presence indicates forwarding is configured
            var status = TryGetRemoteReg(host,
                @"SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager",
                "1", out _);

            if (status == RegistryReadStatus.Read) return; // WEF is configured

            // Could not query the host at all -- "not configured" is not a conclusion
            // we are entitled to draw, and asserting it fabricates a finding per host.
            if (status == RegistryReadStatus.Unreadable)
            {
                Log($"  {host} WEF state undetermined (registry unreadable) -- not reporting.");
                return;
            }

            findings.Add(MakeFinding(host,
                "WEF_NOT_CONFIGURED", Severity.Medium,
                $"Windows Event Forwarding (WEF) is not configured on '{host}'. " +
                "Without centralised log collection, attackers can clear local logs " +
                "and destroy forensic evidence.",
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager: absent",
                "Deploy WEF via GPO: configure a Windows Event Collector and push " +
                "subscription config to all endpoints. " +
                "Forward Security, System, and Sysmon events to your SIEM. " +
                "Alternatively deploy a SIEM agent (Splunk UF, Elastic Agent, Sentinel MMA)."));
        }

    }
}
