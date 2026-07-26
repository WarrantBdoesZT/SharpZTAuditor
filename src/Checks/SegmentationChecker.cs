using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Checks
{
    /// <summary>
    /// Network segmentation and logging gap checks.
    /// Uses TcpClient for port probing and remote registry for firewall/log config.
    /// No PowerShell, no WMI, no CIM.
    /// </summary>
    public class SegmentationChecker : CheckBase
    {
        private readonly string[] _hosts;

        public SegmentationChecker(AuditConfig config, string[] hosts) : base(config)
        {
            _hosts = hosts;
        }

        public async Task<List<Finding>> RunAsync()
        {
            var findings = new List<Finding>();
            Log($"Checking segmentation across {_hosts.Length} host(s)");

            // Resolve audit workstation IP for cross-segment detection
            var auditOctet = GetLocalOctet();

            // Parallel port probing across all hosts
            var probeTasks = _hosts.Select(h => ProbeAndCheckAsync(h, auditOctet)).ToList();
            foreach (var result in await Task.WhenAll(probeTasks))
                findings.AddRange(result);

            Log($"Complete. Findings: {findings.Count}");
            return findings;
        }

        private async Task<List<Finding>> ProbeAndCheckAsync(string host, string? auditOctet)
        {
            var findings = new List<Finding>();
            Log($"  Probing: {host}");

            var ports = Config.Network.AdminPorts;
            var open  = await ProbePortsAsync(host, ports);

            // Cross-segment detection
            string? targetIP     = null;
            string? targetOctet  = null;
            bool    crossSegment = false;

            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host);
                var ipv4 = addresses.FirstOrDefault(
                    a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                if (ipv4 != null)
                {
                    targetIP    = ipv4.ToString();
                    targetOctet = targetIP.Split('.')[2];
                    crossSegment = auditOctet != null && targetOctet != auditOctet;
                }
            }
            catch { }

            // ── CHECK 1: Cross-segment admin port exposure ────────────────────
            // The protocol list now comes from config.network.crossSegmentAdminPorts.
            // It was previously hardcoded, so customising that config key did nothing.
            var watched = new HashSet<string>(
                Config.Network.CrossSegmentAdminPorts, StringComparer.OrdinalIgnoreCase);

            foreach (var proto in open.Keys.Where(k => open[k]))
            {
                if (!crossSegment || !watched.Contains(proto)) continue;

                if (proto.Equals("RDP", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(MakeFinding(host,
                        "CROSS_SEGMENT_RDP", Severity.High,
                        $"RDP (port {ports[proto]}) is reachable on '{host}' ({targetIP ?? "unknown"}) " +
                        "across network segments. Direct RDP from user networks to server segments " +
                        "bypasses jump server controls.",
                        $"Target={host} ({targetIP}); Protocol=RDP; CrossSegment=True",
                        "Block RDP at the network boundary. " +
                        "Require all RDP sessions to route through a hardened jump server. " +
                        "Implement Just-In-Time RDP access via a PAM solution.",
                        subject: proto));
                }
                else
                {
                    findings.Add(MakeFinding(host,
                        "CROSS_SEGMENT_ADMIN_PORT", Severity.High,
                        $"Admin protocol {proto} (port {ports[proto]}) is reachable on " +
                        $"'{host}' ({targetIP ?? "unknown"}) from a different network segment. " +
                        "This enables lateral movement across segment boundaries.",
                        $"Target={host} ({targetIP}); Protocol={proto}; AuditOctet={auditOctet}; TargetOctet={targetOctet}",
                        "Block SMB (445), WinRM (5985/5986), WMI (135) between user and server " +
                        "VLANs at the firewall level. Use jump servers for cross-segment admin access.",
                        // Subject = protocol. Without it, SMB/WMI/WinRM all share
                        // Host+CheckName and deduplication keeps only ONE of them.
                        subject: proto));
                }
            }

            // ── CHECK 2: Windows Firewall state (via registry) ────────────────
            CheckFirewallState(host, findings);

            // ── CHECK 3: Security log size (via registry) ─────────────────────
            CheckSecurityLogSize(host, findings);

            // ── CHECK 4: WEF subscription configured (via registry) ───────────
            CheckWefConfig(host, findings);

            return findings;
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

        // ── Helpers ───────────────────────────────────────────────────────────

        private static string? GetLocalOctet()
        {
            try
            {
                var host      = Dns.GetHostName();
                var addresses = Dns.GetHostAddresses(host);
                var ipv4 = addresses.FirstOrDefault(
                    a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                      && !IPAddress.IsLoopback(a));
                return ipv4?.ToString().Split('.')[2];
            }
            catch { return null; }
        }
    }
}
