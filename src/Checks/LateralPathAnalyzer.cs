using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Checks
{
    /// <summary>
    /// Lateral movement path analysis.
    /// Uses System.DirectoryServices.AccountManagement for local group queries
    /// and remote registry for LAPS detection -- no PowerShell required.
    /// </summary>
    public class LateralPathAnalyzer : CheckBase
    {
        private readonly string[] _hosts;
        private readonly string   _domain;

        public LateralPathAnalyzer(AuditConfig config, string[] hosts, string domain)
            : base(config)
        {
            _hosts  = hosts;
            _domain = domain;
        }

        public async Task<List<Finding>> RunAsync()
        {
            var findings     = new List<Finding>();
            var adminOverlap = new Dictionary<string, List<string>>(
                StringComparer.OrdinalIgnoreCase); // account -> [hosts]

            Log($"Analyzing {_hosts.Length} host(s)");

            var tasks = _hosts.Select(h => AnalyzeHostAsync(h, adminOverlap)).ToList();
            var hostResults = await Task.WhenAll(tasks);
            foreach (var r in hostResults) findings.AddRange(r);

            // Cross-host admin overlap check (requires all hosts to be analyzed first)
            CheckAdminOverlap(adminOverlap, findings);

            Log($"Complete. Findings: {findings.Count}");
            return findings;
        }

        private async Task<List<Finding>> AnalyzeHostAsync(
            string host, Dictionary<string, List<string>> adminOverlap)
        {
            var findings = new List<Finding>();
            Log($"  Analyzing: {host}");

            await Task.Run(() =>
            {
                CheckLocalAdminGroup(host, adminOverlap, findings);
                CheckRdpGroup(host, findings);
                CheckWinRmGroup(host, findings);
                CheckLaps(host, findings);
            });

            return findings;
        }

        // ── CHECK 1: Local Administrators membership ──────────────────────────

        private void CheckLocalAdminGroup(string host,
            Dictionary<string, List<string>> adminOverlap, List<Finding> findings)
        {
            try
            {
                using var ctx = new PrincipalContext(ContextType.Machine, host);
                using var group = GroupPrincipal.FindByIdentity(ctx, "Administrators");
                if (group == null) return;

                var expectedGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    { "Domain Admins", "Enterprise Admins" };

                foreach (var member in group.GetMembers(recursive: false))
                {
                    try
                    {
                        var name = member.SamAccountName ?? string.Empty;
                        var isDomainMember = member.Context?.ContextType == ContextType.Domain
                            || (member.DistinguishedName?.Contains(_domain,
                                StringComparison.OrdinalIgnoreCase) ?? false);

                        if (!isDomainMember) { member.Dispose(); continue; }

                        // Track for overlap analysis
                        lock (adminOverlap)
                        {
                            if (!adminOverlap.ContainsKey(name))
                                adminOverlap[name] = new List<string>();
                            adminOverlap[name].Add(host);
                        }

                        // Flag domain groups (not expected ones)
                        if (member is GroupPrincipal gp &&
                            !expectedGroups.Contains(name))
                        {
                            findings.Add(MakeFinding(host, "DOMAIN_GROUP_LOCAL_ADMIN",
                                Severity.High,
                                $"Domain group '{name}' is in the local Administrators group on '{host}'. " +
                                "All members of this group inherit local admin rights.",
                                $"LocalGroup=Administrators; Member={name}; Type=Group",
                                "Remove broad domain groups from local Administrators. " +
                                "Use LAPS for local admin password management. " +
                                "Use PAW model with dedicated per-tier admin accounts.",
                                subject: name));
                        }
                    }
                    catch { }
                    finally { member.Dispose(); }
                }
            }
            catch (Exception ex)
            {
                Log($"  {host} local admin check failed: {ex.Message}");
                findings.Add(MakeFinding(host, "HOST_UNREACHABLE", Severity.Informational,
                    $"Host '{host}' was unreachable for local admin analysis.",
                    $"Error: {ex.Message}",
                    "Verify host is online and the audit account has access via AccountManagement API."));
            }
        }

        // ── CHECK 2: Remote Desktop Users breadth ────────────────────────────

        private void CheckRdpGroup(string host, List<Finding> findings)
        {
            try
            {
                using var ctx = new PrincipalContext(ContextType.Machine, host);
                using var group = GroupPrincipal.FindByIdentity(ctx, "Remote Desktop Users");
                if (group == null) return;

                var domainMembers = new List<string>();
                foreach (var member in group.GetMembers(recursive: false))
                {
                    try
                    {
                        if (member.Context?.ContextType == ContextType.Domain)
                            domainMembers.Add(member.SamAccountName ?? member.Name ?? "unknown");
                    }
                    catch { }
                    finally { member.Dispose(); }
                }

                if (domainMembers.Count == 0) return;

                findings.Add(MakeFinding(host, "BROAD_RDP_ACCESS", Severity.Medium,
                    $"The Remote Desktop Users group on '{host}' contains " +
                    $"{domainMembers.Count} domain account(s)/group(s). " +
                    "In a Zero Trust model, RDP access should be limited to specific admin accounts via JIT.",
                    $"RemoteDesktopUsers members: {string.Join("; ", domainMembers)}",
                    "Remove broad domain groups from Remote Desktop Users. " +
                    "Implement JIT RDP access via PIM or a PAM solution. " +
                    "Route all RDP through a jump server -- no direct RDP from user workstations."));
            }
            catch (Exception ex)
            {
                Log($"  {host} RDP group check failed: {ex.Message}");
            }
        }

        // ── CHECK 3: Remote Management Users breadth ──────────────────────────

        private void CheckWinRmGroup(string host, List<Finding> findings)
        {
            try
            {
                using var ctx = new PrincipalContext(ContextType.Machine, host);
                using var group = GroupPrincipal.FindByIdentity(ctx, "Remote Management Users");
                if (group == null) return;

                var domainGroups = new List<string>();
                foreach (var member in group.GetMembers(recursive: false))
                {
                    try
                    {
                        if (member is GroupPrincipal &&
                            member.Context?.ContextType == ContextType.Domain)
                            domainGroups.Add(member.SamAccountName ?? member.Name ?? "unknown");
                    }
                    catch { }
                    finally { member.Dispose(); }
                }

                foreach (var grp in domainGroups)
                {
                    findings.Add(MakeFinding(host, "BROAD_WINRM_ACCESS", Severity.Medium,
                        $"Domain group '{grp}' is in Remote Management Users on '{host}'. " +
                        "WinRM access for broad groups allows lateral movement via PowerShell remoting.",
                        $"RemoteManagementUsers member={grp}; Type=Group",
                        "Restrict Remote Management Users to named admin accounts. " +
                        "Use JEA (Just Enough Administration) to constrain WinRM-accessible users.",
                        subject: grp));
                }
            }
            catch (Exception ex)
            {
                Log($"  {host} WinRM group check failed: {ex.Message}");
            }
        }

        // ── CHECK 4: LAPS deployment ──────────────────────────────────────────

        private void CheckLaps(string host, List<Finding> findings)
        {
            // Look in all three places LAPS can be configured. The policy keys matter:
            // a GPO-managed Windows LAPS deployment writes under Policies\LAPS, so
            // checking only the local-state key reports correctly-configured estates
            // as non-compliant.
            var probes = new[]
            {
                (Key: @"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config", Value: "BackupDirectory"),
                (Key: @"SOFTWARE\Microsoft\Policies\LAPS",                     Value: "BackupDirectory"),
                (Key: @"SOFTWARE\Policies\Microsoft Services\AdmPwd",          Value: "AdmPwdEnabled"),
            };

            var anyUnreadable = false;

            foreach (var probe in probes)
            {
                var status = TryGetRemoteReg(host, probe.Key, probe.Value, out _);

                // LAPS is configured somewhere -- nothing to report.
                if (status == RegistryReadStatus.Read) return;
                if (status == RegistryReadStatus.Unreadable) anyUnreadable = true;
            }

            // Every probe failed to READ rather than confirming absence. We cannot tell
            // a host without LAPS from one we simply could not query, and reporting a
            // High finding here fabricates one per unreachable host. The orchestrator
            // already emits REMOTE_REGISTRY_UNREACHABLE explaining the gap.
            if (anyUnreadable)
            {
                Log($"  {host} LAPS state undetermined (registry unreadable) -- not reporting.");
                return;
            }

            findings.Add(MakeFinding(host, "LAPS_NOT_DEPLOYED", Severity.High,
                $"LAPS (Local Administrator Password Solution) does not appear to be deployed on '{host}'. " +
                "Without LAPS, all hosts built from the same image share the same local admin password. " +
                "One compromised host yields local admin on all peers.",
                $"LAPS registry key absent on {host}",
                "Deploy Microsoft LAPS or Windows LAPS (built-in on Windows Server 2019+ and Windows 11). " +
                "Configure 30-day maximum password age. " +
                "Restrict ms-Mcs-AdmPwd read access to delegated admin groups only."));
        }

        // ── Cross-host admin overlap ───────────────────────────────────────────

        private void CheckAdminOverlap(
            Dictionary<string, List<string>> adminOverlap, List<Finding> findings)
        {
            var minHosts      = Config.Thresholds.LocalAdminOverlapMinHosts;
            var criticalHosts = Config.Thresholds.LocalAdminOverlapCriticalHosts;

            foreach (var kv in adminOverlap)
            {
                var account = kv.Key;

                // Distinct: a host enumerated twice must not inflate the overlap count
                // and push the finding into a higher severity band.
                var hosts = kv.Value
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(h => h, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (hosts.Count < minHosts) continue;

                var severity = hosts.Count >= criticalHosts
                    ? Severity.Critical
                    : hosts.Count >= 3 ? Severity.High : Severity.Medium;

                findings.Add(MakeFinding(
                    _domain, "LOCAL_ADMIN_OVERLAP", severity,
                    $"Account '{account}' has local Administrator rights on {hosts.Count} hosts. " +
                    "Compromise of this single account enables lateral movement to all of them.",
                    $"Account={account}; Hosts={string.Join(", ", hosts)}",
                    "Implement LAPS to ensure unique local admin passwords per host. " +
                    "Remove shared admin accounts. " +
                    "Use tiered administration: accounts used on tier-1 servers must not " +
                    "have local admin on tier-2 workstations.",
                    // Subject keeps one finding per account instead of collapsing every
                    // overlapping account in the domain into a single row.
                    subject: account,
                    // AffectedHosts is what lets host-scoped correlation rules match this
                    // domain-anchored finding against per-host findings such as
                    // SMB_SIGNING_DISABLED on the very hosts the account spans.
                    affectedHosts: hosts));
            }
        }
    }
}
