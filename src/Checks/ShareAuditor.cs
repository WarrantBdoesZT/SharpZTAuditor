using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Checks
{
    /// <summary>
    /// SMB share and NTFS ACL misconfiguration checks.
    /// Uses System.IO and System.Security.AccessControl -- no PowerShell, no WMI.
    /// Reads share ACLs via UNC path (\\host\share) and NTFS ACLs via GetAccessControl().
    /// </summary>
    public class ShareAuditor : CheckBase
    {
        private readonly string[] _hosts;
        private readonly string   _domain;

        // Well-known admin shares to skip from the broad ACL check
        private static readonly HashSet<string> AdminShares = new(StringComparer.OrdinalIgnoreCase)
            { "ADMIN$", "C$", "D$", "E$", "IPC$", "PRINT$", "print$" };

        public ShareAuditor(AuditConfig config, string[] hosts, string domain) : base(config)
        {
            _hosts  = hosts;
            _domain = domain;
        }

        public async Task<List<Finding>> RunAsync()
        {
            var findings = new List<Finding>();
            Log($"Auditing shares on {_hosts.Length} host(s)");

            var tasks = _hosts.Select(h => AuditHostAsync(h)).ToList();
            foreach (var result in await Task.WhenAll(tasks))
                findings.AddRange(result);

            // Domain-level: SYSVOL check via FQDN
            findings.AddRange(CheckSysvol());

            Log($"Complete. Findings: {findings.Count}");
            return findings;
        }

        private async Task<List<Finding>> AuditHostAsync(string host)
        {
            var findings = new List<Finding>();
            Log($"  Auditing shares on: {host}");

            await Task.Run(() =>
            {
                CheckAdminShareAcls(host, findings);
                EnumerateAndCheckShares(host, findings);
            });

            return findings;
        }

        // ── Admin share explicit ACL check ────────────────────────────────────

        private void CheckAdminShareAcls(string host, List<Finding> findings)
        {
            // ADMIN$ -- check NTFS ACL of Windows directory
            var adminSharePath = $"\\\\{host}\\ADMIN$";
            try
            {
                if (!Directory.Exists(adminSharePath)) return;

                var acl = new DirectoryInfo(adminSharePath)
                    .GetAccessControl(AccessControlSections.Access);

                foreach (FileSystemAccessRule rule in acl.GetAccessRules(
                    true, false, typeof(NTAccount)))
                {
                    if (rule.AccessControlType != AccessControlType.Allow) continue;

                    var principal = rule.IdentityReference.Value;
                    if (IsAdminPrincipal(principal)) continue;
                    if (IsWriteAccess(rule.FileSystemRights))
                    {
                        findings.Add(MakeFinding(host, "ADMIN_SHARE_OVERPERMISSIVE",
                            Severity.Critical,
                            $"Administrative share ADMIN$ on '{host}' grants write access to '{principal}'. " +
                            "Admin shares should be restricted to Administrators and SYSTEM only.",
                            $"Share=ADMIN$; Principal={principal}; Rights={rule.FileSystemRights}",
                            "Restrict ADMIN$ access to Administrators and SYSTEM only. " +
                            "If admin shares are not required, disable via registry: " +
                            "AutoShareServer=0 or AutoShareWks=0.",
                            subject: $"ADMIN$|{principal}"));
                    }
                }
            }
            catch { /* host may not have ADMIN$ accessible -- not a finding */ }
        }

        // ── Enumerate accessible shares and check ACLs ────────────────────────

        private void EnumerateAndCheckShares(string host, List<Finding> findings)
        {
            // We cannot enumerate shares via UNC without WMI, but we can
            // check well-known share paths that we probe for
            var commonShares = new[] { "Data", "Files", "Share", "Shared", "Public",
                "Users", "Profiles", "Home", "Homes", "Backup", "Backups",
                "Software", "Install", "Installs", "Deploy", "IT", "Scripts",
                "NETLOGON", "SYSVOL" };

            foreach (var shareName in commonShares)
            {
                var uncPath = $"\\\\{host}\\{shareName}";
                try
                {
                    if (!Directory.Exists(uncPath)) continue;
                    CheckShareAcl(host, shareName, uncPath, findings);
                }
                catch { /* share not accessible */ }
            }
        }

        private void CheckShareAcl(string host, string shareName,
            string uncPath, List<Finding> findings)
        {
            try
            {
                var acl = new DirectoryInfo(uncPath)
                    .GetAccessControl(AccessControlSections.Access);

                foreach (FileSystemAccessRule rule in acl.GetAccessRules(
                    true, false, typeof(NTAccount)))
                {
                    if (rule.AccessControlType != AccessControlType.Allow) continue;
                    if (rule.IsInherited) continue; // only flag explicit ACEs

                    var principal = rule.IdentityReference.Value;
                    if (!IsBroadPrincipal(principal)) continue;

                    var isWrite = IsWriteAccess(rule.FileSystemRights);
                    var checkName = isWrite ? "OPEN_SMB_SHARE_WRITE" : "OPEN_SMB_SHARE_READ";
                    var severity  = isWrite ? Severity.High : Severity.Medium;

                    findings.Add(MakeFinding(host, checkName, severity,
                        $"Share '\\\\{host}\\{shareName}' grants " +
                        $"{(isWrite ? "write" : "read")} access to '{principal}'. " +
                        (isWrite
                            ? "Write access enables data exfiltration and planting of malicious files."
                            : "Read access may expose sensitive data to all domain users."),
                        $"Share={shareName}; Path={uncPath}; Principal={principal}; Rights={rule.FileSystemRights}",
                        "Remove 'Everyone' and 'Authenticated Users' from share permissions. " +
                        "Grant access only to specific AD groups that require it. " +
                        "Audit share permissions quarterly.",
                        subject: $"{shareName}|{principal}"));
                }
            }
            catch { }
        }

        // ── SYSVOL write permissions ──────────────────────────────────────────

        private List<Finding> CheckSysvol()
        {
            var findings  = new List<Finding>();
            var sysvolPath = $"\\\\{_domain}\\SYSVOL";

            try
            {
                if (!Directory.Exists(sysvolPath)) return findings;

                var acl = new DirectoryInfo(sysvolPath)
                    .GetAccessControl(AccessControlSections.Access);

                foreach (FileSystemAccessRule rule in acl.GetAccessRules(
                    true, false, typeof(NTAccount)))
                {
                    if (rule.AccessControlType != AccessControlType.Allow) continue;
                    if (rule.IsInherited) continue;

                    var principal = rule.IdentityReference.Value;
                    if (!IsBroadPrincipal(principal)) continue;
                    if (!IsWriteAccess(rule.FileSystemRights)) continue;

                    findings.Add(MakeFinding(_domain, "SYSVOL_WRITE_PERMISSION",
                        Severity.Critical,
                        $"SYSVOL grants write access to '{principal}'. " +
                        "Writable SYSVOL allows planting of malicious scripts or GPO template files " +
                        "that execute on all domain-joined machines during policy refresh.",
                        $"Path={sysvolPath}; Principal={principal}; Rights={rule.FileSystemRights}",
                        "SYSVOL should only be writable by Domain Admins, SYSTEM, and CREATOR OWNER. " +
                        "Remove any broader write permissions immediately. " +
                        "Enable FRS/DFSR monitoring for unauthorized changes.",
                        subject: principal));
                }
            }
            catch (Exception ex)
            {
                Log($"SYSVOL check failed: {ex.Message}");
            }

            return findings;
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private bool IsBroadPrincipal(string principal)
        {
            foreach (var broad in Config.Thresholds.SmbShareBroadPrincipals)
                if (principal.Equals(broad, StringComparison.OrdinalIgnoreCase) ||
                    principal.EndsWith("\\" + broad, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        private static bool IsAdminPrincipal(string principal)
        {
            var adminNames = new[]
            {
                "Administrators", "BUILTIN\\Administrators",
                "Domain Admins", "SYSTEM", "NT AUTHORITY\\SYSTEM",
                "Enterprise Admins", "CREATOR OWNER"
            };
            return adminNames.Any(a =>
                principal.Equals(a, StringComparison.OrdinalIgnoreCase) ||
                principal.EndsWith("\\" + a, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsWriteAccess(FileSystemRights rights)
        {
            return (rights & (
                FileSystemRights.Write |
                FileSystemRights.Modify |
                FileSystemRights.FullControl |
                FileSystemRights.CreateFiles |
                FileSystemRights.CreateDirectories |
                FileSystemRights.WriteData)) != 0;
        }
    }
}
