using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Checks
{
    /// <summary>
    /// Active Directory misconfiguration checks.
    /// Uses System.DirectoryServices for LDAP queries -- no PowerShell required.
    /// All queries are read-only.
    /// </summary>
    public class AdAuditor : CheckBase
    {
        private readonly string _domain;
        private readonly string _ldapBase;
        private readonly int    _staleThreshold;

        public AdAuditor(AuditConfig config, string domain) : base(config)
        {
            _domain         = domain;
            _ldapBase       = $"LDAP://{domain}";
            _staleThreshold = config.Audit.StaleAccountThresholdDays;
        }

        public async Task<List<Finding>> RunAsync()
        {
            var findings = new List<Finding>();
            Log($"Auditing domain: {_domain}");

            await Task.Run(() =>
            {
                RunCheck("CHECK 1 - Kerberoastable SPNs",       () => CheckKerberoastable(findings));
                RunCheck("CHECK 2 - AS-REP Roastable",          () => CheckAsRepRoastable(findings));
                RunCheck("CHECK 3 - Unconstrained delegation",   () => CheckUnconstrainedDelegation(findings));
                RunCheck("CHECK 4 - DCSync ACEs",                () => CheckDcSyncAces(findings));
                RunCheck("CHECK 5 - Missing Protected Users",    () => CheckProtectedUsers(findings));
                RunCheck("CHECK 6 - Stale privileged accounts",  () => CheckStalePrivilegedAccounts(findings));
                RunCheck("CHECK 7 - Nested groups in DA",        () => CheckNestedGroupsInDA(findings));
                RunCheck("CHECK 8 - AdminCount orphans",         () => CheckAdminCountOrphans(findings));
            });

            Log($"Complete. Findings: {findings.Count}");
            return findings;
        }

        private void RunCheck(string name, Action check)
        {
            Log(name);
            try { check(); }
            catch (Exception ex) { Log($"  Skipped ({ex.Message})"); }
        }

        // ── CHECK 1: Kerberoastable SPNs ─────────────────────────────────────

        private void CheckKerberoastable(List<Finding> findings)
        {
            using var searcher = MakeSearcher(
                "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                new[] { "sAMAccountName", "servicePrincipalName", "adminCount", "pwdLastSet" });

            foreach (SearchResult result in searcher.FindAll())
            {
                var sam      = GetStr(result, "sAMAccountName");
                var spns     = GetStrArr(result, "servicePrincipalName");
                var isAdmin  = GetInt(result, "adminCount") == 1;
                var severity = isAdmin ? Severity.Critical : Severity.High;

                findings.Add(MakeFinding(
                    _domain, "KERBEROASTABLE_SPN", severity,
                    $"Account '{sam}' has SPNs and is susceptible to Kerberoasting." +
                    (isAdmin ? " AdminCount=1 - critical privilege escalation path." : ""),
                    $"SamAccountName={sam}; SPNs={string.Join("; ", spns)}; AdminCount={GetInt(result, "adminCount")}",
                    "Use Group Managed Service Accounts (gMSA). If a standard account is required, " +
                    "use a 127+ character random password and audit SPN registrations.",
                    subject: sam));
            }
        }

        // ── CHECK 2: AS-REP Roastable ─────────────────────────────────────────

        private void CheckAsRepRoastable(List<Finding> findings)
        {
            // DONT_REQUIRE_PREAUTH = 0x400000 = 4194304
            using var searcher = MakeSearcher(
                "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)" +
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                new[] { "sAMAccountName", "adminCount" });

            foreach (SearchResult result in searcher.FindAll())
            {
                var sam      = GetStr(result, "sAMAccountName");
                var isAdmin  = GetInt(result, "adminCount") == 1;
                var severity = isAdmin ? Severity.Critical : Severity.High;

                findings.Add(MakeFinding(
                    _domain, "ASREP_ROASTABLE", severity,
                    $"Account '{sam}' does not require Kerberos pre-authentication. " +
                    "AS-REP hashes can be requested anonymously and cracked offline.",
                    $"SamAccountName={sam}; AdminCount={GetInt(result, "adminCount")}",
                    "Enable Kerberos pre-authentication on all accounts unless a legacy application " +
                    "explicitly requires otherwise.",
                    subject: sam));
            }
        }

        // ── CHECK 3: Unconstrained delegation ─────────────────────────────────

        private void CheckUnconstrainedDelegation(List<Finding> findings)
        {
            // TRUSTED_FOR_DELEGATION = 0x80000 = 524288
            // Exclude domain controllers (userAccountControl & 8192 = DC)
            using var searcher = MakeSearcher(
                "(&(objectClass=user)" +
                "(userAccountControl:1.2.840.113556.1.4.803:=524288)" +
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
                new[] { "sAMAccountName", "distinguishedName" });

            foreach (SearchResult result in searcher.FindAll())
            {
                var sam = GetStr(result, "sAMAccountName");
                var dn  = GetStr(result, "distinguishedName");

                findings.Add(MakeFinding(
                    _domain, "UNCONSTRAINED_DELEGATION", Severity.Critical,
                    $"User account '{sam}' is trusted for unconstrained Kerberos delegation. " +
                    "Any TGT presented to this account can be reused to impersonate any user.",
                    $"SamAccountName={sam}; DN={dn}",
                    "Migrate to Constrained Delegation or RBCD. " +
                    "Remove TrustedForDelegation from all non-DC accounts. " +
                    "Add sensitive accounts to the Protected Users group.",
                    subject: sam));
            }
        }

        // ── CHECK 4: DCSync-capable ACEs ─────────────────────────────────────

        private void CheckDcSyncAces(List<Finding> findings)
        {
            // DS-Replication GUIDs
            var dcSyncGuids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", // DS-Replication-Get-Changes
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", // DS-Replication-Get-Changes-All
                "89e95b76-444d-4c62-991a-0facbeda640c"  // DS-Replication-Get-Changes-In-Filtered-Set
            };

            var expectedPrincipals = Config.Thresholds.ExpectedDCSyncPrincipals;

            using var root = new DirectoryEntry(_ldapBase);
            var acl = root.ObjectSecurity;
            if (acl == null) return;

            foreach (ActiveDirectoryAccessRule rule in acl.GetAccessRules(
                true, false, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow)
                    continue;

                var guidStr = rule.ObjectType.ToString();
                if (!dcSyncGuids.Contains(guidStr)) continue;

                var principal = rule.IdentityReference.Value;
                bool isExpected = false;
                foreach (var exp in expectedPrincipals)
                    if (principal.Contains(exp, StringComparison.OrdinalIgnoreCase))
                    { isExpected = true; break; }

                if (isExpected) continue;

                findings.Add(MakeFinding(
                    _domain, "DCSYNC_ACE", Severity.Critical,
                    $"Principal '{principal}' has DCSync-capable replication rights on the domain root. " +
                    "This enables offline extraction of all password hashes without touching a DC.",
                    $"Principal={principal}; RightGUID={guidStr}; AccessType=Allow",
                    "Remove DS-Replication-Get-Changes-All ACEs from all non-DC principals. " +
                    "Use repadmin /showattr to enumerate delegated replication rights.",
                    subject: $"{principal}|{guidStr}"));
            }
        }

        // ── CHECK 5: Missing Protected Users ─────────────────────────────────

        private void CheckProtectedUsers(List<Finding> findings)
        {
            var protectedMembers = GetGroupMemberSAMs("Protected Users");

            foreach (var groupName in Config.Thresholds.PrivilegedGroups)
            {
                List<string> members;
                try { members = GetGroupMemberSAMs(groupName); }
                catch { continue; }

                foreach (var sam in members)
                {
                    if (protectedMembers.Contains(sam)) continue;

                    var enabled  = IsAccountEnabled(sam);
                    var severity = enabled ? Severity.Medium : Severity.Low;

                    findings.Add(MakeFinding(
                        _domain, "MISSING_PROTECTED_USERS", severity,
                        $"Privileged account '{sam}' (member of '{groupName}') is not in Protected Users. " +
                        "TGT lifetime is unrestricted and NTLM/Digest auth is not blocked.",
                        $"SamAccountName={sam}; Group={groupName}; Enabled={enabled}",
                        "Add all tier-0 and tier-1 privileged accounts to Protected Users. " +
                        "Test compatibility -- Protected Users blocks NTLM, DES, RC4, and unconstrained delegation.",
                        subject: $"{groupName}\\{sam}"));
                }
            }
        }

        // ── CHECK 6: Stale privileged accounts ───────────────────────────────

        private void CheckStalePrivilegedAccounts(List<Finding> findings)
        {
            var cutoff = DateTime.UtcNow.AddDays(-_staleThreshold);

            foreach (var groupName in Config.Thresholds.PrivilegedGroups)
            {
                List<string> members;
                try { members = GetGroupMemberSAMs(groupName); }
                catch { continue; }

                foreach (var sam in members)
                {
                    try
                    {
                        using var searcher = MakeSearcher(
                            $"(&(objectClass=user)(sAMAccountName={EscapeLdap(sam)}))",
                            new[] { "lastLogon", "lastLogonTimestamp", "userAccountControl", "pwdLastSet" });

                        var result = searcher.FindOne();
                        if (result == null) continue;

                        // Skip disabled accounts
                        var uac = GetInt(result, "userAccountControl");
                        if ((uac & 2) != 0) continue;

                        // lastLogonTimestamp replicates; lastLogon does not -- use whichever is later
                        var ll  = GetFileTime(result, "lastLogon");
                        var llt = GetFileTime(result, "lastLogonTimestamp");
                        var lastLogon = ll > llt ? ll : llt;

                        if (lastLogon > cutoff) continue;

                        findings.Add(MakeFinding(
                            _domain, "STALE_PRIVILEGED_ACCOUNT", Severity.High,
                            $"Privileged account '{sam}' (member of '{groupName}') has not logged in " +
                            $"for {_staleThreshold}+ days but remains enabled with elevated rights.",
                            $"SamAccountName={sam}; Group={groupName}; LastLogon={lastLogon:yyyy-MM-dd}",
                            "Disable or remove stale privileged accounts. Implement JIT access provisioning. " +
                            "Accounts unused 60 days = review; 90 days = disable; 180 days = delete.",
                            subject: $"{groupName}\\{sam}"));
                    }
                    catch { continue; }
                }
            }
        }

        // ── CHECK 7: Nested groups inside Domain Admins ───────────────────────

        private void CheckNestedGroupsInDA(List<Finding> findings)
        {
            using var searcher = MakeSearcher(
                "(&(objectClass=group)(sAMAccountName=Domain Admins))",
                new[] { "member" });

            var result = searcher.FindOne();
            if (result == null) return;

            foreach (string memberDn in result.Properties["member"])
            {
                using var memberEntry = new DirectoryEntry($"LDAP://{memberDn}");
                var objectClass = memberEntry.Properties["objectClass"];
                bool isGroup = false;
                foreach (var oc in objectClass) if (oc?.ToString() == "group") { isGroup = true; break; }
                if (!isGroup) continue;

                var groupName = memberEntry.Properties["sAMAccountName"]?.Value?.ToString() ?? memberDn;

                findings.Add(MakeFinding(
                    _domain, "NESTED_GROUP_DA", Severity.High,
                    $"Group '{groupName}' is nested inside Domain Admins. " +
                    "All its members inherit Domain Admin rights -- this may be broader than intended.",
                    $"NestedGroup={groupName}; DN={memberDn}",
                    "Remove nested groups from Domain Admins. " +
                    "Only named individual accounts should be direct members.",
                    subject: groupName));
            }
        }

        // ── CHECK 8: AdminCount=1 orphans ─────────────────────────────────────

        private void CheckAdminCountOrphans(List<Finding> findings)
        {
            var privilegedSet = new HashSet<string>(
                Config.Thresholds.PrivilegedGroups, StringComparer.OrdinalIgnoreCase);

            using var searcher = MakeSearcher(
                "(&(objectClass=user)(adminCount=1)" +
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                new[] { "sAMAccountName", "memberOf" });

            foreach (SearchResult result in searcher.FindAll())
            {
                var sam      = GetStr(result, "sAMAccountName");
                bool inPriv  = false;

                foreach (string groupDn in result.Properties["memberOf"])
                {
                    var groupName = ExtractCn(groupDn);
                    if (privilegedSet.Contains(groupName)) { inPriv = true; break; }
                }

                if (inPriv) continue;

                findings.Add(MakeFinding(
                    _domain, "ADMINCOUNT_ORPHAN", Severity.Medium,
                    $"Account '{sam}' has AdminCount=1 but is no longer in any privileged group. " +
                    "This disables DACL inheritance, potentially hiding delegated permissions.",
                    $"SamAccountName={sam}; AdminCount=1",
                    "Reset AdminCount to 0 and re-enable DACL inheritance on accounts " +
                    "not currently in protected groups.",
                    subject: sam));
            }
        }

        // ── LDAP helpers ──────────────────────────────────────────────────────

        private DirectorySearcher MakeSearcher(string filter, string[] props)
        {
            var entry    = new DirectoryEntry(_ldapBase);
            var searcher = new DirectorySearcher(entry, filter);
            searcher.PageSize = 1000;
            foreach (var p in props) searcher.PropertiesToLoad.Add(p);
            return searcher;
        }

        private List<string> GetGroupMemberSAMs(string groupName)
        {
            var results = new List<string>();
            using var ctx = new PrincipalContext(ContextType.Domain, _domain);
            using var group = GroupPrincipal.FindByIdentity(ctx, groupName);
            if (group == null) return results;

            foreach (var member in group.GetMembers(recursive: true))
            {
                if (member is UserPrincipal)
                    results.Add(member.SamAccountName);
                member.Dispose();
            }
            return results;
        }

        private bool IsAccountEnabled(string sam)
        {
            try
            {
                using var searcher = MakeSearcher(
                    $"(&(objectClass=user)(sAMAccountName={EscapeLdap(sam)}))",
                    new[] { "userAccountControl" });
                var result = searcher.FindOne();
                if (result == null) return false;
                return (GetInt(result, "userAccountControl") & 2) == 0;
            }
            catch { return false; }
        }

        private static string GetStr(SearchResult r, string prop)
        {
            var col = r.Properties[prop];
            return col?.Count > 0 ? col[0]?.ToString() ?? string.Empty : string.Empty;
        }

        private static int GetInt(SearchResult r, string prop)
        {
            var col = r.Properties[prop];
            if (col == null || col.Count == 0) return 0;
            return Convert.ToInt32(col[0]);
        }

        private static List<string> GetStrArr(SearchResult r, string prop)
        {
            var list = new List<string>();
            var col  = r.Properties[prop];
            if (col == null) return list;
            foreach (var v in col) if (v != null) list.Add(v.ToString()!);
            return list;
        }

        private static DateTime GetFileTime(SearchResult r, string prop)
        {
            var col = r.Properties[prop];
            if (col == null || col.Count == 0) return DateTime.MinValue;
            try
            {
                var val = col[0];
                if (val is long l && l > 0)
                    return DateTime.FromFileTimeUtc(l);
                if (val is IADsLargeInteger li)
                    return DateTime.FromFileTimeUtc(
                        ((long)li.HighPart << 32) | (uint)li.LowPart);
            }
            catch { }
            return DateTime.MinValue;
        }

        private static string ExtractCn(string dn)
        {
            var parts = dn.Split(',');
            if (parts.Length == 0) return dn;
            var cn = parts[0];
            var eq = cn.IndexOf('=');
            return eq >= 0 ? cn[(eq + 1)..] : cn;
        }

        private static string EscapeLdap(string s) =>
            s.Replace("\\", "\\5c").Replace("*", "\\2a")
             .Replace("(", "\\28").Replace(")", "\\29")
             .Replace("\0", "\\00");
    }

    // COM interop for large integer (lastLogon)
    [System.Runtime.InteropServices.ComImport]
    [System.Runtime.InteropServices.Guid("9068270b-0939-11d1-8be1-00c04fd8d503")]
    [System.Runtime.InteropServices.InterfaceType(
        System.Runtime.InteropServices.ComInterfaceType.InterfaceIsDual)]
    internal interface IADsLargeInteger
    {
        int HighPart { get; set; }
        int LowPart { get; set; }
    }
}
