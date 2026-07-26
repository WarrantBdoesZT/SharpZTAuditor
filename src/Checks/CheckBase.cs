using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Checks
{
    /// <summary>
    /// Outcome of a remote registry read.
    ///
    /// The critical distinction is Absent vs Unreadable. Several checks treat
    /// "value not found" as proof that a control is missing (LAPS_NOT_DEPLOYED,
    /// DCOM_DEFAULT_*, WEF_NOT_CONFIGURED, FIREWALL_LOGGING_DISABLED). If a host
    /// is simply offline or has Remote Registry stopped, that must NOT be reported
    /// as a failed control -- doing so fabricates several High findings per
    /// unreachable host.
    /// </summary>
    public enum RegistryReadStatus
    {
        /// <summary>Connected and the value was read.</summary>
        Read,
        /// <summary>Connected successfully, but the key or value genuinely does not exist.</summary>
        Absent,
        /// <summary>Could not connect, access was denied, or the read failed. Nothing can be concluded.</summary>
        Unreadable
    }

    /// <summary>
    /// Shared helpers available to all check classes.
    /// All methods are pure .NET -- no PowerShell, no external processes.
    /// </summary>
    public abstract class CheckBase
    {
        protected readonly AuditConfig Config;
        protected readonly int PortTimeoutMs;

        protected CheckBase(AuditConfig config)
        {
            Config = config;
            PortTimeoutMs = config.Network.PortProbeTimeoutMs;
        }

        // ── Finding factory ───────────────────────────────────────────────────

        /// <param name="subject">
        /// The specific entity the finding is about (account, principal, share,
        /// firewall profile, protocol). Required whenever a check can emit more than
        /// one finding of the same CheckName against the same Host -- otherwise
        /// deduplication collapses them into a single row.
        /// </param>
        /// <param name="affectedHosts">
        /// Additional hosts this finding touches, for domain-anchored findings that
        /// actually span many machines (e.g. LOCAL_ADMIN_OVERLAP). Used by correlation.
        /// </param>
        protected Finding MakeFinding(
            string host,
            string checkName,
            Severity severity,
            string description,
            string evidence,
            string remediation,
            string module = "",
            string subject = "",
            IEnumerable<string>? affectedHosts = null)
        {
            return new Finding
            {
                Host                = host,
                Module              = module.Length > 0 ? module : GetType().Name,
                CheckName           = checkName,
                Severity            = severity,
                Subject             = subject,
                AffectedHosts       = affectedHosts == null
                                          ? new List<string>()
                                          : new List<string>(affectedHosts),
                Description         = description,
                Evidence            = evidence,
                RemediationGuidance = remediation,
                DiscoveredAt        = DateTime.UtcNow,
            };
        }

        // ── Port probe ────────────────────────────────────────────────────────

        /// <summary>
        /// LEGACY boolean port check. Returns true if the port accepts a connection.
        ///
        /// Do NOT use this for segmentation analysis -- it cannot distinguish a
        /// refused connection (nothing filtering) from a dropped one (a control
        /// enforcing), which is the entire question segmentation asks. Use
        /// <see cref="ZeroTrustAuditor.Network.ProbeEngine"/> instead.
        ///
        /// It remains here for the enrichment checks, which only need to know
        /// whether it is worth attempting a registry read against a host. That
        /// decision genuinely is boolean.
        ///
        /// Known gap: this path is still unbounded and unpaced. Only ProtocolProbe
        /// uses it, over a fixed handful of ports per host.
        /// </summary>
        protected async Task<bool> IsPortOpenAsync(string host, int port)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                var timeoutTask = Task.Delay(PortTimeoutMs);
                var completed   = await Task.WhenAny(connectTask, timeoutTask);
                return completed == connectTask && client.Connected;
            }
            catch { return false; }
        }

        protected async Task<Dictionary<string, bool>> ProbePortsAsync(
            string host, Dictionary<string, int> ports)
        {
            var results = new Dictionary<string, bool>();
            var tasks   = new Dictionary<string, Task<bool>>();

            foreach (var kv in ports)
                tasks[kv.Key] = IsPortOpenAsync(host, kv.Value);

            foreach (var kv in tasks)
                results[kv.Key] = await kv.Value;

            return results;
        }

        // ── Remote registry ───────────────────────────────────────────────────

        /// <summary>
        /// Read a DWORD or string value from a remote registry key.
        /// Returns null on any error (host unreachable, key missing, access denied).
        /// </summary>
        protected static object? GetRemoteReg(
            string computer, string subKey, string valueName,
            Microsoft.Win32.RegistryHive hive = Microsoft.Win32.RegistryHive.LocalMachine)
        {
            try
            {
                using var reg = Microsoft.Win32.RegistryKey.OpenRemoteBaseKey(
                    hive, computer, Microsoft.Win32.RegistryView.Registry64);
                using var key = reg.OpenSubKey(subKey, false);
                return key?.GetValue(valueName);
            }
            catch { return null; }
        }

        protected static int? GetRemoteRegInt(string computer, string subKey, string valueName)
        {
            var v = GetRemoteReg(computer, subKey, valueName);
            if (v == null) return null;

            // Convert.ToInt32 throws on REG_SZ / REG_BINARY values where a DWORD was
            // expected. This used to sit outside any try block: the exception unwound
            // through Task.WhenAll into Orchestrator.RunSafe, which swallowed it and
            // returned an EMPTY list -- so one malformed value on one host silently
            // zeroed out the entire module for every host in the run.
            try { return Convert.ToInt32(v); }
            catch { return null; }
        }

        /// <summary>
        /// Tri-state remote registry read. Use this instead of <see cref="GetRemoteReg"/>
        /// whenever the ABSENCE of a value is going to be reported as a finding, so that
        /// an unreachable host is not mistaken for a misconfigured one.
        /// </summary>
        protected static RegistryReadStatus TryGetRemoteReg(
            string computer, string subKey, string valueName, out object? value,
            Microsoft.Win32.RegistryHive hive = Microsoft.Win32.RegistryHive.LocalMachine)
        {
            value = null;

            Microsoft.Win32.RegistryKey? baseKey;
            try
            {
                baseKey = Microsoft.Win32.RegistryKey.OpenRemoteBaseKey(
                    hive, computer, Microsoft.Win32.RegistryView.Registry64);
            }
            catch
            {
                // Host offline, Remote Registry stopped, RPC blocked, or access denied.
                return RegistryReadStatus.Unreadable;
            }

            if (baseKey == null) return RegistryReadStatus.Unreadable;

            using (baseKey)
            {
                Microsoft.Win32.RegistryKey? key;
                try { key = baseKey.OpenSubKey(subKey, false); }
                catch { return RegistryReadStatus.Unreadable; }   // ACL denied on the subkey

                // Connection succeeded and the key is genuinely not present.
                if (key == null) return RegistryReadStatus.Absent;

                using (key)
                {
                    try { value = key.GetValue(valueName); }
                    catch { return RegistryReadStatus.Unreadable; }

                    return value == null
                        ? RegistryReadStatus.Absent
                        : RegistryReadStatus.Read;
                }
            }
        }

        /// <summary>Tri-state read coerced to an int. Returns Unreadable if the value is not numeric.</summary>
        protected static RegistryReadStatus TryGetRemoteRegInt(
            string computer, string subKey, string valueName, out int? value)
        {
            value = null;
            var status = TryGetRemoteReg(computer, subKey, valueName, out var raw);
            if (status != RegistryReadStatus.Read) return status;

            try { value = Convert.ToInt32(raw); }
            catch { return RegistryReadStatus.Unreadable; }

            return RegistryReadStatus.Read;
        }

        // ── Console helpers ───────────────────────────────────────────────────

        protected void Log(string msg) =>
            Console.WriteLine($"[{GetType().Name}] {msg}");
    }
}
