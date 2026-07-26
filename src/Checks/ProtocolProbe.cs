using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Checks
{
    /// <summary>
    /// Protocol misconfiguration checks.
    /// Uses Microsoft.Win32.RegistryKey for remote registry reads and
    /// TcpClient for port probing -- no PowerShell, no WMI, no CIM.
    /// </summary>
    public class ProtocolProbe : CheckBase
    {
        private readonly string[] _hosts;

        public ProtocolProbe(AuditConfig config, string[] hosts) : base(config)
        {
            _hosts = hosts;
        }

        public async Task<List<Finding>> RunAsync()
        {
            var findings = new List<Finding>();
            Log($"Probing {_hosts.Length} host(s)");

            var tasks = new List<Task<List<Finding>>>();
            foreach (var host in _hosts)
                tasks.Add(ProbeHostAsync(host));

            foreach (var result in await Task.WhenAll(tasks))
                findings.AddRange(result);

            Log($"Complete. Findings: {findings.Count}");
            return findings;
        }

        private async Task<List<Finding>> ProbeHostAsync(string host)
        {
            var findings = new List<Finding>();
            Log($"  Probing: {host}");

            // Port reachability
            var ports = Config.Network.AdminPorts;
            var open  = await ProbePortsAsync(host, ports);

            CheckSmbSigning(host, open, findings);
            CheckNtlmLevel(host, findings);
            CheckWinRm(host, open, findings);
            CheckRdpNla(host, open, findings);
            CheckDcom(host, open, findings);
            await CheckSsh(host, open, findings);

            return findings;
        }

        // ── CHECK 1: SMB signing ──────────────────────────────────────────────

        private void CheckSmbSigning(string host, Dictionary<string, bool> open,
            List<Finding> findings)
        {
            if (!open.GetValueOrDefault("SMB")) return;

            var req = GetRemoteRegInt(host,
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "RequireSecuritySignature");
            var ena = GetRemoteRegInt(host,
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "EnableSecuritySignature");

            if (req == null || req != 0) return;

            var severity = (ena == null || ena == 0) ? Severity.Critical : Severity.High;

            findings.Add(MakeFinding(host, "SMB_SIGNING_DISABLED", severity,
                $"SMB signing is not required on '{host}'. " +
                "SMB relay attacks (NTLM relay) are possible, enabling code execution without credentials.",
                $"RequireSecuritySignature={req}; EnableSecuritySignature={ena}",
                "Set RequireSecuritySignature=1 via GPO: Computer Configuration -> Windows Settings -> " +
                "Security Settings -> Local Policies -> Security Options -> " +
                "Microsoft network server: Digitally sign communications (always)."));
        }

        // ── CHECK 2: NTLMv1 ───────────────────────────────────────────────────

        private void CheckNtlmLevel(string host, List<Finding> findings)
        {
            var level = GetRemoteRegInt(host,
                @"SYSTEM\CurrentControlSet\Control\Lsa",
                "LmCompatibilityLevel");

            if (level == null || level >= Config.Thresholds.LmCompatibilityLevelMinimum) return;

            var severity = level < 2 ? Severity.Critical : Severity.High;

            findings.Add(MakeFinding(host, "NTLM_V1_ENABLED", severity,
                $"LmCompatibilityLevel={level} on '{host}'. " +
                "Values below 3 allow NTLMv1 which can be cracked with rainbow tables or captured with Responder.",
                $"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel={level} (safe minimum: 5)",
                "Set LmCompatibilityLevel=5 via GPO: Network security: LAN Manager authentication level = " +
                "Send NTLMv2 response only. Refuse LM and NTLM."));
        }

        // ── CHECK 3: WinRM encryption ─────────────────────────────────────────

        private void CheckWinRm(string host, Dictionary<string, bool> open,
            List<Finding> findings)
        {
            if (!open.GetValueOrDefault("WinRM")) return;

            var allowUnenc = GetRemoteRegInt(host,
                @"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
                "AllowUnencryptedTraffic");

            if (allowUnenc == 1)
            {
                findings.Add(MakeFinding(host, "WINRM_UNENCRYPTED", Severity.High,
                    $"WinRM allows unencrypted traffic on '{host}'. " +
                    "Credentials over WinRM HTTP port 5985 are readable on the wire.",
                    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\AllowUnencryptedTraffic=1",
                    "Set AllowUnencryptedTraffic=0. Use HTTPS (port 5986) with a valid certificate."));
            }

            if (!open.GetValueOrDefault("WinRMHTTPS"))
            {
                findings.Add(MakeFinding(host, "WINRM_NO_HTTPS", Severity.Medium,
                    $"WinRM HTTPS (port 5986) is not listening on '{host}'. " +
                    "If WinRM is in use, traffic relies on Kerberos message encryption only.",
                    $"Port 5985 open=True; Port 5986 open=False",
                    "Configure a WinRM HTTPS listener with a machine certificate. " +
                    "Disable the HTTP listener where not required."));
            }
        }

        // ── CHECK 4: RDP NLA ──────────────────────────────────────────────────

        private void CheckRdpNla(string host, Dictionary<string, bool> open,
            List<Finding> findings)
        {
            if (!open.GetValueOrDefault("RDP")) return;

            var nla = GetRemoteRegInt(host,
                @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "UserAuthentication");

            if (nla == 0)
            {
                findings.Add(MakeFinding(host, "RDP_NLA_DISABLED", Severity.High,
                    $"RDP Network Level Authentication is disabled on '{host}'. " +
                    "The login screen is exposed before authentication, enabling bruteforce attacks.",
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication=0",
                    "Set UserAuthentication=1 via GPO: Computer Configuration -> Administrative Templates -> " +
                    "Windows Components -> Remote Desktop Services -> Require NLA."));
            }

            var encLevel = GetRemoteRegInt(host,
                @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "MinEncryptionLevel");

            if (encLevel != null && encLevel < 3)
            {
                findings.Add(MakeFinding(host, "RDP_WEAK_ENCRYPTION", Severity.Medium,
                    $"RDP minimum encryption level is {encLevel} on '{host}'. Values below 3 use weak RC4.",
                    $"MinEncryptionLevel={encLevel} (safe minimum: 3)",
                    "Set MinEncryptionLevel=3 or use SecurityLayer=2 (TLS) via GPO: " +
                    "RDS -> Session Host -> Security -> Set client connection encryption level."));
            }
        }

        // ── CHECK 5: DCOM permissions ─────────────────────────────────────────

        private void CheckDcom(string host, Dictionary<string, bool> open,
            List<Finding> findings)
        {
            if (!open.GetValueOrDefault("WMI")) return;

            // Tri-state: these checks report the ABSENCE of a value as a finding, so an
            // unreadable registry must not be treated as absence. Previously a host with
            // Remote Registry stopped produced a High plus a Medium DCOM finding purely
            // because both reads returned null.
            var launchStatus = TryGetRemoteReg(host,
                @"SOFTWARE\Microsoft\Ole", "DefaultLaunchPermission", out _);
            var accessStatus = TryGetRemoteReg(host,
                @"SOFTWARE\Microsoft\Ole", "DefaultAccessPermission", out _);

            if (launchStatus == RegistryReadStatus.Unreadable ||
                accessStatus == RegistryReadStatus.Unreadable)
            {
                Log($"  {host} DCOM permissions undetermined (registry unreadable) -- not reporting.");
                return;
            }

            if (launchStatus == RegistryReadStatus.Absent)
            {
                findings.Add(MakeFinding(host, "DCOM_DEFAULT_LAUNCH_PERMISSION", Severity.High,
                    $"DCOM DefaultLaunchPermission is absent on '{host}'. " +
                    "The built-in default allows Everyone local launch and activation rights.",
                    "HKLM\\SOFTWARE\\Microsoft\\Ole\\DefaultLaunchPermission: key absent",
                    "Define explicit DCOM machine-wide launch permissions restricting to " +
                    "Administrators and SYSTEM only via dcomcnfg.exe or Group Policy."));
            }

            if (accessStatus == RegistryReadStatus.Absent)
            {
                findings.Add(MakeFinding(host, "DCOM_DEFAULT_ACCESS_PERMISSION", Severity.Medium,
                    $"DCOM DefaultAccessPermission is absent on '{host}'. " +
                    "The default grants Everyone call access to all COM servers.",
                    "HKLM\\SOFTWARE\\Microsoft\\Ole\\DefaultAccessPermission: key absent",
                    "Set explicit DefaultAccessPermission restricting to local " +
                    "Administrators via dcomcnfg or SCM hardening."));
            }
        }

        // ── CHECK 6: SSH configuration ────────────────────────────────────────

        private async Task CheckSsh(string host, Dictionary<string, bool> open,
            List<Finding> findings)
        {
            if (!open.GetValueOrDefault("SSH")) return;

            var configPath = $"\\\\{host}\\C$\\ProgramData\\ssh\\sshd_config";

            try
            {
                if (!File.Exists(configPath))
                {
                    findings.Add(MakeFinding(host, "SSH_CONFIG_UNREADABLE", Severity.Informational,
                        $"SSH port 22 is open on '{host}' but sshd_config is not readable via UNC path. " +
                        "Manual review recommended.",
                        $"Port 22 open; {configPath} not accessible",
                        "Verify SSH server configuration manually on the target host."));
                    return;
                }

                var lines = await File.ReadAllLinesAsync(configPath);

                foreach (var line in lines)
                {
                    var trimmed = line.Trim();

                    if (trimmed.StartsWith("StrictModes", StringComparison.OrdinalIgnoreCase) &&
                        trimmed.EndsWith("no", StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(MakeFinding(host, "SSH_STRICT_MODES_DISABLED", Severity.Medium,
                            $"SSH on '{host}' has StrictModes no, disabling permission checks on authorized_keys.",
                            "sshd_config: StrictModes no",
                            "Set StrictModes yes. Ensure authorized_keys is owned by the user " +
                            "and not world-writable."));
                    }

                    if (trimmed.StartsWith("PasswordAuthentication", StringComparison.OrdinalIgnoreCase) &&
                        trimmed.EndsWith("yes", StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(MakeFinding(host, "SSH_PASSWORD_AUTH_ENABLED", Severity.Medium,
                            $"SSH on '{host}' allows password authentication, enabling credential stuffing attacks.",
                            "sshd_config: PasswordAuthentication yes",
                            "Set PasswordAuthentication no. Enforce public key or certificate-based auth."));
                    }

                    if (trimmed.StartsWith("PermitRootLogin", StringComparison.OrdinalIgnoreCase) &&
                        trimmed.EndsWith("yes", StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(MakeFinding(host, "SSH_PERMIT_ROOT_LOGIN", Severity.High,
                            $"SSH on '{host}' permits root/Administrator login directly.",
                            "sshd_config: PermitRootLogin yes",
                            "Set PermitRootLogin no. Require standard account login then elevate."));
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"  {host} SSH config check skipped: {ex.Message}");
            }
        }
    }
}
