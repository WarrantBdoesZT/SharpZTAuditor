using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroTrustAuditor.Models
{
    public class AuditConfig
    {
        [JsonPropertyName("audit")]
        public AuditSettings Audit { get; set; } = new();

        [JsonPropertyName("thresholds")]
        public ThresholdSettings Thresholds { get; set; } = new();

        [JsonPropertyName("correlation")]
        public CorrelationSettings Correlation { get; set; } = new();

        [JsonPropertyName("output")]
        public OutputSettings Output { get; set; } = new();

        [JsonPropertyName("severity")]
        public SeveritySettings Severity { get; set; } = new();

        [JsonPropertyName("network")]
        public NetworkSettings Network { get; set; } = new();

        [JsonPropertyName("reporting")]
        public ReportingSettings Reporting { get; set; } = new();
    }

    public class AuditSettings
    {
        [JsonPropertyName("staleAccountThresholdDays")]
        public int StaleAccountThresholdDays { get; set; } = 90;

        [JsonPropertyName("maxHostsPerRun")]
        public int MaxHostsPerRun { get; set; } = 500;

        [JsonPropertyName("parallelModuleTimeout")]
        public int ParallelModuleTimeoutSeconds { get; set; } = 300;

        [JsonPropertyName("skipModules")]
        public List<string> SkipModules { get; set; } = new();

        [JsonPropertyName("excludeHosts")]
        public List<string> ExcludeHosts { get; set; } = new();

        [JsonPropertyName("excludeChecks")]
        public List<string> ExcludeChecks { get; set; } = new();
    }

    public class ThresholdSettings
    {
        [JsonPropertyName("localAdminOverlapMinHosts")]
        public int LocalAdminOverlapMinHosts { get; set; } = 2;

        [JsonPropertyName("localAdminOverlapCriticalHosts")]
        public int LocalAdminOverlapCriticalHosts { get; set; } = 5;

        [JsonPropertyName("securityLogMinSizeBytes")]
        public long SecurityLogMinSizeBytes { get; set; } = 1_073_741_824;

        [JsonPropertyName("smbShareBroadPrincipals")]
        public List<string> SmbShareBroadPrincipals { get; set; } = new()
        {
            "Everyone", "BUILTIN\\Everyone",
            "NT AUTHORITY\\Authenticated Users", "Authenticated Users",
            "BUILTIN\\Users", "Domain Users"
        };

        [JsonPropertyName("privilegedGroups")]
        public List<string> PrivilegedGroups { get; set; } = new()
        {
            "Domain Admins", "Enterprise Admins", "Schema Admins",
            "Administrators", "Account Operators", "Backup Operators",
            "Print Operators", "Server Operators"
        };

        [JsonPropertyName("expectedDCSyncPrincipals")]
        public List<string> ExpectedDCSyncPrincipals { get; set; } = new()
        {
            "Domain Controllers", "Enterprise Domain Controllers", "Administrators"
        };

        [JsonPropertyName("lmCompatibilityLevelMinimum")]
        public int LmCompatibilityLevelMinimum { get; set; } = 3;
    }

    public class CorrelationRule
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;
        [JsonPropertyName("checkA")]
        public string CheckA { get; set; } = string.Empty;
        [JsonPropertyName("checkB")]
        public string CheckB { get; set; } = string.Empty;
        [JsonPropertyName("riskBoost")]
        public double RiskBoost { get; set; } = 2.0;

        [JsonPropertyName("rationale")]
        public string Rationale { get; set; } = string.Empty;

        /// <summary>
        /// "host"   -- both findings must touch a common host (a real attack chain).
        /// "domain" -- both conditions merely have to exist somewhere in the domain.
        ///
        /// Domain scope is deliberately weaker and is tagged as such on the finding,
        /// because it is an AND of two domain-wide facts rather than a co-location.
        /// </summary>
        [JsonPropertyName("scope")]
        public string Scope { get; set; } = "host";

        [JsonIgnore]
        public bool IsHostScoped =>
            !Scope.Equals("domain", StringComparison.OrdinalIgnoreCase);
    }

    public class CorrelationSettings
    {
        [JsonPropertyName("enabled")]
        public bool Enabled { get; set; } = true;
        [JsonPropertyName("rules")]
        public List<CorrelationRule> Rules { get; set; } = new();
    }

    public class OutputSettings
    {
        [JsonPropertyName("formats")]
        public List<string> Formats { get; set; } = new() { "json", "html", "csv" };

        [JsonPropertyName("splunk")]
        public SplunkSettings Splunk { get; set; } = new();

        [JsonPropertyName("sentinel")]
        public SentinelSettings Sentinel { get; set; } = new();
    }

    public class SplunkSettings
    {
        [JsonPropertyName("index")]
        public string Index { get; set; } = "zero_trust_audit";
        [JsonPropertyName("sourcetype")]
        public string Sourcetype { get; set; } = "zta:finding";
        [JsonPropertyName("host")]
        public string Host { get; set; } = "audit-workstation";
    }

    public class SentinelSettings
    {
        [JsonPropertyName("workspaceId")]
        public string WorkspaceId { get; set; } = string.Empty;
        [JsonPropertyName("logType")]
        public string LogType { get; set; } = "ZeroTrustAuditFinding";
    }

    public class SeveritySettings
    {
        [JsonPropertyName("baseScores")]
        public Dictionary<string, double> BaseScores { get; set; } = new()
        {
            ["Critical"] = 9.0, ["High"] = 7.0, ["Medium"] = 5.0,
            ["Low"] = 3.0, ["Informational"] = 1.0
        };

        [JsonPropertyName("maxScore")]
        public double MaxScore { get; set; } = 10.0;

        public double GetBaseScore(Severity s) =>
            BaseScores.TryGetValue(s.ToString(), out var v) ? v : 1.0;
    }

    public class NetworkSettings
    {
        [JsonPropertyName("portProbeTimeoutMs")]
        public int PortProbeTimeoutMs { get; set; } = 3000;

        [JsonPropertyName("adminPorts")]
        public Dictionary<string, int> AdminPorts { get; set; } = new()
        {
            ["RDP"] = 3389, ["SMB"] = 445, ["WinRM"] = 5985,
            ["WinRMHTTPS"] = 5986, ["WMI"] = 135, ["SSH"] = 22
        };

        /// <summary>
        /// Protocols (keys of <see cref="AdminPorts"/>) that must not cross a segment
        /// boundary. This key existed in audit-config.json but had no property to bind
        /// to, so it was silently discarded and SegmentationChecker used a hardcoded
        /// list instead -- customising it in config had no effect.
        /// </summary>
        [JsonPropertyName("crossSegmentAdminPorts")]
        public List<string> CrossSegmentAdminPorts { get; set; } = new()
        {
            "SMB", "WinRM", "WMI", "RDP"
        };
    }

    public class ReportingSettings
    {
        [JsonPropertyName("organizationName")]
        public string OrganizationName { get; set; } = string.Empty;
        [JsonPropertyName("engagementName")]
        public string EngagementName { get; set; } = string.Empty;
        [JsonPropertyName("auditorName")]
        public string AuditorName { get; set; } = string.Empty;
    }

    public static class AuditConfigLoader
    {
        private static readonly JsonSerializerOptions Opts = new()
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        public static AuditConfig Load(string? path = null)
        {
            path ??= Path.Combine(
                Path.GetDirectoryName(
                    System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                    ?? ".") ?? ".",
                "audit-config.json");

            if (!File.Exists(path))
            {
                Console.WriteLine($"[*] Config not found at '{path}' -- using defaults.");
                return new AuditConfig();
            }

            var config = JsonSerializer.Deserialize<AuditConfig>(
                File.ReadAllText(path), Opts) ?? new AuditConfig();

            Console.WriteLine($"[*] Config loaded: {path}");
            return config;
        }
    }
}
