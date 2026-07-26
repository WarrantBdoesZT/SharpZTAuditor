using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Reports
{
    public class SiemRenderer
    {
        private readonly AuditConfig _config;

        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented              = false,
            DefaultIgnoreCondition     = JsonIgnoreCondition.WhenWritingNull,
            Converters                 = { new JsonStringEnumConverter() }
        };

        public SiemRenderer(AuditConfig config) { _config = config; }

        // ── Splunk HEC ────────────────────────────────────────────────────────

        public void WriteSplunkHec(AuditReport report, string path)
        {
            var cfg = _config.Output.Splunk;
            var sb  = new StringBuilder();

            foreach (var f in report.Findings)
            {
                var evt = new
                {
                    time       = new DateTimeOffset(f.DiscoveredAt, TimeSpan.Zero).ToUnixTimeSeconds(),
                    host       = cfg.Host,
                    source     = "ZeroTrustAuditor",
                    sourcetype = cfg.Sourcetype,
                    index      = cfg.Index,
                    @event     = new
                    {
                        finding_id       = f.Id,
                        dest             = f.Host,
                        domain           = report.Domain,
                        module           = f.Module,
                        check_name       = f.CheckName,
                        severity         = f.Severity.ToString(),
                        risk_score       = f.RiskScore,
                        description      = f.Description,
                        evidence         = f.Evidence,
                        remediation      = f.RemediationGuidance,
                        discovered_at    = f.DiscoveredAt.ToString("o"),
                        report_id        = report.ReportId,
                        mitre_technique  = MapMitre(f.CheckName),
                        mitre_tactic     = MapTactic(f.CheckName),
                        vendor_product   = "ZeroTrustAuditor"
                    }
                };
                sb.AppendLine(JsonSerializer.Serialize(evt, JsonOpts));
            }

            File.WriteAllText(path, sb.ToString(), ReportRenderer.Utf8NoBom);
            Console.WriteLine($"[+] Splunk HEC: {path}");
        }

        // ── Sentinel / Log Analytics ──────────────────────────────────────────

        public void WriteSentinelJson(AuditReport report, string path)
        {
            var records = report.Findings.Select(f => new
            {
                TimeGenerated        = f.DiscoveredAt.ToString("o"),
                FindingId_s          = f.Id,
                ReportId_s           = report.ReportId,
                Domain_s             = report.Domain,
                Host_s               = f.Host,
                Module_s             = f.Module,
                CheckName_s          = f.CheckName,
                Severity_s           = f.Severity.ToString(),
                RiskScore_d          = f.RiskScore,
                Description_s        = f.Description,
                Evidence_s           = f.Evidence,
                Remediation_s        = f.RemediationGuidance,
                MitreTechnique_s     = MapMitre(f.CheckName),
                MitreTactic_s        = MapTactic(f.CheckName),
                AuditorVersion_s     = report.AuditorVersion,
            }).ToList();

            var json = JsonSerializer.Serialize(records, new JsonSerializerOptions
            {
                WriteIndented          = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            });

            File.WriteAllText(path, json, ReportRenderer.Utf8NoBom);
            Console.WriteLine($"[+] Sentinel JSON: {path}");
            Console.WriteLine($"    Log type (table): {_config.Output.Sentinel.LogType}_CL");
        }

        // ── CEF syslog ────────────────────────────────────────────────────────

        public void WriteCef(AuditReport report, string path)
        {
            var lines = new List<string>();
            var now   = DateTime.UtcNow.ToString("MMM dd HH:mm:ss");

            foreach (var f in report.Findings)
            {
                int cefSev = f.Severity switch
                {
                    Severity.Critical      => 10,
                    Severity.High          => 8,
                    Severity.Medium        => 5,
                    Severity.Low           => 3,
                    Severity.Informational => 1,
                    _                      => 1
                };

                var ext = $"rt={f.DiscoveredAt:o} dhost={Esc(f.Host)} " +
                          $"cs1={Esc(f.CheckName)} cs1Label=CheckName " +
                          $"cs2={Esc(f.Module)} cs2Label=Module " +
                          $"cn1={f.RiskScore:F1} cn1Label=RiskScore " +
                          $"cs3={Esc(MapMitre(f.CheckName))} cs3Label=MitreTechnique " +
                          $"msg={Esc(f.Description)} externalId={f.Id}";

                var desc = f.Description.Length > 80
                    ? f.Description[..80] : f.Description;

                lines.Add($"{now} ZeroTrustAuditor " +
                          $"CEF:0|Anthropic|ZeroTrustAuditor|2.0.0|" +
                          $"{Esc(f.CheckName)}|{Esc(desc)}|{cefSev}|{ext}");
            }

            File.WriteAllLines(path, lines, ReportRenderer.Utf8NoBom);
            Console.WriteLine($"[+] CEF: {path} ({lines.Count} events)");
        }

        private static string Esc(string? s) =>
            (s ?? string.Empty)
                .Replace("\\", "\\\\").Replace("|", "\\|")
                .Replace("=", "\\=").Replace("\n", " ");

        // ── MITRE ATT&CK mapping ──────────────────────────────────────────────

        private static string MapMitre(string check) => check switch
        {
            "KERBEROASTABLE_SPN"             => "T1558.003",
            "ASREP_ROASTABLE"                => "T1558.004",
            "UNCONSTRAINED_DELEGATION"       => "T1558.001",
            "DCSYNC_ACE"                     => "T1003.006",
            "SMB_SIGNING_DISABLED"           => "T1557.001",
            "NTLM_V1_ENABLED"                => "T1557.001",
            "LOCAL_ADMIN_OVERLAP"            => "T1021.002",
            "DOMAIN_GROUP_LOCAL_ADMIN"       => "T1078.002",
            "RDP_NLA_DISABLED"               => "T1021.001",
            "WINRM_UNENCRYPTED"              => "T1021.006",
            "DCOM_DEFAULT_LAUNCH_PERMISSION" => "T1021.003",
            "OPEN_SMB_SHARE_WRITE"           => "T1021.002",
            "SYSVOL_WRITE_PERMISSION"        => "T1484.001",
            "LAPS_NOT_DEPLOYED"              => "T1110",
            "CROSS_SEGMENT_ADMIN_PORT"       => "T1021",
            "WEF_NOT_CONFIGURED"             => "T1562.006",
            "WINDOWS_FIREWALL_DISABLED"      => "T1562.004",
            "STALE_PRIVILEGED_ACCOUNT"       => "T1078.002",
            "NESTED_GROUP_DA"                => "T1078.002",
            _                                => "T0000"
        };

        private static string MapTactic(string check) => check switch
        {
            "KERBEROASTABLE_SPN" or "ASREP_ROASTABLE" or
            "DCSYNC_ACE" or "NTLM_V1_ENABLED"         => "CredentialAccess",
            "UNCONSTRAINED_DELEGATION" or
            "SMB_SIGNING_DISABLED"                     => "CredentialAccess",
            "LOCAL_ADMIN_OVERLAP" or
            "DOMAIN_GROUP_LOCAL_ADMIN" or
            "RDP_NLA_DISABLED" or "WINRM_UNENCRYPTED" or
            "OPEN_SMB_SHARE_WRITE" or
            "CROSS_SEGMENT_ADMIN_PORT"                 => "LateralMovement",
            "SYSVOL_WRITE_PERMISSION"                  => "Persistence",
            "LAPS_NOT_DEPLOYED"                        => "CredentialAccess",
            "WEF_NOT_CONFIGURED" or
            "WINDOWS_FIREWALL_DISABLED"                => "DefenseEvasion",
            "STALE_PRIVILEGED_ACCOUNT" or
            "NESTED_GROUP_DA" or
            "MISSING_PROTECTED_USERS"                  => "PrivilegeEscalation",
            _                                          => "Unknown"
        };
    }
}
