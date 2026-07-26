using System.Collections.Generic;
using System.Linq;
using Xunit;
using ZeroTrustAuditor;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Tests
{
    /// <summary>
    /// Regression tests for Orchestrator.Aggregate -- deduplication, severity
    /// selection, and correlation.
    ///
    /// Every test here corresponds to a defect that shipped in v2.0 and silently
    /// corrupted report output. They exist so those specific failures cannot recur.
    /// </summary>
    public class AggregationTests
    {
        private const string Domain = "corp.local";
        private static readonly string[] Hosts = { "SRV01", "SRV02", "SRV03" };

        private static AuditConfig ConfigWithRules(params CorrelationRule[] rules)
        {
            var cfg = new AuditConfig();
            cfg.Correlation.Enabled = true;
            cfg.Correlation.Rules = rules.ToList();
            return cfg;
        }

        private static Finding F(
            string host, string check, Severity sev,
            string subject = "", IEnumerable<string>? affected = null) =>
            new Finding
            {
                Host          = host,
                CheckName     = check,
                Severity      = sev,
                Subject       = subject,
                AffectedHosts = affected == null ? new List<string>() : new List<string>(affected),
            };

        // ── Severity ordering ──────────────────────────────────────────────────

        [Fact]
        public void Severity_IsOrderedAscending_SoDescendingSortsWorstFirst()
        {
            // The original enum ran Critical=0..Informational=4, which inverted every
            // OrderByDescending(f => f.Severity) in the codebase.
            Assert.True(Severity.Critical > Severity.High);
            Assert.True(Severity.High     > Severity.Medium);
            Assert.True(Severity.Medium   > Severity.Low);
            Assert.True(Severity.Low      > Severity.Informational);
        }

        // ── A1: dedup key must include Subject ─────────────────────────────────

        [Fact]
        public void Aggregate_KeepsOneFindingPerSubject_ForDomainAnchoredChecks()
        {
            // All AdAuditor findings stamp Host = the domain name. Keying dedup on
            // Host+CheckName alone collapsed every Kerberoastable account into one row.
            var findings = new List<Finding>
            {
                F(Domain, "KERBEROASTABLE_SPN", Severity.High,     subject: "svc_sql"),
                F(Domain, "KERBEROASTABLE_SPN", Severity.High,     subject: "svc_web"),
                F(Domain, "KERBEROASTABLE_SPN", Severity.Critical, subject: "svc_backup"),
            };

            var report = new Orchestrator(new AuditConfig()).Aggregate(findings, Hosts, Domain);

            Assert.Equal(3, report.Findings.Count);
            Assert.Equal(
                new[] { "svc_backup", "svc_sql", "svc_web" },
                report.Findings.Select(f => f.Subject).OrderBy(s => s).ToArray());
        }

        [Fact]
        public void Aggregate_KeepsOneFindingPerFirewallProfile()
        {
            // Domain / Private / Public all share Host+CheckName on the same machine.
            var findings = new List<Finding>
            {
                F("SRV01", "WINDOWS_FIREWALL_DISABLED", Severity.High, subject: "Domain"),
                F("SRV01", "WINDOWS_FIREWALL_DISABLED", Severity.High, subject: "Private"),
                F("SRV01", "WINDOWS_FIREWALL_DISABLED", Severity.High, subject: "Public"),
            };

            var report = new Orchestrator(new AuditConfig()).Aggregate(findings, Hosts, Domain);

            Assert.Equal(3, report.Findings.Count);
        }

        [Fact]
        public void Aggregate_StillCollapsesTrueDuplicates()
        {
            var findings = new List<Finding>
            {
                F("SRV01", "SMB_SIGNING_DISABLED", Severity.High),
                F("SRV01", "SMB_SIGNING_DISABLED", Severity.High),
            };

            var report = new Orchestrator(new AuditConfig()).Aggregate(findings, Hosts, Domain);

            Assert.Single(report.Findings);
        }

        // ── A2: dedup must keep the MOST severe duplicate ──────────────────────

        [Fact]
        public void Aggregate_KeepsMostSevereDuplicate_NotLeastSevere()
        {
            // With the old inverted enum this returned the Informational row.
            var findings = new List<Finding>
            {
                F("SRV01", "SMB_SIGNING_DISABLED", Severity.Informational),
                F("SRV01", "SMB_SIGNING_DISABLED", Severity.Critical),
                F("SRV01", "SMB_SIGNING_DISABLED", Severity.Medium),
            };

            var report = new Orchestrator(new AuditConfig()).Aggregate(findings, Hosts, Domain);

            Assert.Single(report.Findings);
            Assert.Equal(Severity.Critical, report.Findings[0].Severity);
        }

        // ── A3: correlation must actually fire ─────────────────────────────────

        [Fact]
        public void Correlation_HostScopedRule_MatchesViaAffectedHosts()
        {
            // LOCAL_ADMIN_OVERLAP is anchored on the domain but spans real hosts.
            // Without AffectedHosts this rule could never match anything.
            var rule = new CorrelationRule
            {
                Name = "SMB relay + local admin spread",
                CheckA = "SMB_SIGNING_DISABLED",
                CheckB = "LOCAL_ADMIN_OVERLAP",
                Scope = "host",
                RiskBoost = 2.0,
            };

            var smb     = F("SRV01", "SMB_SIGNING_DISABLED", Severity.High);
            var overlap = F(Domain, "LOCAL_ADMIN_OVERLAP", Severity.High,
                            subject: "svc_admin",
                            affected: new[] { "SRV01", "SRV02" });

            var report = new Orchestrator(ConfigWithRules(rule))
                .Aggregate(new List<Finding> { smb, overlap }, Hosts, Domain);

            Assert.All(report.Findings, f =>
            {
                Assert.Equal("SMB relay + local admin spread", f.Tags["correlationRule"]);
                Assert.Equal("host", f.Tags["correlationScope"]);
            });

            // High base = 7.0, boosted by 2.0
            Assert.Equal(9.0, smb.RiskScore, 3);
            Assert.Equal(9.0, overlap.RiskScore, 3);
            Assert.Contains(overlap.Id, smb.RelatedFindingIds);
        }

        [Fact]
        public void Correlation_HostScopedRule_DoesNotFireAcrossUnrelatedHosts()
        {
            var rule = new CorrelationRule
            {
                Name = "SMB relay + local admin spread",
                CheckA = "SMB_SIGNING_DISABLED",
                CheckB = "LOCAL_ADMIN_OVERLAP",
                Scope = "host",
                RiskBoost = 2.0,
            };

            var smb     = F("SRV99", "SMB_SIGNING_DISABLED", Severity.High);
            var overlap = F(Domain, "LOCAL_ADMIN_OVERLAP", Severity.High,
                            subject: "svc_admin",
                            affected: new[] { "SRV01", "SRV02" });

            new Orchestrator(ConfigWithRules(rule))
                .Aggregate(new List<Finding> { smb, overlap }, Hosts, Domain);

            Assert.Equal(7.0, smb.RiskScore, 3);          // unboosted
            Assert.False(smb.Tags.ContainsKey("correlationRule"));
        }

        [Fact]
        public void Correlation_DomainScopedRule_FiresAndIsTaggedAsDomainScope()
        {
            var rule = new CorrelationRule
            {
                Name = "DCSync rights + stale account",
                CheckA = "DCSYNC_ACE",
                CheckB = "STALE_PRIVILEGED_ACCOUNT",
                Scope = "domain",
                RiskBoost = 2.0,
            };

            var dcsync = F(Domain, "DCSYNC_ACE", Severity.Critical, subject: "svc_repl");
            var stale  = F(Domain, "STALE_PRIVILEGED_ACCOUNT", Severity.High, subject: "DA\\olduser");

            new Orchestrator(ConfigWithRules(rule))
                .Aggregate(new List<Finding> { dcsync, stale }, Hosts, Domain);

            Assert.Equal("domain", dcsync.Tags["correlationScope"]);
            Assert.Equal("domain", stale.Tags["correlationScope"]);
        }

        [Fact]
        public void Correlation_BoostsEachFindingOnlyOncePerRule()
        {
            // One overlap finding spanning three hosts, each with its own SMB finding.
            // The overlap must not be boosted three times.
            var rule = new CorrelationRule
            {
                Name = "SMB relay + local admin spread",
                CheckA = "SMB_SIGNING_DISABLED",
                CheckB = "LOCAL_ADMIN_OVERLAP",
                Scope = "host",
                RiskBoost = 1.0,
            };

            var overlap = F(Domain, "LOCAL_ADMIN_OVERLAP", Severity.Medium,
                            subject: "svc_admin",
                            affected: new[] { "SRV01", "SRV02", "SRV03" });

            var findings = new List<Finding>
            {
                F("SRV01", "SMB_SIGNING_DISABLED", Severity.Medium),
                F("SRV02", "SMB_SIGNING_DISABLED", Severity.Medium),
                F("SRV03", "SMB_SIGNING_DISABLED", Severity.Medium),
                overlap,
            };

            new Orchestrator(ConfigWithRules(rule)).Aggregate(findings, Hosts, Domain);

            // Medium base = 5.0, boosted once by 1.0. Three boosts would give 8.0.
            Assert.Equal(6.0, overlap.RiskScore, 3);
        }

        [Fact]
        public void Correlation_RuleNamingAMissingCheck_IsIgnoredNotCrashing()
        {
            var rule = new CorrelationRule
            {
                Name = "bogus",
                CheckA = "RDP_NLA_DISABLED",
                CheckB = "OPEN_SMB_SHARE",   // a name no check emits
                Scope = "host",
                RiskBoost = 2.0,
            };

            var rdp = F("SRV01", "RDP_NLA_DISABLED", Severity.High);

            var report = new Orchestrator(ConfigWithRules(rule))
                .Aggregate(new List<Finding> { rdp }, Hosts, Domain);

            Assert.Single(report.Findings);
            Assert.Equal(7.0, rdp.RiskScore, 3);
        }

        // ── Exclusions and ordering ────────────────────────────────────────────

        [Fact]
        public void Aggregate_HonoursExcludeChecks()
        {
            var cfg = new AuditConfig();
            cfg.Audit.ExcludeChecks.Add("LAPS_NOT_DEPLOYED");

            var findings = new List<Finding>
            {
                F("SRV01", "LAPS_NOT_DEPLOYED", Severity.High),
                F("SRV01", "SMB_SIGNING_DISABLED", Severity.High),
            };

            var report = new Orchestrator(cfg).Aggregate(findings, Hosts, Domain);

            Assert.Single(report.Findings);
            Assert.Equal("SMB_SIGNING_DISABLED", report.Findings[0].CheckName);
        }

        [Fact]
        public void Aggregate_OrdersByRiskScoreDescending()
        {
            var findings = new List<Finding>
            {
                F("SRV01", "A_CHECK", Severity.Low),
                F("SRV02", "B_CHECK", Severity.Critical),
                F("SRV03", "C_CHECK", Severity.Medium),
            };

            var report = new Orchestrator(new AuditConfig()).Aggregate(findings, Hosts, Domain);

            Assert.Equal(Severity.Critical, report.Findings[0].Severity);
            Assert.Equal(Severity.Low,      report.Findings[2].Severity);
        }

        [Fact]
        public void Aggregate_SeveritySummaryCountsEveryLevel()
        {
            var findings = new List<Finding>
            {
                F("SRV01", "A", Severity.Critical),
                F("SRV02", "B", Severity.Critical),
                F("SRV03", "C", Severity.Low),
            };

            var report = new Orchestrator(new AuditConfig()).Aggregate(findings, Hosts, Domain);

            Assert.Equal(2, report.SeveritySummary[Severity.Critical]);
            Assert.Equal(1, report.SeveritySummary[Severity.Low]);
            Assert.Equal(0, report.SeveritySummary[Severity.High]);
        }
    }
}
