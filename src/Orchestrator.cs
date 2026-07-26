using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrustAuditor.Checks;
using ZeroTrustAuditor.Config;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor
{
    public class Orchestrator
    {
        private readonly AuditConfig _config;
        private readonly SegmentationContext _segmentation;

        public Orchestrator(AuditConfig config, SegmentationContext? segmentation = null)
        {
            _config       = config;
            _segmentation = segmentation ?? new SegmentationContext();
        }

        public async Task<AuditReport> RunAsync(
            string[] hosts, string domain, CancellationToken ct = default)
        {
            // Apply host exclusions
            var excluded = _config.Audit.ExcludeHosts
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var scopedHosts = hosts.Where(h => !excluded.Contains(h)).ToArray();

            if (scopedHosts.Length < hosts.Length)
                Console.WriteLine($"[*] Excluded {hosts.Length - scopedHosts.Length} host(s) per config.");

            if (scopedHosts.Length > _config.Audit.MaxHostsPerRun)
                throw new InvalidOperationException(
                    $"Host count ({scopedHosts.Length}) exceeds config.audit.maxHostsPerRun " +
                    $"({_config.Audit.MaxHostsPerRun}). Narrow your scope or raise the limit.");

            Console.WriteLine($"[*] Starting audit -- {scopedHosts.Length} host(s), domain '{domain}'");

            // Reachability pre-check: surfaces WHY a host produced no findings
            // instead of letting registry/SMB access failures pass silently.
            var reachabilityFindings = await CheckHostReachabilityAsync(scopedHosts);

            using var timeout = new CancellationTokenSource(
                TimeSpan.FromSeconds(_config.Audit.ParallelModuleTimeoutSeconds));
            using var linked  = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);

            // Skip modules from config
            var skip = _config.Audit.SkipModules
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var tasks = new List<Task<List<Finding>>>();

            if (!skip.Contains("AdAuditor") && !skip.Contains("AD"))
            {
                Console.WriteLine("[*] Launching: AdAuditor");
                tasks.Add(RunSafe("AdAuditor",
                    () => new AdAuditor(_config, domain).RunAsync(), linked.Token));
            }

            if (!skip.Contains("ProtocolProbe") && !skip.Contains("Protocol"))
            {
                Console.WriteLine("[*] Launching: ProtocolProbe");
                tasks.Add(RunSafe("ProtocolProbe",
                    () => new ProtocolProbe(_config, scopedHosts).RunAsync(), linked.Token));
            }

            if (!skip.Contains("LateralPathAnalyzer") && !skip.Contains("Lateral"))
            {
                Console.WriteLine("[*] Launching: LateralPathAnalyzer");
                tasks.Add(RunSafe("LateralPathAnalyzer",
                    () => new LateralPathAnalyzer(_config, scopedHosts, domain).RunAsync(), linked.Token));
            }

            if (!skip.Contains("ShareAuditor") && !skip.Contains("Shares"))
            {
                Console.WriteLine("[*] Launching: ShareAuditor");
                tasks.Add(RunSafe("ShareAuditor",
                    () => new ShareAuditor(_config, scopedHosts, domain).RunAsync(), linked.Token));
            }

            if (!skip.Contains("SegmentationChecker") && !skip.Contains("Segmentation"))
            {
                Console.WriteLine("[*] Launching: SegmentationChecker");
                tasks.Add(RunSafe("SegmentationChecker",
                    () => new SegmentationChecker(_config, scopedHosts, _segmentation).RunAsync(),
                    linked.Token));
            }

            var results     = await Task.WhenAll(tasks);
            var allFindings = results.SelectMany(r => r).Concat(reachabilityFindings).ToList();

            Console.WriteLine($"[*] Raw findings: {allFindings.Count}");

            var report = Aggregate(allFindings, scopedHosts, domain);

            Console.WriteLine($"[+] Audit complete. Unique findings: {report.Findings.Count}");
            foreach (var sev in SeverityDescending)
                if (report.SeveritySummary.TryGetValue(sev, out var count) && count > 0)
                    Console.WriteLine($"    {sev,-15} {count}");

            return report;
        }

        private static readonly Severity[] SeverityDescending =
        {
            Severity.Critical, Severity.High, Severity.Medium,
            Severity.Low, Severity.Informational
        };

        private static async Task<List<Finding>> RunSafe(
            string name, Func<Task<List<Finding>>> fn, CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var work = fn();

                // The check modules call blocking LDAP / registry / SMB APIs that expose
                // no cancellation of their own, so a module that overruns is ABANDONED
                // rather than awaited forever. Previously `ct` was accepted here and never
                // observed, which made config.audit.parallelModuleTimeout dead config: a
                // single hung module hung the whole run indefinitely.
                var completed = await Task.WhenAny(
                    work, Task.Delay(Timeout.InfiniteTimeSpan, ct));

                if (completed != work)
                {
                    sw.Stop();
                    Console.Error.WriteLine(
                        $"[!] {name} timed out or was cancelled after {sw.Elapsed.TotalSeconds:F1}s " +
                        "-- its partial results are discarded. Raise config.audit.parallelModuleTimeout " +
                        "or narrow the host scope.");
                    return new List<Finding>();
                }

                var result = await work;
                sw.Stop();
                Console.WriteLine($"[✓] {name} complete: {result.Count} finding(s) ({sw.Elapsed.TotalSeconds:F1}s)");
                return result;
            }
            catch (Exception ex)
            {
                sw.Stop();
                Console.Error.WriteLine($"[!] {name} failed after {sw.Elapsed.TotalSeconds:F1}s: {ex.Message}");
                return new List<Finding>();
            }
        }

        // ── Host reachability pre-check ────────────────────────────────────────
        // Registry and SMB access failures are silent by design in the individual
        // checks (a closed port or a locked-down host looks identical to "nothing
        // to report"). This pass tells the user WHICH hosts couldn't be read from
        // and WHY, so a clean report can be trusted instead of just assumed.

        private async Task<List<Finding>> CheckHostReachabilityAsync(string[] hosts)
        {
            var smbPort = _config.Network.AdminPorts.TryGetValue("SMB", out var p) ? p : 445;
            var timeoutMs = _config.Network.PortProbeTimeoutMs;

            var probes = hosts.Select(async host =>
            {
                bool smbOpen = await IsTcpOpenAsync(host, smbPort, timeoutMs);
                bool regOpen = IsRemoteRegistryOpen(host);
                return (Host: host, SmbOpen: smbOpen, RegOpen: regOpen);
            });

            var results = await Task.WhenAll(probes);
            var reachable = results.Count(r => r.SmbOpen || r.RegOpen);

            Console.WriteLine($"[*] Host reachability: {reachable}/{hosts.Length} host(s) " +
                "responded to SMB and/or Remote Registry");

            var findings = new List<Finding>();

            foreach (var r in results)
            {
                if (!r.RegOpen)
                {
                    Console.WriteLine($"    [!] {r.Host}: Remote Registry not accessible -- " +
                        "ProtocolProbe and parts of SegmentationChecker will report nothing for this host.");
                    findings.Add(new Finding
                    {
                        Host                = r.Host,
                        Module              = "Orchestrator",
                        CheckName           = "REMOTE_REGISTRY_UNREACHABLE",
                        Severity            = Severity.Informational,
                        Description         = $"Could not read the remote registry on '{r.Host}'. " +
                            "ProtocolProbe (SMB signing, NTLMv1, RDP NLA, DCOM, WinRM) and the registry-based " +
                            "checks in SegmentationChecker will silently report zero findings for this host -- " +
                            "that does NOT mean the host is compliant, it means it could not be read.",
                        Evidence            = "RegistryKey.OpenRemoteBaseKey failed or returned no accessible key.",
                        RemediationGuidance = "Verify the Remote Registry service is running on the target " +
                            "(GPO: Computer Configuration > Windows Settings > System Services > Remote Registry > " +
                            "Automatic) and that the auditing account has network access to the host.",
                    });
                }

                if (!r.SmbOpen)
                {
                    Console.WriteLine($"    [!] {r.Host}: SMB (445) unreachable -- " +
                        "ShareAuditor and LateralPathAnalyzer will report nothing for this host.");
                    findings.Add(new Finding
                    {
                        Host                = r.Host,
                        Module              = "Orchestrator",
                        CheckName           = "SMB_UNREACHABLE",
                        Severity            = Severity.Informational,
                        Description         = $"Could not reach '{r.Host}' on TCP port 445 (SMB). " +
                            "ShareAuditor (SYSVOL/share ACLs) and LateralPathAnalyzer (local admin overlap, LAPS) " +
                            "will silently report zero findings for this host -- that does NOT mean the host is " +
                            "clean, it means it was unreachable.",
                        Evidence            = $"TCP connect to {r.Host}:{smbPort} did not complete within {timeoutMs}ms.",
                        RemediationGuidance = "Verify network connectivity and that a firewall between the audit " +
                            "workstation and this host is not blocking port 445.",
                    });
                }
            }

            return findings;
        }

        private static async Task<bool> IsTcpOpenAsync(string host, int port, int timeoutMs)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                var timeoutTask = Task.Delay(timeoutMs);
                var completed   = await Task.WhenAny(connectTask, timeoutTask);
                return completed == connectTask && client.Connected;
            }
            catch { return false; }
        }

        private static bool IsRemoteRegistryOpen(string host)
        {
            try
            {
                using var reg = Microsoft.Win32.RegistryKey.OpenRemoteBaseKey(
                    Microsoft.Win32.RegistryHive.LocalMachine, host, Microsoft.Win32.RegistryView.Registry64);
                return reg != null;
            }
            catch { return false; }
        }

        /// <summary>
        /// Deduplicate, score, and correlate. Public so it can be unit tested without
        /// touching a network -- this is where the three worst historical bugs lived.
        /// </summary>
        public AuditReport Aggregate(List<Finding> all, string[] hosts, string domain)
        {
            // Apply check exclusions
            var excluded = _config.Audit.ExcludeChecks
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var eligible = all.Where(f => !excluded.Contains(f.CheckName)).ToList();

            // Deduplicate on the identity of the thing being reported.
            //
            // Subject is part of the key because every AdAuditor finding, the SYSVOL
            // check, and the local-admin-overlap check all stamp Host with the DOMAIN
            // name. Keying on Host+CheckName alone collapsed every Kerberoastable
            // account in the domain into one finding (likewise all three firewall
            // profiles per host, and every cross-segment protocol per target).
            //
            // OrderByDescending(Severity) now genuinely keeps the MOST severe member:
            // the Severity enum is ordered ascending with pinned values. It used to be
            // declared Critical=0..Informational=4, so this same expression kept the
            // LEAST severe member -- discarding the Critical duplicates.
            var deduped = eligible
                .GroupBy(f => $"{f.Host}|{f.CheckName}|{f.Subject}",
                         StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(f => f.Severity).First())
                .ToList();

            // Base risk scores
            foreach (var f in deduped)
                f.RiskScore = _config.Severity.GetBaseScore(f.Severity);

            if (_config.Correlation.Enabled)
                ApplyCorrelation(deduped);

            var summary = new Dictionary<Severity, int>();
            foreach (Severity s in Enum.GetValues(typeof(Severity)))
                summary[s] = deduped.Count(f => f.Severity == s);

            return new AuditReport
            {
                TargetHosts     = hosts,
                Domain          = domain,
                Findings        = deduped
                    .OrderByDescending(f => f.RiskScore)
                    .ThenByDescending(f => f.Severity)
                    .ToList(),
                SeveritySummary = summary,
            };
        }

        // ── Correlation ────────────────────────────────────────────────────────
        //
        // Previously this grouped findings by Host and required both sides of a rule
        // to appear in the same group. Because domain-wide checks anchor on the domain
        // name while per-host checks anchor on a hostname, four of the six shipped
        // rules could never match, and the two that could were vacuous -- they fired
        // whenever both conditions existed anywhere in the domain.
        //
        // Now a finding "touches" its own Host plus everything in AffectedHosts, so
        // LOCAL_ADMIN_OVERLAP correlates with the specific hosts it actually spans.
        // Rules that are genuinely domain-wide declare scope:"domain" and are tagged
        // as such, so nobody mistakes them for a same-host attack chain.

        private void ApplyCorrelation(List<Finding> findings)
        {
            var byCheck = findings
                .GroupBy(f => f.CheckName, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

            // A finding is boosted at most once per rule, however many partners it has.
            var boosted = new HashSet<string>(StringComparer.Ordinal);

            foreach (var rule in _config.Correlation.Rules)
            {
                if (string.IsNullOrWhiteSpace(rule.CheckA) ||
                    string.IsNullOrWhiteSpace(rule.CheckB)) continue;

                if (!byCheck.TryGetValue(rule.CheckA, out var aSide)) continue;
                if (!byCheck.TryGetValue(rule.CheckB, out var bSide)) continue;

                foreach (var fa in aSide)
                foreach (var fb in bSide)
                {
                    if (ReferenceEquals(fa, fb)) continue;
                    if (rule.IsHostScoped && !SharesHost(fa, fb)) continue;

                    Boost(fa, rule, boosted);
                    Boost(fb, rule, boosted);

                    if (!fa.RelatedFindingIds.Contains(fb.Id)) fa.RelatedFindingIds.Add(fb.Id);
                    if (!fb.RelatedFindingIds.Contains(fa.Id)) fb.RelatedFindingIds.Add(fa.Id);

                    TagRule(fa, rule);
                    TagRule(fb, rule);
                }
            }
        }

        private void Boost(Finding f, CorrelationRule rule, HashSet<string> boosted)
        {
            if (!boosted.Add($"{f.Id}|{rule.Name}")) return;
            f.RiskScore = Math.Min(_config.Severity.MaxScore, f.RiskScore + rule.RiskBoost);
        }

        private static void TagRule(Finding f, CorrelationRule rule)
        {
            if (f.Tags.TryGetValue("correlationRule", out var existing) && existing.Length > 0)
            {
                if (!existing.Split(';').Select(s => s.Trim()).Contains(rule.Name))
                    f.Tags["correlationRule"] = existing + "; " + rule.Name;
            }
            else
            {
                f.Tags["correlationRule"] = rule.Name;
            }

            f.Tags["correlationScope"] = rule.IsHostScoped ? "host" : "domain";
        }

        /// <summary>Every host a finding touches: its anchor host plus any AffectedHosts.</summary>
        private static IEnumerable<string> TouchedHosts(Finding f)
        {
            if (!string.IsNullOrEmpty(f.Host)) yield return f.Host;
            foreach (var h in f.AffectedHosts)
                if (!string.IsNullOrEmpty(h)) yield return h;
        }

        private static bool SharesHost(Finding a, Finding b)
        {
            var lhs = new HashSet<string>(TouchedHosts(a), StringComparer.OrdinalIgnoreCase);
            foreach (var h in TouchedHosts(b))
                if (lhs.Contains(h)) return true;
            return false;
        }
    }
}
