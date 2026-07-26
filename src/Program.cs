using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Reports;

namespace ZeroTrustAuditor
{
    /// <summary>
    /// ZeroTrustAuditor v2.0 -- Pure C# Zero Trust misconfiguration assessment.
    ///
    /// Usage:
    ///   ZeroTrustAuditor.exe --hosts host1,host2 --domain corp.local
    ///   ZeroTrustAuditor.exe --hosts-file targets.txt --domain corp.local
    ///   ZeroTrustAuditor.exe --hosts host1 --domain corp.local --config audit-config.json
    ///   ZeroTrustAuditor.exe --hosts host1 --domain corp.local --skip-modules AdAuditor,ShareAuditor
    ///
    /// --skip-modules accepts a comma-separated list of module names to skip:
    ///   AdAuditor, ProtocolProbe, LateralPathAnalyzer, ShareAuditor, SegmentationChecker
    ///
    /// No PowerShell. No external processes. No WMI/CIM.
    /// Pure .NET 8 with System.DirectoryServices, Registry, and TCP.
    /// </summary>
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            PrintBanner();

            // Subcommands are matched before flag parsing so `merge` never collides
            // with the audit path's required --domain.
            if (args.Length > 0 &&
                args[0].Equals("merge", StringComparison.OrdinalIgnoreCase))
            {
                return Commands.MergeCommand.Run(args.Skip(1).ToArray());
            }

            if (args.Any(a => a is "--help" or "-h" or "-?" or "/?"))
            {
                PrintUsage();
                return 0;
            }

            var opts = ParseArgs(args);
            if (opts == null) return 1;

            Directory.CreateDirectory(opts.OutputDir);

            // Apply CLI skip-modules on top of whatever is in config
            var config = AuditConfigLoader.Load(opts.ConfigPath);
            if (opts.SkipModules.Length > 0)
            {
                foreach (var m in opts.SkipModules)
                    if (!config.Audit.SkipModules.Contains(m, StringComparer.OrdinalIgnoreCase))
                        config.Audit.SkipModules.Add(m);

                Console.WriteLine($"[*] Skipping modules (--skip-modules): {string.Join(", ", opts.SkipModules)}");
            }

            // ── Segmentation context: zones, policy, service catalog ──────────
            var segmentation = ZeroTrustAuditor.Config.SegmentationConfigLoader.Load(
                opts.ZonesPath, opts.PolicyPath, opts.ServicesPath);

            segmentation.Validation.PrintTo(Console.Out, Console.Error);

            if (segmentation.Validation.HasErrors)
            {
                Console.Error.WriteLine(
                    "\n[!] Segmentation configuration has errors (listed above). " +
                    "Fix them and re-run -- proceeding would silently mis-attribute zones.");
                return 4;
            }

            if (segmentation.IsConfigured)
                Console.WriteLine(
                    $"[*] Zone map: {segmentation.Zones.Zones.Count} zone(s), " +
                    $"{segmentation.Zones.RangeCount} CIDR range(s); " +
                    $"policy rules: {segmentation.Policy.Rules.Count}; " +
                    $"service classes: {segmentation.Services.ServiceClasses.Count}");

            var probeOptions = new Network.ProbeOptions
            {
                TimeoutMs        = config.Network.PortProbeTimeoutMs,
                MaxConcurrency   = opts.MaxConcurrency  ?? config.Network.MaxParallelProbes,
                ProbesPerSecond  = opts.ProbesPerSecond ?? config.Network.ProbesPerSecond,
                RetriesOnTimeout = config.Network.RetriesOnTimeout,
                GrabBanners      = config.Network.GrabBanners,
                AllowOtProbing   = opts.AllowOtProbing,
                DryRun           = opts.DryRun,
            };

            Console.WriteLine(
                $"[*] Probe budget: max {probeOptions.MaxConcurrency} concurrent, " +
                $"{(probeOptions.ProbesPerSecond <= 0 ? "unlimited" : probeOptions.ProbesPerSecond + "/sec")}, " +
                $"{probeOptions.TimeoutMs}ms timeout, {probeOptions.RetriesOnTimeout} retry(s)");

            if (probeOptions.DryRun)
                Console.WriteLine("[*] DRY RUN -- probes will be planned but no packets sent.");

            if (probeOptions.AllowOtProbing)
                Console.WriteLine(
                    "[!] OT/ICS active probing ENABLED. Controllers can fault on unexpected " +
                    "connections -- confirm you have written approval from the OT owner.");

            var orchestrator = new Orchestrator(config, segmentation, probeOptions);
            var renderer     = new ReportRenderer();
            var siem         = new SiemRenderer(config);

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

            try
            {
                var report  = await orchestrator.RunAsync(opts.Hosts, opts.Domain, cts.Token);
                var stamp   = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
                var formats = config.Output.Formats
                    .Select(f => f.ToLowerInvariant()).ToHashSet();

                if (formats.Contains("json"))
                    renderer.WriteJson(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.json"));

                if (formats.Contains("csv"))
                    renderer.WriteCsv(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.csv"));

                if (formats.Contains("html"))
                    renderer.WriteHtml(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.html"));

                if (formats.Contains("splunk"))
                    siem.WriteSplunkHec(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.splunk.json"));

                if (formats.Contains("sentinel"))
                    siem.WriteSentinelJson(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.sentinel.json"));

                if (formats.Contains("cef"))
                    siem.WriteCef(report,
                        Path.Combine(opts.OutputDir, $"audit-{stamp}.cef"));

                // ── Lateral movement graph ────────────────────────────────────
                // Build a graph from the findings and compute attack paths to
                // high-value targets. Always generated unless explicitly disabled.
                if (!opts.NoGraph)
                {
                    Console.WriteLine("[*] Building lateral movement graph...");
                    var graphBuilder = new PathGraphBuilder(config);
                    var graph        = graphBuilder.Build(report.Findings, opts.Hosts, opts.Domain);
                    var graphRenderer = new Reports.GraphRenderer();

                    graphRenderer.WriteHtml(graph,
                        Path.Combine(opts.OutputDir, $"lateral-graph-{stamp}.html"));
                    graphRenderer.WriteJson(graph,
                        Path.Combine(opts.OutputDir, $"lateral-graph-{stamp}.json"));

                    Console.WriteLine($"[+] Graph: {graph.Nodes.Count} nodes, " +
                        $"{graph.Edges.Count} edges, {graph.CriticalPaths.Count} attack path(s)");

                    var topPaths = graph.CriticalPaths
                        .Where(p => p.RiskScore >= 8.0).ToList();
                    if (topPaths.Count > 0)
                    {
                        Console.WriteLine($"\n[!] {topPaths.Count} CRITICAL attack path(s) found:");
                        foreach (var p in topPaths.Take(5))
                            Console.WriteLine($"    [{p.RiskScore:F1}] {p.Summary}");
                    }
                }

                // ── Raw reachability observations ─────────────────────────────
                // Written whenever probing ran, because Filtered results never
                // become findings yet are the evidence a boundary control works.
                if (orchestrator.Observations.Count > 0)
                {
                    var vantageIp   = Network.LocalAddressProvider.Primary();
                    var vantageZone = segmentation.IsConfigured
                        ? segmentation.Zones.Resolve(vantageIp).Id
                        : "unknown";

                    new ReachabilityRenderer().Write(
                        orchestrator.Observations,
                        orchestrator.ProbeStatistics,
                        vantageZone,
                        Path.Combine(opts.OutputDir, $"reachability-{stamp}.json"),
                        Environment.MachineName);

                    if (orchestrator.ProbeStatistics != null)
                        Console.WriteLine($"[*] Probes: {orchestrator.ProbeStatistics}");

                    // ── Segmentation analysis: observed vs declared policy ─────
                    if (segmentation.IsConfigured)
                    {
                        var analysis = new Analysis.PolicyEvaluator(segmentation).Analyze(
                            orchestrator.Observations,
                            Environment.MachineName,
                            vantageIp);

                        // Fold the AD / protocol / share findings in as context on the
                        // reachable paths they make worse. They remain reported in
                        // their own right; this adds the relationship between them.
                        var enriched = Analysis.EnrichmentCorrelator.Apply(
                            analysis, report.Findings);

                        if (enriched > 0)
                            Console.WriteLine(
                                $"[*] Enrichment: {enriched} reachable path(s) escalated by " +
                                "host configuration weaknesses.");

                        var segRenderer = new SegmentationReportRenderer();
                        segRenderer.WriteHtml(analysis,
                            Path.Combine(opts.OutputDir, $"segmentation-{stamp}.html"));
                        segRenderer.WriteJson(analysis,
                            Path.Combine(opts.OutputDir, $"segmentation-{stamp}.json"));
                        segRenderer.WriteExposureCsv(analysis,
                            Path.Combine(opts.OutputDir, $"exposure-register-{stamp}.csv"));

                        PrintSegmentationSummary(analysis);
                    }
                    else
                    {
                        Console.WriteLine(
                            "[!] No zone map configured -- the segmentation report " +
                            "(matrix, exposure register, ZTMM scorecard) was not produced.");
                    }
                }

                Console.WriteLine($"\n[+] Reports written to: {Path.GetFullPath(opts.OutputDir)}");
                return 0;
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("\n[!] Audit cancelled.");
                return 2;
            }
            catch (Exception ex)
            {
                PrintFriendlyError(ex);
                return 3;
            }
        }

        static void PrintSegmentationSummary(Models.SegmentationAnalysis analysis)
        {
            var violations = analysis.Violations.ToList();
            var critical   = violations.Count(v => v.Severity == Models.Severity.Critical);

            Console.WriteLine();
            Console.WriteLine($"[*] Segmentation (from zone '{analysis.VantageZoneId}'):");
            Console.WriteLine($"    Violations       {violations.Count} ({critical} critical)");
            Console.WriteLine($"    Unenforced paths {analysis.Unenforced.Count()}");
            Console.WriteLine($"    Enforced (good)  {analysis.EnforcementEvidence.Count()}");
            Console.WriteLine($"    Zone pairs       {analysis.Matrix.AssessedPairs}/{analysis.Matrix.TotalPairs} assessed");

            var segmentationScore = analysis.Scorecard.Functions
                .FirstOrDefault(f => f.Function == "Network Segmentation");
            if (segmentationScore is { Assessed: true })
                Console.WriteLine($"    CISA ZTMM        Network Segmentation = {segmentationScore.Stage}");

            foreach (var f in violations.Where(v => v.Severity == Models.Severity.Critical).Take(5))
                Console.WriteLine($"    [CRITICAL] {f.VantageZoneId} -> {f.TargetIp}:{f.Port} ({f.ServiceClass})");
        }

        // ── Error reporting ───────────────────────────────────────────────────

        static void PrintFriendlyError(Exception ex)
        {
            Console.Error.WriteLine($"\n[!] Fatal error: {ex.Message}");

            string? hint = ex switch
            {
                System.DirectoryServices.DirectoryServicesCOMException =>
                    "Active Directory / LDAP error -- verify the domain name is correct and this " +
                    "workstation is domain-joined or has line-of-sight to a Domain Controller.",
                System.Net.Sockets.SocketException =>
                    "Network error -- check that the hostname resolves and is reachable " +
                    "(try: nltest /dsgetdc:<domain> or ping <host>).",
                UnauthorizedAccessException =>
                    "Access denied -- verify the account running this tool has the required " +
                    "read permissions (see README > Permissions required).",
                System.ComponentModel.Win32Exception =>
                    "A Windows API call failed -- this is often a permissions or connectivity " +
                    "issue on the target host.",
                _ => null
            };

            if (hint != null)
                Console.Error.WriteLine($"    Hint: {hint}");

            if (Environment.GetEnvironmentVariable("ZTA_DEBUG") == "1")
                Console.Error.WriteLine(ex.StackTrace);
            else
                Console.Error.WriteLine("    (Set environment variable ZTA_DEBUG=1 to see the full stack trace.)");
        }

        static void PrintUsage()
        {
            Console.WriteLine(
                "\nUsage:\n" +
                "  ZeroTrustAuditor.exe --hosts h1,h2 --domain corp.local\n" +
                "  ZeroTrustAuditor.exe --hosts-file targets.txt --domain corp.local\n" +
                "\nSubcommands:\n" +
                "  merge <files...>  Combine reachability captures from several vantage\n" +
                "                    zones into one matrix. See: ZeroTrustAuditor merge\n" +
                "\nOptional flags:\n" +
                "  --output   ./reports          Output directory (default: ./reports)\n" +
                "  --config   audit-config.json  Config file path\n" +
                "  --skip-modules AdAuditor,ShareAuditor\n" +
                "             Comma-separated list of modules to skip.\n" +
                "             Valid names: AdAuditor, ProtocolProbe,\n" +
                "             LateralPathAnalyzer, ShareAuditor, SegmentationChecker\n" +
                "  --no-graph Skip lateral movement graph generation\n" +
                "\nSegmentation:\n" +
                "  --zones    zones.json         Zone map (CIDR -> zone, trust tier, role).\n" +
                "             Required for cross-zone analysis; without it those\n" +
                "             checks are SKIPPED rather than guessed at.\n" +
                "  --policy   policy.json        Approved cross-zone flows (default-deny).\n" +
                "  --services services.json      High-risk service catalog.\n" +
                "\nProbe safety:\n" +
                "  --max-concurrency 128         Ceiling on simultaneous probes.\n" +
                "  --rate 100                    Probes per second (0 = unlimited).\n" +
                "  --dry-run                     Plan the probes, send nothing.\n" +
                "  --allow-ot-probing            Permit ACTIVE probing of OT/ICS services.\n" +
                "             Off by default: an unexpected TCP connect can fault a\n" +
                "             controller. Also requires activeProbing=true on the zone.\n" +
                "  --help, -h Show this help text");
        }

        // ── Arg parsing ───────────────────────────────────────────────────────

        record Options(
            string[]  Hosts,
            string    Domain,
            string    OutputDir,
            string?   ConfigPath,
            string[]  SkipModules,
            bool      NoGraph,
            string?   ZonesPath,
            string?   PolicyPath,
            string?   ServicesPath,
            int?      MaxConcurrency,
            int?      ProbesPerSecond,
            bool      AllowOtProbing,
            bool      DryRun);

        static Options? ParseArgs(string[] args)
        {
            string? hostsArg     = null;
            string? hostsFile    = null;
            string? domain       = null;
            string  outputDir    = "./reports";
            string? configPath   = null;
            string? skipModules  = null;
            bool    noGraph      = false;
            string? zonesPath      = null;
            string? policyPath     = null;
            string? servicesPath   = null;
            int?    maxConcurrency = null;
            int?    probesPerSec   = null;
            bool    allowOtProbing = false;
            bool    dryRun         = false;

            // Fix: use args.Length (not args.Length - 1) so the last flag is never skipped.
            // Each value flag consumes args[i] (the flag) and args[++i] (the value),
            // so the bounds check inside the switch handles the edge case safely.
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--hosts":
                        if (i + 1 < args.Length) hostsArg    = args[++i]; break;
                    case "--hosts-file":
                        if (i + 1 < args.Length) hostsFile   = args[++i]; break;
                    case "--domain":
                        if (i + 1 < args.Length) domain      = args[++i]; break;
                    case "--output":
                        if (i + 1 < args.Length) outputDir   = args[++i]; break;
                    case "--config":
                        if (i + 1 < args.Length) configPath  = args[++i]; break;
                    case "--skip-modules":
                        if (i + 1 < args.Length) skipModules = args[++i]; break;
                    case "--zones":
                        if (i + 1 < args.Length) zonesPath    = args[++i]; break;
                    case "--policy":
                        if (i + 1 < args.Length) policyPath   = args[++i]; break;
                    case "--services":
                        if (i + 1 < args.Length) servicesPath = args[++i]; break;
                    case "--max-concurrency":
                        if (i + 1 < args.Length && int.TryParse(args[++i], out var mc))
                            maxConcurrency = mc;
                        break;
                    case "--rate":
                        if (i + 1 < args.Length && int.TryParse(args[++i], out var rate))
                            probesPerSec = rate;
                        break;
                    case "--allow-ot-probing":
                        allowOtProbing = true; break;
                    case "--dry-run":
                        dryRun = true; break;
                    case "--no-graph":
                        noGraph = true; break;
                }
            }

            if (domain == null)
            {
                Console.Error.WriteLine("[!] Missing required flag: --domain");
                PrintUsage();
                return null;
            }

            // Resolve host list
            string[] hosts;

            if (hostsFile != null)
            {
                // Resolve relative paths from the current working directory
                var resolvedPath = Path.IsPathRooted(hostsFile)
                    ? hostsFile
                    : Path.Combine(Directory.GetCurrentDirectory(), hostsFile);

                if (!File.Exists(resolvedPath))
                {
                    Console.Error.WriteLine($"[!] Hosts file not found: {resolvedPath}");
                    Console.Error.WriteLine($"    Current directory: {Directory.GetCurrentDirectory()}");
                    return null;
                }

                hosts = File.ReadAllLines(resolvedPath)
                    .Select(l => l.Trim())
                    .Where(l => l.Length > 0 && !l.StartsWith('#') && !l.StartsWith("//"))
                    .ToArray();

                Console.WriteLine($"[*] Hosts file: {resolvedPath}");
            }
            else if (hostsArg != null)
            {
                hosts = hostsArg.Split(',',
                    StringSplitOptions.RemoveEmptyEntries |
                    StringSplitOptions.TrimEntries);
            }
            else
            {
                Console.Error.WriteLine("[!] Specify --hosts or --hosts-file.");
                return null;
            }

            if (hosts.Length == 0)
            {
                Console.Error.WriteLine("[!] No hosts resolved from input. Check the file is not empty and has no BOM.");
                return null;
            }

            Console.WriteLine($"[*] Hosts in scope: {hosts.Length}");
            foreach (var h in hosts)
                Console.WriteLine($"    {h}");

            // Parse skip-modules list
            var skipList = skipModules == null
                ? Array.Empty<string>()
                : skipModules.Split(',',
                    StringSplitOptions.RemoveEmptyEntries |
                    StringSplitOptions.TrimEntries);

            return new Options(hosts, domain, outputDir, configPath, skipList, noGraph,
                               zonesPath, policyPath, servicesPath,
                               maxConcurrency, probesPerSec, allowOtProbing, dryRun);
        }

        static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(
                "  ZeroTrustAuditor v2.0 | Pure C# Zero Trust Assessment\n" +
                "  No PowerShell. No WMI. No external processes.\n");
            Console.ResetColor();
        }
    }
}
