using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ZeroTrustAuditor.Analysis;
using ZeroTrustAuditor.Config;
using ZeroTrustAuditor.Reports;

namespace ZeroTrustAuditor.Commands
{
    /// <summary>
    /// Combines reachability files captured from several vantage points.
    ///
    ///   ZeroTrustAuditor merge run-user.json run-dmz.json run-mgmt.json
    ///                          --output merged.json --zones zones.json --report
    ///
    /// One run measures one source zone, so one row of the zone matrix. Running from
    /// a host in each zone and merging is the honest way to fill in the rest -- no
    /// agents, no deployed infrastructure, nothing needing a change window.
    /// </summary>
    public static class MergeCommand
    {
        public static int Run(string[] args)
        {
            var inputs       = new List<string>();
            string? output   = null;
            string? zones    = null;
            string? policy   = null;
            string? services = null;
            var     report   = false;

            for (var i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--output" or "-o":
                        if (i + 1 < args.Length) output = args[++i];
                        break;
                    case "--zones":
                        if (i + 1 < args.Length) zones = args[++i];
                        break;
                    case "--policy":
                        if (i + 1 < args.Length) policy = args[++i];
                        break;
                    case "--services":
                        if (i + 1 < args.Length) services = args[++i];
                        break;
                    case "--report":
                        report = true;
                        break;
                    default:
                        if (!args[i].StartsWith('-')) inputs.Add(args[i]);
                        break;
                }
            }

            if (inputs.Count == 0)
            {
                PrintUsage();
                return 1;
            }

            if (inputs.Count == 1)
                Console.WriteLine(
                    "[*] Only one input file: this will normalise it, but adds no coverage.");

            Console.WriteLine($"[*] Merging {inputs.Count} reachability file(s)...");

            var result = ObservationMerger.Merge(inputs);

            foreach (var warning in result.Warnings) Console.WriteLine($"[warn] {warning}");
            foreach (var error   in result.Errors)   Console.Error.WriteLine($"[!] {error}");

            if (result.HasErrors && result.Document.Observations.Count == 0)
            {
                Console.Error.WriteLine("[!] Nothing could be merged.");
                return 3;
            }

            var document = result.Document;

            Console.WriteLine(
                $"[+] Read {result.TotalRead} observation(s) from {result.FilesRead} file(s); " +
                $"{document.Observations.Count} unique after merge " +
                $"({result.Deduplicated} duplicate key(s) resolved).");

            Console.WriteLine(
                $"[+] Vantage zones covered: {string.Join(", ", document.VantageZones)}");

            if (document.Conflicts.Count > 0)
            {
                Console.WriteLine(
                    $"[!] {document.Conflicts.Count} path(s) disagreed between runs. A path open " +
                    "in one capture and filtered in another means the control changed, or is " +
                    "not stable. These are listed in the merged file.");

                foreach (var conflict in document.Conflicts.Take(5))
                    Console.WriteLine(
                        $"    {conflict.Key}: kept {conflict.KeptVerdict} over " +
                        $"{conflict.OtherVerdict} ({conflict.Reason})");
            }

            output ??= "merged-reachability.json";
            new ReachabilityRenderer().Write(document, output);

            if (!report) return 0;

            // ── Optional: full segmentation report across all vantages ────────
            if (string.IsNullOrWhiteSpace(zones))
            {
                Console.Error.WriteLine(
                    "[!] --report needs --zones: without a zone map, observations cannot be " +
                    "placed in a matrix.");
                return 4;
            }

            var context = SegmentationConfigLoader.Load(zones, policy, services);
            context.Validation.PrintTo(Console.Out, Console.Error);

            if (context.Validation.HasErrors)
            {
                Console.Error.WriteLine("[!] Zone or policy configuration has errors; report skipped.");
                return 4;
            }

            var analysis = new PolicyEvaluator(context).Analyze(
                document.Observations, document.VantageHost, vantageIp: null);

            var stamp    = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
            var dir      = Path.GetDirectoryName(Path.GetFullPath(output));
            var renderer = new SegmentationReportRenderer();

            var htmlPath = Path.Combine(dir ?? ".", $"segmentation-merged-{stamp}.html");
            var jsonPath = Path.Combine(dir ?? ".", $"segmentation-merged-{stamp}.json");
            var csvPath  = Path.Combine(dir ?? ".", $"exposure-register-merged-{stamp}.csv");

            renderer.WriteHtml(analysis, htmlPath);
            renderer.WriteJson(analysis, jsonPath);
            renderer.WriteExposureCsv(analysis, csvPath);

            Console.WriteLine(
                $"[+] Merged matrix covers {analysis.Matrix.AssessedPairs} of " +
                $"{analysis.Matrix.TotalPairs} zone pair(s) across " +
                $"{analysis.VantageZones.Count} vantage zone(s).");

            return 0;
        }

        private static void PrintUsage()
        {
            Console.WriteLine(
                "\nUsage:\n" +
                "  ZeroTrustAuditor merge <file1.json> <file2.json> [...] [options]\n" +
                "\nCombines reachability captures taken from different vantage zones.\n" +
                "Each run measures ONE source zone; merging fills in additional matrix rows.\n" +
                "\nOptions:\n" +
                "  --output, -o merged.json   Output path (default: merged-reachability.json)\n" +
                "  --report                   Also render the combined segmentation report\n" +
                "  --zones    zones.json      Zone map (required with --report)\n" +
                "  --policy   policy.json     Approved cross-zone flows\n" +
                "  --services services.json   High-risk service catalog\n" +
                "\nExample:\n" +
                "  ZeroTrustAuditor merge reports\\reach-user.json reports\\reach-dmz.json \\\n" +
                "                         --zones zones.json --policy policy.json --report\n");
        }
    }
}
