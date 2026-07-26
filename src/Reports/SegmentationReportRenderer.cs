using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Reports
{
    /// <summary>
    /// Renders the segmentation assessment: zone matrix, endpoint exposure
    /// register, violations, enforcement evidence, and the NSA/CISA guidance that
    /// applies to each.
    /// </summary>
    public class SegmentationReportRenderer
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            Converters    = { new JsonStringEnumConverter() },
        };

        public void WriteJson(SegmentationAnalysis analysis, string path)
        {
            File.WriteAllText(
                path, JsonSerializer.Serialize(analysis, JsonOpts), ReportRenderer.Utf8NoBom);
            Console.WriteLine($"[+] Segmentation JSON: {path}");
        }

        /// <summary>
        /// The endpoint exposure register as CSV -- which endpoints allow which
        /// high-risk ports, sortable in a spreadsheet and pasteable into a ticket.
        /// </summary>
        public void WriteExposureCsv(SegmentationAnalysis analysis, string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine("TargetIp,Hostname,Zone,ZoneRole,ZoneTier,WorstSeverity," +
                          "BlastRadius,ReachableFromZones,OpenServices,Violations");

            foreach (var e in analysis.Exposures)
            {
                var violations = e.Services.Count(s => s.Policy == PolicyStatus.Violation);

                sb.AppendLine(string.Join(",",
                    ReportRenderer.Q(e.TargetIp),
                    ReportRenderer.Q(e.Hostname ?? ""),
                    ReportRenderer.Q(e.ZoneName),
                    ReportRenderer.Q(e.ZoneRole),
                    e.ZoneTier.ToString(CultureInfo.InvariantCulture),
                    ReportRenderer.Q(e.WorstSeverity.ToString()),
                    e.BlastRadius.ToString(CultureInfo.InvariantCulture),
                    ReportRenderer.Q(string.Join(" ", e.ReachableFromZones)),
                    ReportRenderer.Q(e.OpenServiceSummary),
                    violations.ToString(CultureInfo.InvariantCulture)));
            }

            File.WriteAllText(path, sb.ToString(), ReportRenderer.Utf8NoBom);
            Console.WriteLine($"[+] Exposure register CSV: {path}");
        }

        // ── HTML ──────────────────────────────────────────────────────────────

        public void WriteHtml(SegmentationAnalysis analysis, string path)
        {
            var sb = new StringBuilder();

            sb.Append(HtmlHead);
            AppendHeader(sb, analysis);
            AppendSummary(sb, analysis);
            AppendMatrix(sb, analysis);
            AppendExposureRegister(sb, analysis);
            AppendViolations(sb, analysis);
            AppendScorecard(sb, analysis);
            AppendEnforcementEvidence(sb, analysis);
            AppendProgramGuidance(sb, analysis);
            sb.Append(HtmlTail);

            File.WriteAllText(path, sb.ToString(), ReportRenderer.Utf8NoBom);
            Console.WriteLine($"[+] Segmentation HTML: {path}");
        }

        private static void AppendHeader(StringBuilder sb, SegmentationAnalysis a)
        {
            sb.AppendLine($"""
<header>
  <h1>Network Segmentation Assessment</h1>
  <p>Vantage: <strong>{E(a.VantageZoneId)}</strong> ({E(a.VantageIp)} on {E(a.VantageHost)})
     &nbsp;|&nbsp; Generated {a.GeneratedAt:yyyy-MM-dd HH:mm} UTC</p>
</header>
""");
        }

        private static void AppendSummary(StringBuilder sb, SegmentationAnalysis a)
        {
            var violations = a.Violations.Count();
            var critical   = a.Violations.Count(v => v.Severity == Severity.Critical);
            var unenforced = a.Unenforced.Count();
            var enforced   = a.EnforcementEvidence.Count();
            var exposed    = a.Exposures.Count(e => e.OpenHighRiskServices.Any());

            sb.AppendLine($"""
<section class="summary">
  <div class="card crit"><div class="n">{critical}</div><div class="l">Critical violations</div></div>
  <div class="card high"><div class="n">{violations}</div><div class="l">Total violations</div></div>
  <div class="card med"><div class="n">{unenforced}</div><div class="l">Unenforced paths</div></div>
  <div class="card ok"><div class="n">{enforced}</div><div class="l">Enforced (working)</div></div>
  <div class="card"><div class="n">{exposed}</div><div class="l">Exposed endpoints</div></div>
  <div class="card"><div class="n">{a.Matrix.AssessedPairs}/{a.Matrix.TotalPairs}</div><div class="l">Zone pairs assessed</div></div>
</section>
""");

            if (a.UnmappedEndpointCount > 0)
            {
                sb.AppendLine($"""
<div class="callout warn">
  <strong>{a.UnmappedEndpointCount} endpoint(s) matched no declared zone.</strong>
  They are scored as untrusted. An unmapped host is a data-flow-mapping gap:
  NSA's Network and Environment pillar names data flow mapping as the capability
  segmentation depends on &mdash; you cannot segment what you have not inventoried.
</div>
""");
            }

            sb.AppendLine($"""
<div class="callout info">
  <strong>Coverage.</strong> This run measured reachability <em>from</em>
  <code>{E(a.VantageZoneId)}</code> only. Every other row of the matrix is
  <em>unassessed</em>, which is not the same as clean. Run from a host in each
  source zone to fill the remaining rows.
</div>
""");
        }

        private static void AppendMatrix(StringBuilder sb, SegmentationAnalysis a)
        {
            sb.AppendLine("""
<section>
<h2>Zone reachability matrix</h2>
<p class="hint">Rows are source zones, columns destinations. Colour shows the worst
outcome found for that pair. Grey means no probe was made from that source zone.</p>
<div class="scroll">
<table class="matrix">
<thead><tr><th>from &rarr; to</th>
""");

            foreach (var zone in a.Matrix.Zones)
                sb.AppendLine($"<th>{E(zone.Id)}</th>");

            sb.AppendLine("</tr></thead><tbody>");

            foreach (var from in a.Matrix.Zones)
            {
                sb.AppendLine($"<tr><th class=\"rowhead\">{E(from.Id)}<span class=\"tier\">tier {from.Tier}</span></th>");

                foreach (var to in a.Matrix.Zones)
                {
                    var cell = a.Matrix.Cell(from.Id, to.Id);

                    if (cell is not { Assessed: true })
                    {
                        sb.AppendLine("<td class=\"m-na\" title=\"Not assessed from this vantage\">&ndash;</td>");
                        continue;
                    }

                    var cls = cell.ViolationCount > 0
                        ? (cell.WorstSeverity == Severity.Critical ? "m-crit" : "m-high")
                        : cell.UnenforcedCount > 0 ? "m-med"
                        : cell.FilteredCount > 0   ? "m-ok"
                        : "m-none";

                    var label = cell.ViolationCount > 0
                        ? cell.ViolationCount.ToString(CultureInfo.InvariantCulture)
                        : cell.UnenforcedCount > 0 ? "!"
                        : cell.FilteredCount > 0   ? "&#10003;"
                        : "&middot;";

                    var title = $"{cell.OpenCount} open, {cell.ClosedCount} closed, " +
                                $"{cell.FilteredCount} filtered" +
                                (cell.CrossingServices.Count > 0
                                    ? $" | crossing: {string.Join(", ", cell.CrossingServices)}"
                                    : "");

                    sb.AppendLine($"<td class=\"{cls}\" title=\"{E(title)}\">{label}</td>");
                }

                sb.AppendLine("</tr>");
            }

            sb.AppendLine("""
</tbody></table></div>
<p class="legend">
  <span class="sw m-crit"></span> critical violation
  <span class="sw m-high"></span> violation
  <span class="sw m-med"></span> unenforced (nothing blocking)
  <span class="sw m-ok"></span> enforced
  <span class="sw m-na"></span> not assessed
</p>
</section>
""");
        }

        private static void AppendExposureRegister(StringBuilder sb, SegmentationAnalysis a)
        {
            sb.AppendLine("""
<section>
<h2>Endpoint exposure register</h2>
<p class="hint">Which endpoints allow high-risk ports, from where, and how far a
compromise would reach. Sorted by severity, then blast radius.</p>
<div class="scroll">
<table>
<thead><tr>
  <th>Endpoint</th><th>Zone</th><th>Role</th><th>Tier</th>
  <th>Open high-risk services</th><th>Worst</th><th>Reachable from</th>
</tr></thead><tbody>
""");

            var rows = a.Exposures.Where(e => e.Services.Any(
                s => s.Verdict == ReachabilityVerdict.Open)).ToList();

            if (rows.Count == 0)
            {
                sb.AppendLine("""
<tr><td colspan="7" class="empty">No endpoint was found reachable on any probed
high-risk port from this vantage zone.</td></tr>
""");
            }

            foreach (var e in rows)
            {
                var services = string.Join(" ", e.Services
                    .Where(s => s.Verdict == ReachabilityVerdict.Open)
                    .OrderByDescending(s => s.Severity)
                    .Select(s =>
                    {
                        var flag = s.Confirmation?.StartsWith("MISMATCH") == true
                            ? " <span class=\"mismatch\" title=\"" + E(s.Confirmation) + "\">&#9888;</span>"
                            : "";
                        return $"<span class=\"svc {SevClass(s.Severity)}\">{E(s.ServiceClassId)}" +
                               $"<em>{s.Port}</em></span>{flag}";
                    }));

                sb.AppendLine($"""
<tr>
  <td><code>{E(e.TargetIp)}</code>{(string.IsNullOrEmpty(e.Hostname) ? "" : "<br/><span class=\"host\">" + E(e.Hostname!) + "</span>")}</td>
  <td>{E(e.ZoneName)}</td>
  <td>{E(e.ZoneRole)}</td>
  <td>{e.ZoneTier}</td>
  <td>{services}</td>
  <td><span class="badge {SevClass(e.WorstSeverity)}">{e.WorstSeverity}</span></td>
  <td>{E(string.Join(", ", e.ReachableFromZones))} <span class="blast">({e.BlastRadius})</span></td>
</tr>
""");
            }

            sb.AppendLine("</tbody></table></div></section>");
        }

        private static void AppendViolations(StringBuilder sb, SegmentationAnalysis a)
        {
            sb.AppendLine("""
<section>
<h2>Policy violations</h2>
<p class="hint">Reachable paths that declared policy does not permit, worst first.
Each carries the exact boundary change and the guidance that covers it.</p>
""");

            var violations = a.Violations.ToList();

            if (violations.Count == 0)
            {
                sb.AppendLine("""
<div class="callout ok"><strong>No policy violations from this vantage zone.</strong>
Confirm the remaining matrix rows before treating the estate as segmented.</div>
""");
            }

            foreach (var f in violations.Take(200))
            {
                sb.AppendLine($"""
<article class="finding {SevClass(f.Severity)}">
  <div class="fhead">
    <span class="badge {SevClass(f.Severity)}">{f.Severity}</span>
    <span class="path"><code>{E(f.VantageZoneId)}</code> &rarr;
      <code>{E(f.TargetIp)}</code>:<strong>{f.Port}</strong>
      <span class="svcname">{E(f.ServiceClass)}</span></span>
    <span class="score">{f.RiskScore:F1}</span>
  </div>
  <p>{E(f.Description)}</p>
  <p class="remedy"><strong>Fix:</strong> {E(f.Remediation)}</p>
  <details><summary>Evidence &amp; guidance</summary>
    <pre class="ev">{E(f.Evidence.ToString())}
confidence={f.Confidence:F2}  verdict={f.Verdict}  policy={f.Policy}</pre>
    <ul class="guidance">
""");
                foreach (var g in f.Guidance)
                {
                    var link = string.IsNullOrEmpty(g.Url)
                        ? E(g.Document)
                        : $"<a href=\"{E(g.Url)}\" rel=\"noreferrer\">{E(g.Document)}</a>";
                    sb.AppendLine($"<li><span class=\"src\">{E(g.Source)}</span> {link}<br/><span class=\"sec\">{E(g.Section)}</span></li>");
                }
                sb.AppendLine("</ul></details></article>");
            }

            if (violations.Count > 200)
                sb.AppendLine($"<p class=\"hint\">Showing 200 of {violations.Count}. " +
                              "The full set is in the JSON output.</p>");

            sb.AppendLine("</section>");
        }

        private static void AppendScorecard(StringBuilder sb, SegmentationAnalysis a)
        {
            sb.AppendLine("""
<section>
<h2>CISA Zero Trust Maturity Model &mdash; Networks pillar</h2>
""");
            sb.AppendLine($"<p class=\"hint\">{E(a.Scorecard.Caveat)}</p>");
            sb.AppendLine("<div class=\"scroll\"><table><thead><tr><th>Function</th><th>Stage</th><th>Evidence</th><th>Next step</th></tr></thead><tbody>");

            foreach (var f in a.Scorecard.Functions)
            {
                var stage = f.Assessed
                    ? $"<span class=\"stage s{(int)f.Stage}\">{f.Stage}</span>"
                    : "<span class=\"stage na\">not assessed</span>";

                sb.AppendLine($"<tr><td><strong>{E(f.Function)}</strong></td><td>{stage}</td>" +
                              $"<td>{E(f.Evidence)}</td><td>{E(f.NextStep)}</td></tr>");
            }

            sb.AppendLine("</tbody></table></div></section>");
        }

        private static void AppendEnforcementEvidence(StringBuilder sb, SegmentationAnalysis a)
        {
            var enforced = a.EnforcementEvidence.ToList();
            if (enforced.Count == 0) return;

            var byPair = enforced
                .GroupBy(f => $"{f.VantageZoneId} → {f.TargetZoneId}")
                .OrderByDescending(g => g.Count());

            sb.AppendLine("""
<section>
<h2>Enforcement evidence</h2>
<p class="hint">Boundaries that actively blocked the probe. An assessment that
reports only failures gets ignored &mdash; this is what is working, and what you
should avoid regressing.</p>
<div class="scroll"><table><thead><tr><th>Zone pair</th><th>Blocked probes</th><th>Services</th></tr></thead><tbody>
""");

            foreach (var group in byPair)
            {
                var services = string.Join(", ",
                    group.Select(f => f.ServiceClass).Distinct().OrderBy(s => s));
                sb.AppendLine($"<tr><td><code>{E(group.Key)}</code></td><td>{group.Count()}</td>" +
                              $"<td>{E(services)}</td></tr>");
            }

            sb.AppendLine("</tbody></table></div></section>");
        }

        private static void AppendProgramGuidance(StringBuilder sb, SegmentationAnalysis a)
        {
            sb.AppendLine("""
<section>
<h2>Segmentation guidance &mdash; NSA and CISA</h2>
<p class="hint">Programme-level references behind the findings above.</p>
<ul class="guidance big">
""");
            foreach (var g in a.ProgramGuidance)
            {
                var link = string.IsNullOrEmpty(g.Url)
                    ? E(g.Document)
                    : $"<a href=\"{E(g.Url)}\" rel=\"noreferrer\">{E(g.Document)}</a>";
                sb.AppendLine($"<li><span class=\"src\">{E(g.Source)}</span> {link}<br/>" +
                              $"<span class=\"sec\">{E(g.Section)}</span></li>");
            }
            sb.AppendLine("</ul></section>");
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static string E(string? s) => WebUtility.HtmlEncode(s ?? string.Empty);

        private static string SevClass(Severity s) => s switch
        {
            Severity.Critical => "crit",
            Severity.High     => "high",
            Severity.Medium   => "med",
            Severity.Low      => "low",
            _                 => "info",
        };

        private const string HtmlHead = """
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Segmentation Assessment</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f4f5f7;
     color:#1d2330;font-size:14px;line-height:1.55;padding-bottom:60px}
header{background:#12182b;color:#fff;padding:24px 32px}
header h1{font-size:21px;font-weight:650}
header p{opacity:.7;font-size:12px;margin-top:5px}
section{padding:22px 32px}
h2{font-size:16px;margin-bottom:6px}
.hint{font-size:12px;color:#5b6478;margin-bottom:12px;max-width:105ch}
.summary{display:flex;gap:12px;flex-wrap:wrap;padding:20px 32px 4px}
.card{background:#fff;border-radius:9px;padding:14px 18px;flex:1;min-width:132px;text-align:center;
      box-shadow:0 1px 3px rgba(0,0,0,.09)}
.card .n{font-size:26px;font-weight:700}.card .l{font-size:10.5px;color:#6b7280;
      text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
.card.crit .n{color:#dc2626}.card.high .n{color:#ea580c}
.card.med .n{color:#d97706}.card.ok .n{color:#16a34a}
.callout{margin:14px 32px;padding:11px 14px;border-radius:8px;font-size:12.5px;border-left:4px solid}
.callout.warn{background:#fffbeb;border-color:#f59e0b}
.callout.info{background:#eff6ff;border-color:#3b82f6}
.callout.ok{background:#f0fdf4;border-color:#16a34a}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;
      box-shadow:0 1px 3px rgba(0,0,0,.08);font-size:12.5px}
th{background:#f9fafb;padding:8px 11px;text-align:left;font-size:10.5px;text-transform:uppercase;
   letter-spacing:.4px;color:#6b7280;border-bottom:1px solid #e5e7eb;white-space:nowrap}
td{padding:8px 11px;border-bottom:1px solid #f3f4f6;vertical-align:top}
tr:last-child td{border-bottom:none}
td.empty{text-align:center;color:#6b7280;padding:22px}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;background:#f3f4f6;
     padding:1px 5px;border-radius:3px}
.host{font-size:11px;color:#6b7280}
.matrix td{text-align:center;font-weight:650;min-width:44px}
.matrix .rowhead{background:#fff;text-transform:none;font-size:11.5px;color:#1d2330}
.matrix .tier{display:block;font-size:9.5px;color:#9ca3af;font-weight:400}
.m-crit{background:#dc2626;color:#fff}.m-high{background:#f97316;color:#fff}
.m-med{background:#fbbf24;color:#3f2d00}.m-ok{background:#bbf7d0;color:#14532d}
.m-none{background:#f9fafb;color:#9ca3af}.m-na{background:#e5e7eb;color:#9ca3af}
.legend{margin-top:9px;font-size:11.5px;color:#5b6478;display:flex;gap:14px;flex-wrap:wrap;align-items:center}
.sw{display:inline-block;width:13px;height:13px;border-radius:3px;vertical-align:-2px;margin-right:4px}
.badge{display:inline-block;padding:2px 8px;border-radius:11px;font-size:10px;font-weight:650}
.badge.crit{background:#fee2e2;color:#991b1b}.badge.high{background:#ffedd5;color:#9a3412}
.badge.med{background:#fef3c7;color:#92400e}.badge.low{background:#dcfce7;color:#166534}
.badge.info{background:#f3f4f6;color:#374151}
.svc{display:inline-block;padding:2px 7px;border-radius:5px;margin:1px 3px 1px 0;font-size:11px;font-weight:600}
.svc em{font-style:normal;opacity:.65;margin-left:4px}
.svc.crit{background:#fee2e2;color:#991b1b}.svc.high{background:#ffedd5;color:#9a3412}
.svc.med{background:#fef3c7;color:#92400e}.svc.low{background:#dcfce7;color:#166534}
.svc.info{background:#f3f4f6;color:#374151}
.mismatch{color:#b45309;cursor:help}
.blast{color:#9ca3af;font-size:11px}
.finding{background:#fff;border-radius:9px;padding:13px 16px;margin-bottom:9px;
         box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #d1d5db}
.finding.crit{border-left-color:#dc2626}.finding.high{border-left-color:#f97316}
.finding.med{border-left-color:#fbbf24}.finding.low{border-left-color:#16a34a}
.fhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.fhead .path{font-size:12.5px}.fhead .svcname{color:#6b7280;font-size:11.5px;margin-left:5px}
.fhead .score{margin-left:auto;font-weight:700;color:#6b7280}
.finding p{font-size:12.5px;margin-bottom:5px;max-width:110ch}
.remedy{color:#14532d}
details{margin-top:7px}summary{cursor:pointer;font-size:11.5px;color:#4b5563}
pre.ev{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10.5px;background:#f9fafb;
       padding:7px 9px;border-radius:5px;margin:7px 0;white-space:pre-wrap;word-break:break-word}
ul.guidance{list-style:none;font-size:11.5px}
ul.guidance li{padding:6px 0;border-top:1px solid #f3f4f6}
ul.guidance .src{display:inline-block;background:#12182b;color:#fff;font-size:9.5px;font-weight:700;
     padding:1px 6px;border-radius:3px;margin-right:6px;letter-spacing:.3px}
ul.guidance .sec{color:#5b6478}
ul.guidance.big{background:#fff;border-radius:9px;padding:6px 16px;box-shadow:0 1px 3px rgba(0,0,0,.08);font-size:12.5px}
.stage{display:inline-block;padding:2px 9px;border-radius:11px;font-size:10.5px;font-weight:650;white-space:nowrap}
.stage.s0{background:#fee2e2;color:#991b1b}.stage.s1{background:#ffedd5;color:#9a3412}
.stage.s2{background:#dbeafe;color:#1e40af}.stage.s3{background:#dcfce7;color:#166534}
.stage.na{background:#f3f4f6;color:#6b7280}
a{color:#1d4ed8}
@media (max-width:720px){section{padding:18px 14px}.summary{padding:16px 14px 4px}.callout{margin:12px 14px}}
</style></head><body>
""";

        private const string HtmlTail = """
<footer style="text-align:center;padding:20px;font-size:11px;color:#9ca3af">
ZeroTrustAuditor &mdash; read-only segmentation assessment.
Unassessed zone pairs are not evidence of segmentation.
</footer>
</body></html>
""";
    }
}
