using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Reports
{
    public class ReportRenderer
    {
        /// <summary>
        /// UTF-8 WITHOUT a byte order mark.
        ///
        /// Encoding.UTF8 emits EF BB BF. A leading BOM makes the file invalid JSON per
        /// RFC 8259 and is rejected by strict parsers -- including Splunk HEC and the
        /// Sentinel Log Analytics ingestion API, which meant the SIEM outputs this tool
        /// advertised could not actually be ingested.
        /// </summary>
        internal static readonly Encoding Utf8NoBom = new UTF8Encoding(false);

        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            Converters    = { new JsonStringEnumConverter() }
        };

        // ── JSON ──────────────────────────────────────────────────────────────

        public void WriteJson(AuditReport report, string path)
        {
            File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOpts), Utf8NoBom);
            Console.WriteLine($"[+] JSON: {path}");
        }

        // ── CSV ───────────────────────────────────────────────────────────────

        public void WriteCsv(AuditReport report, string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,Host,Module,CheckName,Severity,RiskScore,Description,Evidence,Remediation");

            foreach (var f in report.Findings)
            {
                sb.AppendLine(string.Join(",",
                    Q(f.Id), Q(f.Host), Q(f.Module), Q(f.CheckName),
                    Q(f.Severity.ToString()), f.RiskScore.ToString("F1"),
                    Q(f.Description), Q(f.Evidence), Q(f.RemediationGuidance)));
            }

            File.WriteAllText(path, sb.ToString(), Utf8NoBom);
            Console.WriteLine($"[+] CSV:  {path}");
        }

        internal static string Q(string? s)
        {
            var v = (s ?? string.Empty)
                .Replace("\"", "\"\"")
                .Replace("\r", " ")     // was unhandled: a bare CR still broke the row
                .Replace("\n", " ");

            // Neutralise spreadsheet formula injection. These cells carry AD-controlled
            // strings (principal names, share names, group names), and Excel will
            // evaluate a leading =, +, - or @ as a formula on open.
            if (v.Length > 0 && (v[0] == '=' || v[0] == '+' || v[0] == '-' ||
                                 v[0] == '@' || v[0] == '\t'))
                v = "'" + v;

            return "\"" + v + "\"";
        }

        // ── HTML ──────────────────────────────────────────────────────────────

        public void WriteHtml(AuditReport report, string path)
        {
            var critical = report.Findings.Count(f => f.Severity == Severity.Critical);
            var high     = report.Findings.Count(f => f.Severity == Severity.High);
            var medium   = report.Findings.Count(f => f.Severity == Severity.Medium);
            var low      = report.Findings.Count(f => f.Severity == Severity.Low);
            var total    = report.Findings.Count;

            var sb = new StringBuilder();
            sb.Append("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZeroTrustAuditor Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:#f4f5f7;color:#1d2330;font-size:14px;line-height:1.6}
header{background:#1d2330;color:#fff;padding:24px 32px}
header h1{font-size:20px;font-weight:600}
header p{opacity:.6;font-size:12px;margin-top:4px}
.summary{display:flex;gap:12px;padding:20px 32px;flex-wrap:wrap}
.card{background:#fff;border-radius:8px;padding:16px 20px;flex:1;min-width:120px;
      box-shadow:0 1px 3px rgba(0,0,0,.08);text-align:center}
.card .num{font-size:28px;font-weight:700}
.card .lbl{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.5px;margin-top:2px}
.c-crit{color:#dc2626}.c-high{color:#ea580c}.c-med{color:#d97706}
.c-low{color:#16a34a}.c-info{color:#6b7280}
.findings{padding:0 32px 48px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
      overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}
th{background:#f9fafb;padding:9px 12px;text-align:left;font-size:11px;
   text-transform:uppercase;letter-spacing:.5px;color:#6b7280;border-bottom:1px solid #e5e7eb}
td{padding:9px 12px;border-bottom:1px solid #f3f4f6;vertical-align:top;font-size:12px}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:600}
.bC{background:#fee2e2;color:#991b1b}
.bH{background:#ffedd5;color:#9a3412}
.bM{background:#fef3c7;color:#92400e}
.bL{background:#dcfce7;color:#166534}
.bI{background:#f3f4f6;color:#374151}
.host{font-family:monospace;font-size:11px;background:#f3f4f6;padding:1px 5px;border-radius:3px}
.ev{font-family:monospace;font-size:10px;background:#f9fafb;padding:4px 6px;border-radius:3px;
    white-space:pre-wrap;word-break:break-all;max-height:60px;overflow-y:auto}
footer{text-align:center;padding:16px;font-size:11px;color:#9ca3af}
.card{cursor:pointer;transition:transform .15s,box-shadow .15s;border:2px solid transparent}
.card:hover{transform:translateY(-2px);box-shadow:0 4px 10px rgba(0,0,0,.12)}
.card.active{border-color:#1d2330}
.toolbar{display:flex;align-items:center;gap:16px;padding:0 32px 16px;flex-wrap:wrap}
.toolbar input[type=text]{flex:1;min-width:220px;padding:8px 12px;border:1px solid #d1d5db;
    border-radius:6px;font-size:13px;font-family:inherit}
.toolbar label{font-size:12px;color:#374151;display:flex;align-items:center;gap:6px;white-space:nowrap;cursor:pointer}
#resultCount{font-size:12px;color:#6b7280;white-space:nowrap}
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:#1d2330}
th.sortable::after{content:' \2195';opacity:.4;font-size:9px}
</style>
</head>
<body>
<header>
  <h1>ZeroTrustAuditor v2.0 -- Report</h1>
""");
            sb.AppendLine($"  <p>Domain: {WebUtility.HtmlEncode(report.Domain)} &nbsp;|&nbsp;" +
                          $" Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm} UTC &nbsp;|&nbsp;" +
                          $" Hosts: {report.TargetHosts.Length} &nbsp;|&nbsp;" +
                          $" Report ID: {report.ReportId}</p>");
            sb.Append("""
</header>
<div class="summary">
""");
            sb.AppendLine(Card("Critical", critical, "c-crit", "Critical"));
            sb.AppendLine(Card("High",     high,     "c-high", "High"));
            sb.AppendLine(Card("Medium",   medium,   "c-med",  "Medium"));
            sb.AppendLine(Card("Low",      low,      "c-low",  "Low"));
            sb.AppendLine(Card("Total",    total,    "c-info", null));
            sb.Append("""
</div>
<div class="toolbar">
  <input type="text" id="searchBox" placeholder="Search host, check, description, evidence..." oninput="applyFilters()">
  <label><input type="checkbox" id="groupToggle" onchange="applyFilters()"> Group by Check</label>
  <span id="resultCount"></span>
</div>
<div class="findings">
<table>
<thead><tr>
  <th class="sortable" onclick="sortBy(0)">Severity</th>
  <th class="sortable" onclick="sortBy(1)">Score</th>
  <th class="sortable" onclick="sortBy(2)">Host</th>
  <th class="sortable" onclick="sortBy(3)">Check</th>
  <th>Description</th><th>Evidence</th><th>Remediation</th>
</tr></thead>
<tbody id="findingsBody">
""");
            foreach (var f in report.Findings)
            {
                var bc = f.Severity switch
                {
                    Severity.Critical => "bC", Severity.High => "bH",
                    Severity.Medium   => "bM", Severity.Low  => "bL", _ => "bI"
                };
                sb.AppendLine($"""
<tr data-severity="{WebUtility.HtmlEncode(f.Severity.ToString())}" data-host="{WebUtility.HtmlEncode(f.Host)}" data-check="{WebUtility.HtmlEncode(f.CheckName)}" data-score="{f.RiskScore:F1}">
  <td><span class="badge {bc}">{WebUtility.HtmlEncode(f.Severity.ToString())}</span></td>
  <td><strong>{f.RiskScore:F1}</strong></td>
  <td><span class="host">{WebUtility.HtmlEncode(f.Host)}</span></td>
  <td>{WebUtility.HtmlEncode(f.CheckName)}</td>
  <td>{WebUtility.HtmlEncode(f.Description)}</td>
  <td><div class="ev">{WebUtility.HtmlEncode(f.Evidence)}</div></td>
  <td>{WebUtility.HtmlEncode(f.RemediationGuidance)}</td>
</tr>
""");
            }
            sb.Append("""
</tbody></table>
</div>
<footer>ZeroTrustAuditor v2.0 -- read-only, non-destructive assessment</footer>
""");
            sb.Append(InteractiveScript);
            sb.Append("""
</body></html>
""");
            File.WriteAllText(path, sb.ToString(), Utf8NoBom);
            Console.WriteLine($"[+] HTML: {path}");
        }

        private static string Card(string label, int count, string cls, string? severityFilter) =>
            $"<div class=\"card\" id=\"card-{label}\" " +
            $"onclick=\"filterSeverity({(severityFilter == null ? "null" : $"'{severityFilter}'")})\">" +
            $"<div class=\"num {cls}\">{count}</div>" +
            $"<div class=\"lbl\">{label}</div></div>";

        // Vanilla JS -- no external dependencies, no build step. Operates entirely
        // on the data-* attributes rendered onto each <tr> above.
        private const string InteractiveScript = """
<script>
const SEV_RANK = {Critical:4, High:3, Medium:2, Low:1, Informational:0};
let activeSeverity = null;
let sortState = {idx: -1, dir: 1};

function filterSeverity(sev) {
  activeSeverity = (activeSeverity === sev) ? null : sev;
  document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
  const activeId = activeSeverity ? ('card-' + activeSeverity) : 'card-Total';
  const el = document.getElementById(activeId);
  if (el) el.classList.add('active');
  applyFilters();
}

function applyFilters() {
  const q = document.getElementById('searchBox').value.toLowerCase();
  const group = document.getElementById('groupToggle').checked;
  const tbody = document.getElementById('findingsBody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  let shown = 0;

  rows.forEach(r => {
    const matchesSeverity = !activeSeverity || r.dataset.severity === activeSeverity;
    const matchesSearch = !q || r.textContent.toLowerCase().includes(q);
    const visible = matchesSeverity && matchesSearch;
    r.style.display = visible ? '' : 'none';
    if (visible) shown++;
  });

  if (group) {
    const sorted = rows.slice().sort((a, b) => {
      const c = a.dataset.check.localeCompare(b.dataset.check);
      return c !== 0 ? c : a.dataset.host.localeCompare(b.dataset.host);
    });
    sorted.forEach(r => tbody.appendChild(r));
  }

  document.getElementById('resultCount').textContent =
    'Showing ' + shown + ' of ' + rows.length + ' finding(s)';
}

function sortBy(idx) {
  const tbody = document.getElementById('findingsBody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const dir = (sortState.idx === idx) ? -sortState.dir : 1;
  sortState = {idx, dir};

  const keyFor = (row) => {
    if (idx === 0) return SEV_RANK[row.dataset.severity] ?? -1;
    if (idx === 1) return parseFloat(row.dataset.score) || 0;
    if (idx === 2) return row.dataset.host.toLowerCase();
    return row.dataset.check.toLowerCase();
  };

  rows.sort((a, b) => {
    const ka = keyFor(a), kb = keyFor(b);
    if (ka < kb) return -1 * dir;
    if (ka > kb) return 1 * dir;
    return 0;
  });

  rows.forEach(r => tbody.appendChild(r));
}

document.getElementById('card-Total').classList.add('active');
applyFilters();
</script>
""";
    }
}
