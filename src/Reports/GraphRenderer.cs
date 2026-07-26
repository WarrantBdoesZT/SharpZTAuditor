using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Reports
{
    /// <summary>
    /// Renders the lateral movement graph two ways:
    ///   1. An interactive, self-contained HTML page (D3.js force-directed graph)
    ///   2. A BloodHound-style JSON export for ingestion into other tooling
    /// </summary>
    public class GraphRenderer
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            Converters    = { new JsonStringEnumConverter() },
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        // ── JSON export ───────────────────────────────────────────────────────

        public void WriteJson(LateralMovementGraph graph, string path)
        {
            File.WriteAllText(path, JsonSerializer.Serialize(graph, JsonOpts), ReportRenderer.Utf8NoBom);
            Console.WriteLine($"[+] Graph JSON: {path}");
        }

        // ── Interactive HTML ────────────────────────────────────────────────────

        public void WriteHtml(LateralMovementGraph graph, string path)
        {
            // Serialize graph data as compact JSON to embed in the page
            var dataJson = JsonSerializer.Serialize(new
            {
                nodes = graph.Nodes,
                edges = graph.Edges,
                paths = graph.CriticalPaths,
            }, new JsonSerializerOptions
            {
                Converters = { new JsonStringEnumConverter() },
            });

            var criticalCount = graph.CriticalPaths.Count(p => p.RiskScore >= 8.0);
            var pathCount     = graph.CriticalPaths.Count;
            var nodeCount     = graph.Nodes.Count;
            var edgeCount     = graph.Edges.Count;

            var html = HtmlTemplate
                .Replace("{{DOMAIN}}", Esc(graph.Domain))
                .Replace("{{GENERATED}}", graph.GeneratedAt.ToString("yyyy-MM-dd HH:mm") + " UTC")
                .Replace("{{NODE_COUNT}}", nodeCount.ToString())
                .Replace("{{EDGE_COUNT}}", edgeCount.ToString())
                .Replace("{{PATH_COUNT}}", pathCount.ToString())
                .Replace("{{CRITICAL_COUNT}}", criticalCount.ToString())
                .Replace("{{GRAPH_DATA}}", dataJson)
                .Replace("{{PATHS_HTML}}", BuildPathsHtml(graph));

            File.WriteAllText(path, html, ReportRenderer.Utf8NoBom);
            Console.WriteLine($"[+] Graph HTML: {path}");
        }

        private string BuildPathsHtml(LateralMovementGraph graph)
        {
            if (graph.CriticalPaths.Count == 0)
                return "<p class='empty'>No attack paths to high-value targets were found. " +
                       "This is the desired Zero Trust outcome.</p>";

            var sb = new StringBuilder();
            int rank = 1;
            foreach (var p in graph.CriticalPaths.OrderByDescending(x => x.RiskScore))
            {
                var sevClass = p.RiskScore >= 8.0 ? "crit"
                             : p.RiskScore >= 6.0 ? "high"
                             : p.RiskScore >= 4.0 ? "med" : "low";

                sb.Append($@"
    <div class='path-card {sevClass}'>
      <div class='path-head'>
        <span class='rank'>#{rank}</span>
        <span class='path-route'>{Esc(p.StartNode)} &rarr; {Esc(p.EndNode)}</span>
        <span class='path-score {sevClass}'>{p.RiskScore:F1}</span>
      </div>
      <div class='path-meta'>{p.HopCount} hop(s) &middot; weight {p.TotalWeight:F1}</div>
      <ol class='hop-list'>");

                foreach (var h in p.Hops)
                {
                    sb.Append($@"
        <li>
          <span class='hop-from'>{Esc(h.From)}</span>
          <span class='hop-verb' title='{Esc(h.Mitre)}'>{h.EdgeType}</span>
          <span class='hop-to'>{Esc(h.To)}</span>
          <div class='hop-reason'>{Esc(h.Reason)}{(string.IsNullOrEmpty(h.Mitre) ? "" : $" <span class='mitre'>{Esc(h.Mitre)}</span>")}</div>
        </li>");
                }

                sb.Append(@"
      </ol>
    </div>");
                rank++;
            }
            return sb.ToString();
        }

        private static string Esc(string? s) =>
            System.Net.WebUtility.HtmlEncode(s ?? string.Empty);

        // ── HTML template (D3.js force-directed graph) ──────────────────────────

        private const string HtmlTemplate = @"<!DOCTYPE html>
<html lang=""en"">
<head>
<meta charset=""utf-8""/>
<meta name=""viewport"" content=""width=device-width,initial-scale=1""/>
<title>Lateral Movement Graph - {{DOMAIN}}</title>
<script src=""https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js""></script>
<style>
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
  --text:#e6edf3;--muted:#7d8590;--accent:#58a6ff;--green:#3fb950;
  --yellow:#d29922;--red:#f85149;--orange:#ff7b72;--purple:#bc8cff;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;
     display:flex;height:100vh;overflow:hidden}
#graph-pane{flex:1;position:relative}
#side-pane{width:420px;background:var(--bg2);border-left:1px solid var(--border);
           overflow-y:auto;padding:20px}
header{position:absolute;top:0;left:0;right:0;padding:16px 20px;
       background:linear-gradient(180deg,rgba(13,17,23,.95),transparent);z-index:10}
header h1{font-size:18px;font-weight:600;color:var(--accent)}
header .sub{font-size:12px;color:var(--muted);margin-top:2px}
.stats{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
.stat{background:var(--bg3);border:1px solid var(--border);border-radius:6px;
      padding:6px 12px}
.stat .n{font-size:18px;font-weight:700}
.stat .l{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.stat.crit .n{color:var(--red)}
svg{width:100%;height:100%;cursor:grab}
svg:active{cursor:grabbing}
.link{stroke-opacity:.4}
.link.path-edge{stroke:var(--red);stroke-opacity:.9;stroke-width:3px}
.node circle{stroke:#000;stroke-width:1.5px;cursor:pointer}
.node text{font-size:10px;fill:var(--text);pointer-events:none;
           text-shadow:0 1px 3px #000}
.legend{position:absolute;bottom:16px;left:20px;background:var(--bg2);
        border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-size:11px}
.legend h4{font-size:10px;text-transform:uppercase;letter-spacing:.08em;
           color:var(--muted);margin-bottom:8px}
.legend-row{display:flex;align-items:center;gap:8px;margin:4px 0}
.legend-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}
#side-pane h2{font-size:15px;font-weight:600;margin-bottom:4px}
#side-pane .side-sub{font-size:12px;color:var(--muted);margin-bottom:16px;
                     padding-bottom:12px;border-bottom:1px solid var(--border)}
.path-card{background:var(--bg3);border:1px solid var(--border);border-radius:8px;
           padding:12px;margin-bottom:12px;border-left-width:3px}
.path-card.crit{border-left-color:var(--red)}
.path-card.high{border-left-color:var(--orange)}
.path-card.med{border-left-color:var(--yellow)}
.path-card.low{border-left-color:var(--green)}
.path-head{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.rank{font-family:monospace;font-size:11px;color:var(--muted);font-weight:700}
.path-route{flex:1;font-size:13px;font-weight:600}
.path-score{font-family:monospace;font-size:14px;font-weight:700;
            padding:2px 8px;border-radius:10px}
.path-score.crit{background:rgba(248,81,73,.15);color:var(--red)}
.path-score.high{background:rgba(255,123,114,.15);color:var(--orange)}
.path-score.med{background:rgba(210,153,34,.15);color:var(--yellow)}
.path-score.low{background:rgba(63,185,80,.15);color:var(--green)}
.path-meta{font-size:11px;color:var(--muted);margin-bottom:8px}
.hop-list{list-style:none;padding-left:0}
.hop-list li{padding:6px 0;border-top:1px solid var(--border)}
.hop-from,.hop-to{font-family:monospace;font-size:11px;color:var(--text)}
.hop-verb{display:inline-block;font-family:monospace;font-size:9px;
          background:rgba(88,166,255,.15);color:var(--accent);padding:1px 6px;
          border-radius:8px;margin:0 6px}
.hop-reason{font-size:11px;color:var(--muted);margin-top:3px}
.mitre{font-family:monospace;font-size:9px;color:var(--purple);
       border:1px solid var(--purple);border-radius:6px;padding:0 4px;margin-left:4px}
.empty{color:var(--green);font-size:13px;padding:20px;text-align:center;
       background:rgba(63,185,80,.07);border:1px solid var(--green);border-radius:8px}
.tooltip{position:absolute;background:var(--bg3);border:1px solid var(--accent);
         border-radius:6px;padding:8px 10px;font-size:11px;pointer-events:none;
         opacity:0;transition:opacity .15s;z-index:100;max-width:240px}
.tab-row{display:flex;gap:4px;margin-bottom:16px}
.tab{padding:6px 14px;font-size:12px;border-radius:6px;cursor:pointer;
     background:var(--bg3);border:1px solid var(--border);color:var(--muted)}
.tab.active{background:var(--accent);color:#000;font-weight:600}
</style>
</head>
<body>

<div id=""graph-pane"">
  <header>
    <h1>Lateral Movement Graph</h1>
    <div class=""sub"">Domain: {{DOMAIN}} &middot; Generated {{GENERATED}}</div>
    <div class=""stats"">
      <div class=""stat""><div class=""n"">{{NODE_COUNT}}</div><div class=""l"">Nodes</div></div>
      <div class=""stat""><div class=""n"">{{EDGE_COUNT}}</div><div class=""l"">Edges</div></div>
      <div class=""stat""><div class=""n"">{{PATH_COUNT}}</div><div class=""l"">Attack Paths</div></div>
      <div class=""stat crit""><div class=""n"">{{CRITICAL_COUNT}}</div><div class=""l"">Critical Paths</div></div>
    </div>
  </header>

  <svg id=""graph""></svg>

  <div class=""legend"">
    <h4>Node Types</h4>
    <div class=""legend-row""><span class=""legend-dot"" style=""background:#f85149""></span>Domain Controller / Tier 0</div>
    <div class=""legend-row""><span class=""legend-dot"" style=""background:#d29922""></span>Server / Tier 1</div>
    <div class=""legend-row""><span class=""legend-dot"" style=""background:#58a6ff""></span>Workstation / Tier 2</div>
    <div class=""legend-row""><span class=""legend-dot"" style=""background:#bc8cff""></span>User / Service Account</div>
    <div class=""legend-row""><span class=""legend-dot"" style=""background:#3fb950""></span>Group</div>
    <div class=""legend-row""style=""margin-top:8px""><span style=""width:18px;height:3px;background:#f85149;display:inline-block""></span>&nbsp;Critical attack path</div>
  </div>

  <div class=""tooltip"" id=""tooltip""></div>
</div>

<div id=""side-pane"">
  <h2>Attack Paths to High-Value Targets</h2>
  <div class=""side-sub"">Ranked by risk. Each path shows how an attacker moves from a low-privilege foothold to a Domain Controller or privileged account.</div>
  {{PATHS_HTML}}
</div>

<script>
const DATA = {{GRAPH_DATA}};

// Build a set of edges that appear in any critical path for highlighting
const pathEdgeSet = new Set();
DATA.paths.forEach(p => {
  p.hops.forEach(h => {
    pathEdgeSet.add(h.from + '|' + h.to);
  });
});

const svg = d3.select('#graph');
const width = document.getElementById('graph-pane').clientWidth;
const height = window.innerHeight;
svg.attr('viewBox', [0, 0, width, height]);

const g = svg.append('g');

// Zoom / pan
svg.call(d3.zoom().scaleExtent([0.2, 4]).on('zoom', (e) => {
  g.attr('transform', e.transform);
}));

// Color by node type / tier
function nodeColor(n){
  if(n.type === 'DomainController') return '#f85149';
  if(n.type === 'Group')           return '#3fb950';
  if(n.type === 'User' || n.type === 'ServiceAccount') return '#bc8cff';
  if(n.tier === 1)                 return '#d29922';
  return '#58a6ff';
}
function nodeRadius(n){
  if(n.isHighValue) return 14;
  if(n.type === 'DomainController') return 14;
  if(n.tier === 1) return 10;
  return 7;
}

// Map labels back to node ids for path-edge matching
const labelToId = {};
DATA.nodes.forEach(n => { labelToId[n.label] = n.id; });

const links = DATA.edges.map(e => Object.assign({}, e));
const nodes = DATA.nodes.map(n => Object.assign({}, n));

const sim = d3.forceSimulation(nodes)
  .force('link', d3.forceLink(links).id(d => d.id).distance(90).strength(0.4))
  .force('charge', d3.forceManyBody().strength(-300))
  .force('center', d3.forceCenter(width/2, height/2))
  .force('collide', d3.forceCollide().radius(d => nodeRadius(d)+6));

// Arrow markers
svg.append('defs').selectAll('marker')
  .data(['default','path'])
  .join('marker')
    .attr('id', d => 'arrow-'+d)
    .attr('viewBox','0 -5 10 10')
    .attr('refX', 22).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6)
    .attr('orient','auto')
  .append('path')
    .attr('d','M0,-5L10,0L0,5')
    .attr('fill', d => d === 'path' ? '#f85149' : '#7d8590');

function isPathEdge(d){
  const s = (typeof d.source === 'object') ? d.source.label : d.source;
  const t = (typeof d.target === 'object') ? d.target.label : d.target;
  return pathEdgeSet.has(s + '|' + t);
}

const link = g.append('g').selectAll('line')
  .data(links).join('line')
    .attr('class', d => 'link' + (isPathEdge(d) ? ' path-edge' : ''))
    .attr('stroke', d => isPathEdge(d) ? '#f85149' : '#7d8590')
    .attr('stroke-width', d => isPathEdge(d) ? 3 : 1)
    .attr('marker-end', d => isPathEdge(d) ? 'url(#arrow-path)' : 'url(#arrow-default)');

const node = g.append('g').selectAll('g')
  .data(nodes).join('g')
    .attr('class','node')
    .call(d3.drag()
      .on('start', dragStart)
      .on('drag', dragged)
      .on('end', dragEnd));

node.append('circle')
  .attr('r', nodeRadius)
  .attr('fill', nodeColor)
  .attr('stroke', d => d.isHighValue ? '#fff' : '#000')
  .attr('stroke-width', d => d.isHighValue ? 2.5 : 1.5);

node.append('text')
  .attr('x', d => nodeRadius(d) + 4)
  .attr('y', 4)
  .text(d => d.label);

const tooltip = d3.select('#tooltip');
node.on('mouseover', (e, d) => {
  tooltip.style('opacity', 1)
    .html(`<strong>${d.label}</strong><br>Type: ${d.type}<br>Tier: ${d.tier}` +
          (d.isHighValue ? '<br><span style=""color:#f85149"">HIGH VALUE TARGET</span>' : ''))
    .style('left', (e.pageX + 12) + 'px')
    .style('top', (e.pageY + 12) + 'px');
}).on('mousemove', (e) => {
  tooltip.style('left', (e.pageX + 12) + 'px').style('top', (e.pageY + 12) + 'px');
}).on('mouseout', () => tooltip.style('opacity', 0));

sim.on('tick', () => {
  link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
  node.attr('transform', d => `translate(${d.x},${d.y})`);
});

function dragStart(e,d){ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }
function dragged(e,d){ d.fx=e.x; d.fy=e.y; }
function dragEnd(e,d){ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }
</script>
</body>
</html>";
    }
}
