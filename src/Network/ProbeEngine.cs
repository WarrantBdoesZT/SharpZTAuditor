using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Network
{
    public sealed class ProbeOptions
    {
        public int TimeoutMs        { get; init; } = 3000;
        public int MaxConcurrency   { get; init; } = 128;
        public int ProbesPerSecond  { get; init; } = 100;

        /// <summary>
        /// Extra attempts when a probe times out. One dropped SYN on a congested
        /// link otherwise reads as "filtered", i.e. as a working control.
        /// </summary>
        public int RetriesOnTimeout { get; init; } = 1;

        public bool GrabBanners     { get; init; } = true;

        /// <summary>Operator opt-in required to actively probe OT/ICS services.</summary>
        public bool AllowOtProbing  { get; init; }

        /// <summary>Plan the probes and report them without sending anything.</summary>
        public bool DryRun          { get; init; }
    }

    public sealed class ProbeTarget
    {
        public string    Host      { get; init; } = string.Empty;
        public IPAddress Address   { get; init; } = IPAddress.None;
        public int       Port      { get; init; }
        public string    Transport { get; init; } = "tcp";
        public ServiceClassDefinition? Service { get; init; }

        /// <summary>False for zones flagged safeMode with activeProbing disabled.</summary>
        public bool ZoneAllowsActiveProbing { get; init; } = true;

        public string ServiceId => Service?.Id ?? $"tcp/{Port}";
    }

    public sealed class ReachabilityObservation
    {
        public string    Host           { get; init; } = string.Empty;
        public string    TargetIp       { get; init; } = string.Empty;
        public int       Port           { get; init; }
        public string    Transport      { get; init; } = "tcp";
        public string    ServiceClassId { get; init; } = string.Empty;

        /// <summary>
        /// The zone this observation was made FROM. Stamped by the caller, which
        /// knows the zone map; the probe engine deliberately does not.
        ///
        /// Carried per-observation rather than per-run so that merged results from
        /// several vantage points stay attributable. Reachability is a property of
        /// an ordered pair, and a merged file that forgot where each measurement was
        /// taken would be worthless.
        /// </summary>
        public string VantageZoneId { get; set; } = string.Empty;

        /// <summary>Machine the probe ran on, for provenance in merged files.</summary>
        public string VantageHost { get; set; } = string.Empty;

        public ReachabilityVerdict Verdict    { get; init; }
        public ProbeEvidence       Evidence   { get; init; } = new();
        public double              Confidence { get; init; }

        public DateTimeOffset ObservedAt { get; init; } = DateTimeOffset.UtcNow;
    }

    public sealed class ProbeStatistics
    {
        public int Planned  { get; set; }
        public int Sent     { get; set; }
        public int Skipped  { get; set; }
        public int Open     { get; set; }
        public int Closed   { get; set; }
        public int Filtered { get; set; }
        public int Unknown  { get; set; }

        public override string ToString() =>
            $"planned={Planned} sent={Sent} skipped={Skipped} " +
            $"open={Open} closed={Closed} filtered={Filtered} unknown={Unknown}";
    }

    /// <summary>
    /// Bounded, paced, retrying TCP prober producing tri-state observations.
    /// </summary>
    public sealed class ProbeEngine : IDisposable
    {
        private readonly ProbeOptions  _options;
        private readonly SemaphoreSlim _concurrency;
        private readonly RateLimiter   _rateLimiter;

        public ProbeStatistics Statistics { get; } = new();

        public ProbeEngine(ProbeOptions options)
        {
            _options     = options;
            _concurrency = new SemaphoreSlim(Math.Max(1, options.MaxConcurrency));
            _rateLimiter = new RateLimiter(options.ProbesPerSecond);
        }

        public async Task<IReadOnlyList<ReachabilityObservation>> ProbeAsync(
            IReadOnlyList<ProbeTarget> targets, CancellationToken ct = default)
        {
            Statistics.Planned = targets.Count;

            var tasks = targets.Select(t => ProbeOneAsync(t, ct)).ToList();
            var results = await Task.WhenAll(tasks).ConfigureAwait(false);

            Statistics.Sent    = _sent;
            Statistics.Skipped = _skipped;

            foreach (var r in results)
            {
                switch (r.Verdict)
                {
                    case ReachabilityVerdict.Open:     Statistics.Open++;     break;
                    case ReachabilityVerdict.Closed:   Statistics.Closed++;   break;
                    case ReachabilityVerdict.Filtered: Statistics.Filtered++; break;
                    default:                           Statistics.Unknown++;  break;
                }
            }

            return results;
        }

        private async Task<ReachabilityObservation> ProbeOneAsync(
            ProbeTarget target, CancellationToken ct)
        {
            // ── Safety interlocks, applied before any packet ──────────────────
            var passiveOnly = target.Service?.IsPassiveOnly == true;

            if (passiveOnly && !(_options.AllowOtProbing && target.ZoneAllowsActiveProbing))
            {
                Interlocked.Increment(ref _skipped);
                return NotProbed(target, "passive-only",
                    "Service is marked passive-only (OT/ICS). Active probing requires both " +
                    "--allow-ot-probing and activeProbing=true on the target zone.");
            }

            if (!target.ZoneAllowsActiveProbing)
            {
                Interlocked.Increment(ref _skipped);
                return NotProbed(target, "zone-safe-mode",
                    "Target zone is in safe mode with active probing disabled.");
            }

            if (_options.DryRun)
            {
                Interlocked.Increment(ref _skipped);
                return NotProbed(target, "dry-run", "Dry run: no packets were sent.");
            }

            // ── Probe, retrying only on timeouts ──────────────────────────────
            TcpProbeResult? result = null;
            var attempts    = 0;
            var maxAttempts = 1 + Math.Max(0, _options.RetriesOnTimeout);

            for (; attempts < maxAttempts; attempts++)
            {
                await _concurrency.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    await _rateLimiter.WaitAsync(ct).ConfigureAwait(false);
                    result = await TcpProbe.ProbeAsync(
                        target.Address, target.Port, _options.TimeoutMs,
                        _options.GrabBanners, ct).ConfigureAwait(false);
                }
                finally
                {
                    _concurrency.Release();
                }

                Interlocked.Increment(ref _sent);

                // Open and Closed are both definitive answers from the host itself.
                if (result.Verdict != ReachabilityVerdict.Filtered) break;
                if (result.Response != "timeout") break;   // ICMP is definitive too
            }

            attempts = Math.Min(attempts + 1, maxAttempts);
            result ??= new TcpProbeResult
            {
                Verdict  = ReachabilityVerdict.Unknown,
                Response = "not-attempted",
            };

            return new ReachabilityObservation
            {
                Host           = target.Host,
                TargetIp       = target.Address.ToString(),
                Port           = target.Port,
                Transport      = target.Transport,
                ServiceClassId = target.ServiceId,
                Verdict        = result.Verdict,
                Confidence     = ConfidenceFor(result, attempts, maxAttempts),
                Evidence = new ProbeEvidence
                {
                    Method              = "tcp-connect",
                    Response            = result.Response,
                    RttMs               = result.RttMs,
                    Attempts            = attempts,
                    Banner              = result.Banner,
                    ServiceConfirmation = ConfirmService(target, result.Banner),
                },
            };
        }

        private int _sent;
        private int _skipped;

        private static ReachabilityObservation NotProbed(
            ProbeTarget target, string reason, string detail) =>
            new()
            {
                Host           = target.Host,
                TargetIp       = target.Address.ToString(),
                Port           = target.Port,
                Transport      = target.Transport,
                ServiceClassId = target.ServiceId,
                // Never Closed or Filtered: not probing tells us nothing, and
                // recording it as either would be an outright false statement.
                Verdict    = ReachabilityVerdict.Unknown,
                Confidence = 0.0,
                Evidence = new ProbeEvidence
                {
                    Method              = "not-probed",
                    Response            = reason,
                    Attempts            = 0,
                    ServiceConfirmation = detail,
                },
            };

        /// <summary>
        /// A Closed verdict is definitive: the host itself answered. A Filtered
        /// verdict is inferred from silence, so it is never fully certain -- packet
        /// loss looks the same as a firewall.
        /// </summary>
        internal static double ConfidenceFor(TcpProbeResult result, int attempts, int maxAttempts) =>
            result.Verdict switch
            {
                ReachabilityVerdict.Open     => result.Banner != null ? 1.0 : 0.9,
                ReachabilityVerdict.Closed   => 1.0,
                ReachabilityVerdict.Filtered => result.Response == "icmp-unreachable"
                                                    ? 0.95
                                                    : (attempts >= maxAttempts ? 0.8 : 0.6),
                _                            => 0.0,
            };

        /// <summary>
        /// Cheap sanity check that an open port runs the service its number implies.
        /// An SSH daemon on 3389 is misclassified by port-number alone.
        /// </summary>
        internal static string? ConfirmService(ProbeTarget target, string? banner)
        {
            if (banner == null) return null;

            var expected = target.Service?.Id ?? string.Empty;
            var upper    = banner.ToUpperInvariant();

            var looksLike = upper switch
            {
                _ when upper.StartsWith("SSH-")      => "SSH",
                _ when upper.StartsWith("220 ")      => "FTP/SMTP",
                _ when upper.Contains("MYSQL")       => "MYSQL",
                _ when upper.Contains("POSTGRE")     => "POSTGRES",
                _                                     => null,
            };

            if (looksLike == null) return "banner-present (unrecognised)";

            return expected.Length > 0 &&
                   !looksLike.Contains(expected, StringComparison.OrdinalIgnoreCase)
                ? $"MISMATCH: port implies {expected}, banner looks like {looksLike}"
                : $"confirmed {looksLike}";
        }

        public void Dispose()
        {
            _concurrency.Dispose();
            _rateLimiter.Dispose();
        }
    }
}
