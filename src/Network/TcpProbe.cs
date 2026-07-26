using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Network
{
    public sealed class TcpProbeResult
    {
        public ReachabilityVerdict Verdict { get; init; }

        /// <summary>syn-ack | rst | timeout | icmp-unreachable | dns-failure | error:CODE</summary>
        public string Response { get; init; } = string.Empty;

        public int     RttMs  { get; init; }
        public string? Banner { get; init; }
    }

    /// <summary>
    /// A single TCP connect that preserves WHY it failed.
    ///
    /// The old implementation was `catch { return false; }`, which collapsed three
    /// materially different outcomes into one boolean. For segmentation assessment
    /// that distinction is the entire result:
    ///
    ///   SYN/ACK -> Open      something is listening and the path is open
    ///   RST     -> Closed    the host ANSWERED. Nothing is filtering between us and
    ///                        it -- the segmentation control is absent, there simply
    ///                        is no service on that port today. One service install
    ///                        away from a violation.
    ///   drop    -> Filtered  the packet died in transit. A control IS enforcing.
    ///
    /// Collapsing Closed and Filtered means a powered-off host and a correctly
    /// firewalled host produce identical output.
    /// </summary>
    public static class TcpProbe
    {
        /// <summary>Ports that volunteer an identifying banner on connect.</summary>
        private static readonly int[] BannerPorts = { 21, 22, 23, 25, 110, 143, 3306, 5432 };

        public static bool EmitsBanner(int port) => Array.IndexOf(BannerPorts, port) >= 0;

        /// <summary>
        /// Maps a socket outcome to a verdict. Pure, so the mapping is unit-testable
        /// without needing a firewall to point at.
        /// </summary>
        public static ReachabilityVerdict Classify(SocketError error, out string response)
        {
            switch (error)
            {
                case SocketError.Success:
                    response = "syn-ack";
                    return ReachabilityVerdict.Open;

                // The host actively refused: it received our SYN and replied RST.
                // Reachable, nothing listening, nothing blocking.
                case SocketError.ConnectionRefused:
                case SocketError.ConnectionReset:
                    response = "rst";
                    return ReachabilityVerdict.Closed;

                // Silently dropped.
                case SocketError.TimedOut:
                    response = "timeout";
                    return ReachabilityVerdict.Filtered;

                // ICMP unreachable, including administratively-prohibited (type 3
                // code 13), which is a firewall explicitly rejecting the flow.
                case SocketError.HostUnreachable:
                case SocketError.NetworkUnreachable:
                case SocketError.HostDown:
                case SocketError.NetworkDown:
                    response = "icmp-unreachable";
                    return ReachabilityVerdict.Filtered;

                // Our OWN host blocked the egress. Says nothing about the target.
                case SocketError.AccessDenied:
                    response = "local-egress-blocked";
                    return ReachabilityVerdict.Unknown;

                case SocketError.HostNotFound:
                case SocketError.NoData:
                case SocketError.TryAgain:
                    response = "dns-failure";
                    return ReachabilityVerdict.Unknown;

                default:
                    response = $"error:{error}";
                    return ReachabilityVerdict.Unknown;
            }
        }

        public static async Task<TcpProbeResult> ProbeAsync(
            IPAddress address, int port, int timeoutMs,
            bool grabBanner, CancellationToken ct)
        {
            var stopwatch = Stopwatch.StartNew();

            using var socket = new Socket(
                address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(timeoutMs);

                await socket.ConnectAsync(new IPEndPoint(address, port), timeoutCts.Token)
                            .ConfigureAwait(false);

                stopwatch.Stop();

                string? banner = null;
                if (grabBanner && EmitsBanner(port))
                    banner = await TryReadBannerAsync(socket, 1000, ct).ConfigureAwait(false);

                return new TcpProbeResult
                {
                    Verdict  = ReachabilityVerdict.Open,
                    Response = "syn-ack",
                    RttMs    = (int)stopwatch.ElapsedMilliseconds,
                    Banner   = banner,
                };
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // Our own deadline elapsed with no response of any kind: dropped.
                stopwatch.Stop();
                return new TcpProbeResult
                {
                    Verdict  = ReachabilityVerdict.Filtered,
                    Response = "timeout",
                    RttMs    = (int)stopwatch.ElapsedMilliseconds,
                };
            }
            catch (SocketException ex)
            {
                stopwatch.Stop();
                var verdict = Classify(ex.SocketErrorCode, out var response);
                return new TcpProbeResult
                {
                    Verdict  = verdict,
                    Response = response,
                    RttMs    = (int)stopwatch.ElapsedMilliseconds,
                };
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                return new TcpProbeResult
                {
                    Verdict  = ReachabilityVerdict.Unknown,
                    Response = $"error:{ex.GetType().Name}",
                    RttMs    = (int)stopwatch.ElapsedMilliseconds,
                };
            }
        }

        /// <summary>
        /// Reads whatever the server volunteers on connect. Nothing is ever sent --
        /// this is a passive read, used to check that an open port is running the
        /// service its number implies.
        /// </summary>
        private static async Task<string?> TryReadBannerAsync(
            Socket socket, int timeoutMs, CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs);

                var buffer = new byte[256];
                var read = await socket
                    .ReceiveAsync(buffer.AsMemory(0, buffer.Length), SocketFlags.None, cts.Token)
                    .ConfigureAwait(false);

                return read <= 0 ? null : Sanitize(buffer, read);
            }
            catch
            {
                return null;   // no banner is not an error
            }
        }

        internal static string? Sanitize(byte[] buffer, int length)
        {
            var sb = new StringBuilder(length);

            for (var i = 0; i < length; i++)
            {
                var c = (char)buffer[i];
                if (c is '\r' or '\n' or '\t') { sb.Append(' '); continue; }
                if (c < 0x20 || c > 0x7E) continue;      // drop control / non-ASCII
                sb.Append(c);
            }

            var text = sb.ToString().Trim();
            while (text.Contains("  ")) text = text.Replace("  ", " ");

            if (text.Length == 0) return null;
            return text.Length > 120 ? text[..120] : text;
        }
    }
}
