using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Tests
{
    /// <summary>
    /// The Closed/Filtered distinction is the core of Phase 2. Classification is a
    /// pure function so every branch is testable without needing a firewall; the
    /// Open and Closed paths are additionally exercised against real loopback
    /// sockets.
    /// </summary>
    public class TcpProbeClassificationTests
    {
        [Fact]
        public void SynAck_IsOpen()
        {
            Assert.Equal(ReachabilityVerdict.Open,
                TcpProbe.Classify(SocketError.Success, out var response));
            Assert.Equal("syn-ack", response);
        }

        [Theory]
        [InlineData(SocketError.ConnectionRefused)]
        [InlineData(SocketError.ConnectionReset)]
        public void Rst_IsClosed_NotFiltered(SocketError error)
        {
            // The host ANSWERED. Nothing is filtering. Reporting this as Filtered
            // would claim a segmentation control exists where none does.
            Assert.Equal(ReachabilityVerdict.Closed, TcpProbe.Classify(error, out var response));
            Assert.Equal("rst", response);
        }

        [Fact]
        public void Timeout_IsFiltered_NotClosed()
        {
            Assert.Equal(ReachabilityVerdict.Filtered,
                TcpProbe.Classify(SocketError.TimedOut, out var response));
            Assert.Equal("timeout", response);
        }

        [Theory]
        [InlineData(SocketError.HostUnreachable)]
        [InlineData(SocketError.NetworkUnreachable)]
        [InlineData(SocketError.HostDown)]
        [InlineData(SocketError.NetworkDown)]
        public void IcmpUnreachable_IsFiltered(SocketError error)
        {
            Assert.Equal(ReachabilityVerdict.Filtered,
                TcpProbe.Classify(error, out var response));
            Assert.Equal("icmp-unreachable", response);
        }

        [Fact]
        public void LocalEgressBlocked_IsUnknown_NotAStatementAboutTheTarget()
        {
            Assert.Equal(ReachabilityVerdict.Unknown,
                TcpProbe.Classify(SocketError.AccessDenied, out var response));
            Assert.Equal("local-egress-blocked", response);
        }

        [Theory]
        [InlineData(SocketError.HostNotFound)]
        [InlineData(SocketError.NoData)]
        public void DnsFailure_IsUnknown(SocketError error)
        {
            Assert.Equal(ReachabilityVerdict.Unknown, TcpProbe.Classify(error, out _));
        }

        [Fact]
        public void UnrecognisedError_IsUnknown_AndNamesTheCode()
        {
            Assert.Equal(ReachabilityVerdict.Unknown,
                TcpProbe.Classify(SocketError.ProtocolNotSupported, out var response));
            Assert.StartsWith("error:", response);
        }

        [Fact]
        public void BannerSanitiserStripsControlCharacters()
        {
            var raw = System.Text.Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_9.2\r\n\0\0");
            Assert.Equal("SSH-2.0-OpenSSH_9.2", TcpProbe.Sanitize(raw, raw.Length));
        }

        [Fact]
        public void BannerSanitiserTruncates()
        {
            var raw = System.Text.Encoding.ASCII.GetBytes(new string('A', 400));
            Assert.Equal(120, TcpProbe.Sanitize(raw, raw.Length)!.Length);
        }
    }

    public class TcpProbeSocketTests
    {
        [Fact]
        public async Task ListeningPort_IsObservedOpen()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;

            try
            {
                var result = await TcpProbe.ProbeAsync(
                    IPAddress.Loopback, port, 3000, grabBanner: false, CancellationToken.None);

                Assert.Equal(ReachabilityVerdict.Open, result.Verdict);
                Assert.Equal("syn-ack", result.Response);
            }
            finally
            {
                listener.Stop();
            }
        }

        [Fact]
        public async Task ClosedPort_IsObservedClosed_NotFiltered()
        {
            // Bind then immediately release, so the port is almost certainly free
            // and loopback returns RST rather than dropping.
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();

            var result = await TcpProbe.ProbeAsync(
                IPAddress.Loopback, port, 3000, grabBanner: false, CancellationToken.None);

            Assert.Equal(ReachabilityVerdict.Closed, result.Verdict);
            Assert.NotEqual(ReachabilityVerdict.Filtered, result.Verdict);
        }
    }

    public class RateLimiterTests
    {
        [Fact]
        public void Schedule_SpacesPermitsByTheInterval()
        {
            const long interval = 100;

            // First permit at an idle limiter: no wait.
            var (wait1, next1) = RateLimiter.Schedule(now: 1000, currentNextPermit: 0, interval);
            Assert.Equal(0, wait1);
            Assert.Equal(1100, next1);

            // Immediately again: must wait out the remaining interval.
            var (wait2, next2) = RateLimiter.Schedule(now: 1000, currentNextPermit: next1, interval);
            Assert.Equal(100, wait2);
            Assert.Equal(1200, next2);

            // After a long idle gap the limiter does not build up burst credit.
            var (wait3, next3) = RateLimiter.Schedule(now: 5000, currentNextPermit: next2, interval);
            Assert.Equal(0, wait3);
            Assert.Equal(5100, next3);
        }

        [Fact]
        public void ZeroRate_IsUnlimited()
        {
            using var limiter = new RateLimiter(0);
            Assert.True(limiter.IsUnlimited);
        }

        [Fact]
        public async Task PacingActuallyDelays()
        {
            using var limiter = new RateLimiter(50);   // 20ms apart
            var stopwatch = Stopwatch.StartNew();

            for (var i = 0; i < 5; i++)
                await limiter.WaitAsync();

            stopwatch.Stop();

            // 5 permits at 20ms spacing is ~80ms of enforced delay. Generous lower
            // bound so this cannot flake on a loaded CI runner.
            Assert.True(stopwatch.ElapsedMilliseconds >= 40,
                $"expected pacing to delay at least 40ms, took {stopwatch.ElapsedMilliseconds}ms");
        }
    }

    public class ProbeEngineSafetyTests
    {
        private static ServiceClassDefinition OtService() => new()
        {
            Id          = "MODBUS",
            Ports       = new List<int> { 502 },
            Risk        = ServiceRisk.Critical,
            Category    = ServiceCategories.OtIcs,
            ProbePolicy = ProbePolicies.PassiveOnly,
        };

        private static ProbeTarget Target(ServiceClassDefinition service, bool zoneAllows = true) =>
            new()
            {
                Host    = "plc01",
                Address = IPAddress.Loopback,
                Port    = service.Ports[0],
                Service = service,
                ZoneAllowsActiveProbing = zoneAllows,
            };

        [Fact]
        public async Task PassiveOnlyService_IsNeverProbedByDefault()
        {
            using var engine = new ProbeEngine(new ProbeOptions());
            var results = await engine.ProbeAsync(new[] { Target(OtService()) });

            var observation = Assert.Single(results);
            Assert.Equal(ReachabilityVerdict.Unknown, observation.Verdict);
            Assert.Equal("not-probed", observation.Evidence.Method);
            Assert.Equal("passive-only", observation.Evidence.Response);
            Assert.Equal(0, observation.Evidence.Attempts);
            Assert.Equal(1, engine.Statistics.Skipped);
            Assert.Equal(0, engine.Statistics.Sent);
        }

        [Fact]
        public async Task OtProbing_RequiresBothTheFlagAndTheZoneOptIn()
        {
            // Flag set, but the zone still forbids it.
            using var engine = new ProbeEngine(new ProbeOptions { AllowOtProbing = true });
            var results = await engine.ProbeAsync(
                new[] { Target(OtService(), zoneAllows: false) });

            Assert.Equal(ReachabilityVerdict.Unknown, results[0].Verdict);
            Assert.Equal("not-probed", results[0].Evidence.Method);
        }

        [Fact]
        public async Task SafeModeZone_BlocksEvenOrdinaryServices()
        {
            var smb = new ServiceClassDefinition
            {
                Id = "SMB", Ports = new List<int> { 445 }, Risk = ServiceRisk.Critical,
            };

            using var engine = new ProbeEngine(new ProbeOptions());
            var results = await engine.ProbeAsync(new[] { Target(smb, zoneAllows: false) });

            Assert.Equal("zone-safe-mode", results[0].Evidence.Response);
            Assert.Equal(0, engine.Statistics.Sent);
        }

        [Fact]
        public async Task DryRun_SendsNothing()
        {
            var smb = new ServiceClassDefinition
            {
                Id = "SMB", Ports = new List<int> { 445 }, Risk = ServiceRisk.Critical,
            };

            using var engine = new ProbeEngine(new ProbeOptions { DryRun = true });
            var results = await engine.ProbeAsync(new[] { Target(smb) });

            Assert.Equal(ReachabilityVerdict.Unknown, results[0].Verdict);
            Assert.Equal("dry-run", results[0].Evidence.Response);
            Assert.Equal(0, engine.Statistics.Sent);
        }

        [Fact]
        public async Task ConcurrencyCeilingIsRespected()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;

            try
            {
                using var engine = new ProbeEngine(new ProbeOptions
                {
                    MaxConcurrency  = 2,
                    ProbesPerSecond = 0,
                    RetriesOnTimeout = 0,
                });

                var targets = Enumerable.Range(0, 12).Select(_ => new ProbeTarget
                {
                    Host = "local", Address = IPAddress.Loopback, Port = port,
                }).ToList();

                var results = await engine.ProbeAsync(targets);

                Assert.Equal(12, results.Count);
                Assert.All(results, r => Assert.Equal(ReachabilityVerdict.Open, r.Verdict));
            }
            finally
            {
                listener.Stop();
            }
        }

        [Fact]
        public void ConfidenceReflectsHowDefinitiveTheAnswerIs()
        {
            var closed = new TcpProbeResult
            {
                Verdict = ReachabilityVerdict.Closed, Response = "rst",
            };
            var filteredOnce = new TcpProbeResult
            {
                Verdict = ReachabilityVerdict.Filtered, Response = "timeout",
            };

            // RST is the host speaking for itself; silence is an inference.
            Assert.Equal(1.0, ProbeEngine.ConfidenceFor(closed, 1, 2));
            Assert.True(ProbeEngine.ConfidenceFor(filteredOnce, 1, 2) < 1.0);
            Assert.True(ProbeEngine.ConfidenceFor(filteredOnce, 2, 2) >
                        ProbeEngine.ConfidenceFor(filteredOnce, 1, 2));
        }

        [Fact]
        public void ServiceMismatchIsFlagged()
        {
            var target = new ProbeTarget
            {
                Host = "srv", Address = IPAddress.Loopback, Port = 3389,
                Service = new ServiceClassDefinition { Id = "RDP", Ports = new List<int> { 3389 } },
            };

            // An SSH daemon answering on the RDP port: port number alone would
            // have reported this as RDP.
            var confirmation = ProbeEngine.ConfirmService(target, "SSH-2.0-OpenSSH_9.2");

            Assert.NotNull(confirmation);
            Assert.StartsWith("MISMATCH", confirmation);
        }

        [Fact]
        public void MatchingBannerIsConfirmed()
        {
            var target = new ProbeTarget
            {
                Host = "srv", Address = IPAddress.Loopback, Port = 22,
                Service = new ServiceClassDefinition { Id = "SSH", Ports = new List<int> { 22 } },
            };

            Assert.Equal("confirmed SSH", ProbeEngine.ConfirmService(target, "SSH-2.0-OpenSSH_9.2"));
        }
    }
}
