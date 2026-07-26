using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace ZeroTrustAuditor.Network
{
    /// <summary>
    /// Paces outbound probes so an assessment does not look like — or land like — a
    /// denial of service.
    ///
    /// This matters for accuracy as much as for courtesy. Unthrottled, the previous
    /// design fired 500 hosts x 7 ports concurrently from one process; the ephemeral
    /// port range and the Windows half-open connection limit then produced timeouts
    /// that were recorded as "port closed", i.e. as evidence of GOOD segmentation.
    /// The tool became more optimistic the harder it was pushed.
    /// </summary>
    public sealed class RateLimiter : IDisposable
    {
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly long _intervalTicks;
        private long _nextPermitTicks;

        /// <param name="permitsPerSecond">Zero or negative disables pacing.</param>
        public RateLimiter(int permitsPerSecond)
        {
            _intervalTicks = permitsPerSecond <= 0
                ? 0
                : Stopwatch.Frequency / permitsPerSecond;
        }

        public bool IsUnlimited => _intervalTicks <= 0;

        public async Task WaitAsync(CancellationToken ct = default)
        {
            if (IsUnlimited) return;

            long waitTicks;

            await _gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var now = Stopwatch.GetTimestamp();
                (waitTicks, _nextPermitTicks) = Schedule(now, _nextPermitTicks, _intervalTicks);
            }
            finally
            {
                _gate.Release();
            }

            if (waitTicks > 0)
                await Task.Delay(TicksToTimeSpan(waitTicks), ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Pure scheduling step, extracted so pacing can be tested deterministically
        /// instead of by sleeping and hoping.
        /// </summary>
        internal static (long WaitTicks, long NextPermit) Schedule(
            long now, long currentNextPermit, long intervalTicks)
        {
            var scheduled = Math.Max(now, currentNextPermit);
            return (scheduled - now, scheduled + intervalTicks);
        }

        private static TimeSpan TicksToTimeSpan(long stopwatchTicks) =>
            TimeSpan.FromSeconds((double)stopwatchTicks / Stopwatch.Frequency);

        public void Dispose() => _gate.Dispose();
    }
}
