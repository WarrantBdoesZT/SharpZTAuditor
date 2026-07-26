using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace ZeroTrustAuditor.Network
{
    /// <summary>
    /// Turns a target specification into concrete addresses.
    ///
    /// Accepts a single IP, a hostname, a CIDR block, or an inclusive range
    /// ("10.0.0.10-10.0.0.50"). An assumed-breach sweep is expressed in subnets --
    /// requiring a hand-written hostname list means you only ever assess the hosts
    /// you already knew about, which is precisely the blind spot that matters.
    /// </summary>
    public static class TargetExpander
    {
        /// <summary>Safety cap. A /16 is 65,534 hosts and is almost never intended.</summary>
        public const int DefaultMaxHosts = 4096;

        public static bool TryExpand(
            string? spec, int maxHosts, out List<IPAddress> addresses, out string? error)
        {
            addresses = new List<IPAddress>();
            error     = null;

            if (string.IsNullOrWhiteSpace(spec))
            {
                error = "target specification is empty";
                return false;
            }

            var text = spec.Trim();

            if (text.Contains('-') && !text.Contains('/'))
                return TryExpandRange(text, maxHosts, addresses, out error);

            if (text.Contains('/'))
                return TryExpandCidr(text, maxHosts, addresses, out error);

            if (IPAddress.TryParse(text, out var literal))
            {
                addresses.Add(literal);
                return true;
            }

            // Hostname
            var resolved = LocalAddressProvider.ResolveHost(text);
            if (resolved == null)
            {
                error = $"'{text}' is not an IP, CIDR, or resolvable hostname";
                return false;
            }

            addresses.Add(resolved);
            return true;
        }

        private static bool TryExpandCidr(
            string text, int maxHosts, List<IPAddress> addresses, out string? error)
        {
            error = null;

            if (!IpRange.TryParse(text, out var range, out var parseError))
            {
                error = parseError;
                return false;
            }

            if (range!.Family == AddressFamily.InterNetworkV6)
            {
                if (range.PrefixLength == 128)
                {
                    addresses.Add(range.NetworkAddress);
                    return true;
                }

                // An IPv6 /64 holds 1.8e19 addresses. Enumeration is meaningless;
                // IPv6 discovery needs neighbour/DNS data, not a sweep.
                error = $"cannot enumerate IPv6 range {range} -- specify individual " +
                        "addresses or a /128. IPv6 sweeps are not feasible by enumeration.";
                return false;
            }

            var hostBits = 32 - range.PrefixLength;
            if (hostBits >= 31)
            {
                // /0 and /1 are absurd; guard before the shift overflows meaning.
                error = $"{range} is too large to enumerate";
                return false;
            }

            var total = 1L << hostBits;

            // Skip network and broadcast for anything roomier than a point-to-point link.
            var skipEdges = range.PrefixLength <= 30;
            var usable    = skipEdges ? total - 2 : total;

            if (usable > maxHosts)
            {
                error = $"{range} expands to {usable:N0} hosts, above the limit of " +
                        $"{maxHosts:N0}. Narrow the range or raise --max-targets.";
                return false;
            }

            var baseBytes = range.NetworkAddress.GetAddressBytes();
            var baseValue = ToUInt32(baseBytes);

            var start = skipEdges ? 1L : 0L;
            var end   = skipEdges ? total - 1 : total;

            for (var i = start; i < end; i++)
                addresses.Add(new IPAddress(ToBytes((uint)(baseValue + i))));

            return true;
        }

        private static bool TryExpandRange(
            string text, int maxHosts, List<IPAddress> addresses, out string? error)
        {
            error = null;

            var parts = text.Split('-', 2);
            if (parts.Length != 2)
            {
                error = $"'{text}' is not a valid range";
                return false;
            }

            if (!IPAddress.TryParse(parts[0].Trim(), out var first) ||
                !IPAddress.TryParse(parts[1].Trim(), out var last))
            {
                error = $"'{text}' contains an invalid IP address";
                return false;
            }

            if (first.AddressFamily != AddressFamily.InterNetwork ||
                last.AddressFamily  != AddressFamily.InterNetwork)
            {
                error = "ranges are supported for IPv4 only";
                return false;
            }

            var startValue = ToUInt32(first.GetAddressBytes());
            var endValue   = ToUInt32(last.GetAddressBytes());

            if (endValue < startValue)
            {
                error = $"range '{text}' ends before it starts";
                return false;
            }

            var count = (long)endValue - startValue + 1;
            if (count > maxHosts)
            {
                error = $"range '{text}' covers {count:N0} hosts, above the limit of " +
                        $"{maxHosts:N0}.";
                return false;
            }

            for (var v = startValue; ; v++)
            {
                addresses.Add(new IPAddress(ToBytes(v)));
                if (v == endValue) break;
            }

            return true;
        }

        private static uint ToUInt32(byte[] bytes) =>
            ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) |
            ((uint)bytes[2] << 8)  | bytes[3];

        private static byte[] ToBytes(uint value) => new[]
        {
            (byte)(value >> 24), (byte)(value >> 16),
            (byte)(value >> 8),  (byte)value,
        };
    }
}
