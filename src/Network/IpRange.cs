using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ZeroTrustAuditor.Network
{
    /// <summary>
    /// An IPv4 or IPv6 CIDR block with correct prefix-based containment.
    ///
    /// This replaces the third-octet string comparison that previously stood in for
    /// "network segment". That heuristic was wrong in both directions: 10.1.5.0/24
    /// and 10.2.5.0/24 were treated as the same segment (missing every exposure
    /// between them), while a single /23 was treated as two segments (inventing
    /// violations inside one broadcast domain). Masks were never consulted and IPv6
    /// was never evaluated at all.
    /// </summary>
    public sealed class IpRange
    {
        private readonly byte[] _network;

        public IPAddress NetworkAddress { get; }
        public int PrefixLength { get; }
        public AddressFamily Family { get; }

        /// <summary>The text this range was parsed from, for evidence strings.</summary>
        public string Text { get; }

        private IpRange(IPAddress network, byte[] networkBytes, int prefixLength, string text)
        {
            NetworkAddress = network;
            _network       = networkBytes;
            PrefixLength   = prefixLength;
            Family         = network.AddressFamily;
            Text           = text;
        }

        public int MaxPrefixLength =>
            Family == AddressFamily.InterNetwork ? 32 : 128;

        /// <summary>
        /// Parses "10.0.0.0/8", "2001:db8::/32", or a bare address (treated as a
        /// single-host /32 or /128).
        /// </summary>
        public static bool TryParse(string? text, out IpRange? range, out string? error)
        {
            range = null;
            error = null;

            if (string.IsNullOrWhiteSpace(text))
            {
                error = "CIDR is empty";
                return false;
            }

            var s     = text.Trim();
            var slash = s.IndexOf('/');
            var ipPart = slash < 0 ? s : s.Substring(0, slash);

            if (!IPAddress.TryParse(ipPart, out var ip))
            {
                error = $"'{ipPart}' is not a valid IP address";
                return false;
            }

            ip = Normalize(ip);
            var max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;

            int prefix;
            if (slash < 0)
            {
                prefix = max;   // bare address == single host
            }
            else
            {
                var prefixPart = s.Substring(slash + 1).Trim();
                if (!int.TryParse(prefixPart, NumberStyles.None,
                                  CultureInfo.InvariantCulture, out prefix))
                {
                    error = $"'{prefixPart}' is not a valid prefix length";
                    return false;
                }

                if (prefix > max)
                {
                    error = $"prefix /{prefix} exceeds the maximum /{max} for " +
                            (max == 32 ? "IPv4" : "IPv6");
                    return false;
                }
            }

            var bytes = ip.GetAddressBytes();
            ApplyMask(bytes, prefix);

            range = new IpRange(new IPAddress(bytes), bytes, prefix, s);
            return true;
        }

        public static IpRange Parse(string text)
        {
            if (TryParse(text, out var range, out var error))
                return range!;
            throw new FormatException($"Invalid CIDR '{text}': {error}");
        }

        /// <summary>True if the address falls inside this block.</summary>
        public bool Contains(IPAddress? address)
        {
            if (address == null) return false;

            var addr = Normalize(address);
            if (addr.AddressFamily != Family) return false;

            var bytes = addr.GetAddressBytes();
            if (bytes.Length != _network.Length) return false;

            var fullBytes = PrefixLength / 8;
            for (var i = 0; i < fullBytes; i++)
                if (bytes[i] != _network[i]) return false;

            var remainingBits = PrefixLength % 8;
            if (remainingBits == 0) return true;

            var mask = (0xFF << (8 - remainingBits)) & 0xFF;
            return (bytes[fullBytes] & mask) == (_network[fullBytes] & mask);
        }

        /// <summary>
        /// IPv4-mapped IPv6 addresses (::ffff:10.0.0.1) are folded to plain IPv4 so
        /// that a v4 zone definition still matches a v4-mapped result from DNS.
        /// </summary>
        internal static IPAddress Normalize(IPAddress address) =>
            address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6
                ? address.MapToIPv4()
                : address;

        private static void ApplyMask(byte[] bytes, int prefixLength)
        {
            var fullBytes     = prefixLength / 8;
            var remainingBits = prefixLength % 8;

            if (remainingBits != 0 && fullBytes < bytes.Length)
            {
                var mask = (0xFF << (8 - remainingBits)) & 0xFF;
                bytes[fullBytes] = (byte)(bytes[fullBytes] & mask);
                fullBytes++;
            }

            for (var i = fullBytes; i < bytes.Length; i++)
                bytes[i] = 0;
        }

        public override string ToString() => $"{NetworkAddress}/{PrefixLength}";
    }
}
