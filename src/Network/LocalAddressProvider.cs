using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ZeroTrustAuditor.Network
{
    /// <summary>
    /// Determines which local address the host would actually use to reach a target.
    ///
    /// The previous implementation took the first IPv4 result of
    /// Dns.GetHostAddresses(Dns.GetHostName()), which on any multi-homed machine
    /// (VPN client, Hyper-V vSwitch, second NIC, docker bridge) returns an arbitrary
    /// adapter depending on enumeration order. The entire cross-segment
    /// determination for a run therefore depended on which NIC happened to be
    /// listed first.
    /// </summary>
    public static class LocalAddressProvider
    {
        /// <summary>
        /// Asks the OS routing table which source address it would use for this
        /// destination, by connecting a UDP socket. UDP connect performs no I/O and
        /// sends no packets -- it only binds the socket to the route the kernel picks.
        /// </summary>
        public static IPAddress? ForTarget(IPAddress? target)
        {
            if (target == null) return null;

            try
            {
                using var socket = new Socket(
                    target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

                // Arbitrary high port. Nothing is transmitted.
                socket.Connect(new IPEndPoint(target, 65530));

                return (socket.LocalEndPoint as IPEndPoint)?.Address;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Best-effort local address when no specific target is in play. Prefers an
        /// operational, non-loopback, non-link-local IPv4 address.
        /// </summary>
        public static IPAddress? Primary()
        {
            try
            {
                var candidates = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                    .Select(u => u.Address)
                    .Where(a => !IPAddress.IsLoopback(a))
                    .ToList();

                return candidates.FirstOrDefault(
                           a => a.AddressFamily == AddressFamily.InterNetwork &&
                                !IsLinkLocalV4(a))
                    ?? candidates.FirstOrDefault(
                           a => a.AddressFamily == AddressFamily.InterNetworkV6 &&
                                !a.IsIPv6LinkLocal);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>169.254.0.0/16 -- APIPA, meaning DHCP failed. Never a real segment.</summary>
        private static bool IsLinkLocalV4(IPAddress address)
        {
            var b = address.GetAddressBytes();
            return b.Length == 4 && b[0] == 169 && b[1] == 254;
        }

        /// <summary>Resolves a hostname to its first usable address, or null.</summary>
        public static IPAddress? ResolveHost(string host)
        {
            try
            {
                var addresses = Dns.GetHostAddresses(host);
                return addresses.FirstOrDefault(
                           a => a.AddressFamily == AddressFamily.InterNetwork)
                    ?? addresses.FirstOrDefault(
                           a => a.AddressFamily == AddressFamily.InterNetworkV6);
            }
            catch
            {
                return null;
            }
        }
    }
}
