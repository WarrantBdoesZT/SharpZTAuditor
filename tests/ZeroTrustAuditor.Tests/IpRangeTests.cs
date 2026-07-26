using System.Net;
using Xunit;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Tests
{
    /// <summary>
    /// CIDR containment. These cases are exactly the ones the old third-octet
    /// heuristic got wrong.
    /// </summary>
    public class IpRangeTests
    {
        [Theory]
        [InlineData("10.0.0.0/8",      "10.55.99.1",   true)]
        [InlineData("10.0.0.0/8",      "11.0.0.1",     false)]
        [InlineData("10.20.0.0/16",    "10.20.255.254", true)]
        [InlineData("10.20.0.0/16",    "10.21.0.1",    false)]
        [InlineData("192.168.1.0/24",  "192.168.1.255", true)]
        [InlineData("192.168.1.0/24",  "192.168.2.0",  false)]
        [InlineData("10.30.1.0/24",    "10.30.1.5",    true)]
        [InlineData("0.0.0.0/0",       "8.8.8.8",      true)]
        [InlineData("10.1.2.3/32",     "10.1.2.3",     true)]
        [InlineData("10.1.2.3/32",     "10.1.2.4",     false)]
        public void Contains_Ipv4(string cidr, string address, bool expected)
        {
            var range = IpRange.Parse(cidr);
            Assert.Equal(expected, range.Contains(IPAddress.Parse(address)));
        }

        [Fact]
        public void DifferentThirdOctetSameNetwork_IsContained()
        {
            // A /23 spans two third-octet values. The old heuristic called this a
            // segment boundary and invented cross-segment violations inside one
            // broadcast domain.
            var range = IpRange.Parse("192.168.0.0/23");

            Assert.True(range.Contains(IPAddress.Parse("192.168.0.10")));
            Assert.True(range.Contains(IPAddress.Parse("192.168.1.10")));
        }

        [Fact]
        public void SameThirdOctetDifferentNetworks_AreNotContained()
        {
            // 10.1.5.x and 10.2.5.x share a third octet but are different segments.
            // The old heuristic treated them as identical and MISSED every exposure
            // between them.
            var range = IpRange.Parse("10.1.5.0/24");

            Assert.True(range.Contains(IPAddress.Parse("10.1.5.20")));
            Assert.False(range.Contains(IPAddress.Parse("10.2.5.20")));
        }

        [Theory]
        [InlineData("2001:db8::/32", "2001:db8:1234::1", true)]
        [InlineData("2001:db8::/32", "2001:db9::1",      false)]
        [InlineData("fe80::/10",     "fe80::1",          true)]
        [InlineData("::1/128",       "::1",              true)]
        public void Contains_Ipv6(string cidr, string address, bool expected)
        {
            var range = IpRange.Parse(cidr);
            Assert.Equal(expected, range.Contains(IPAddress.Parse(address)));
        }

        [Fact]
        public void AddressFamiliesDoNotCross()
        {
            Assert.False(IpRange.Parse("10.0.0.0/8").Contains(IPAddress.Parse("2001:db8::1")));
            Assert.False(IpRange.Parse("2001:db8::/32").Contains(IPAddress.Parse("10.0.0.1")));
        }

        [Fact]
        public void Ipv4MappedIpv6_MatchesIpv4Range()
        {
            // DNS and dual-stack sockets can hand back ::ffff:10.20.0.5.
            var range = IpRange.Parse("10.20.0.0/16");
            Assert.True(range.Contains(IPAddress.Parse("::ffff:10.20.0.5")));
        }

        [Fact]
        public void HostBitsAreMaskedOff()
        {
            var range = IpRange.Parse("10.1.2.3/24");
            Assert.Equal("10.1.2.0/24", range.ToString());
        }

        [Fact]
        public void BareAddressBecomesSingleHost()
        {
            Assert.Equal(32,  IpRange.Parse("10.1.2.3").PrefixLength);
            Assert.Equal(128, IpRange.Parse("2001:db8::1").PrefixLength);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("not-an-ip")]
        [InlineData("10.0.0.0/33")]
        [InlineData("10.0.0.0/abc")]
        [InlineData("2001:db8::/129")]
        [InlineData("999.1.1.1/24")]
        [InlineData("10.0.0.0/-1")]
        public void InvalidInput_IsRejectedWithAReason(string cidr)
        {
            Assert.False(IpRange.TryParse(cidr, out var range, out var error));
            Assert.Null(range);
            Assert.False(string.IsNullOrWhiteSpace(error));
        }

        [Fact]
        public void Contains_NullAddress_IsFalse()
        {
            Assert.False(IpRange.Parse("10.0.0.0/8").Contains(null));
        }
    }
}
