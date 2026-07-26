using System.Linq;
using Xunit;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Tests
{
    public class TargetExpanderTests
    {
        [Fact]
        public void SingleAddressExpandsToItself()
        {
            Assert.True(TargetExpander.TryExpand("10.1.2.3", 4096, out var addresses, out _));
            Assert.Equal("10.1.2.3", Assert.Single(addresses).ToString());
        }

        [Fact]
        public void Slash24_SkipsNetworkAndBroadcast()
        {
            Assert.True(TargetExpander.TryExpand("10.20.30.0/24", 4096, out var addresses, out _));

            Assert.Equal(254, addresses.Count);
            Assert.Equal("10.20.30.1",   addresses.First().ToString());
            Assert.Equal("10.20.30.254", addresses.Last().ToString());
            Assert.DoesNotContain(addresses, a => a.ToString() == "10.20.30.0");
            Assert.DoesNotContain(addresses, a => a.ToString() == "10.20.30.255");
        }

        [Fact]
        public void Slash32_IsASingleHost()
        {
            Assert.True(TargetExpander.TryExpand("10.1.2.3/32", 4096, out var addresses, out _));
            Assert.Single(addresses);
        }

        [Fact]
        public void Slash31_KeepsBothAddresses()
        {
            // Point-to-point links have no network/broadcast to skip.
            Assert.True(TargetExpander.TryExpand("10.1.2.0/31", 4096, out var addresses, out _));
            Assert.Equal(2, addresses.Count);
        }

        [Fact]
        public void RangeSyntaxIsInclusive()
        {
            Assert.True(TargetExpander.TryExpand(
                "10.0.0.10-10.0.0.20", 4096, out var addresses, out _));

            Assert.Equal(11, addresses.Count);
            Assert.Equal("10.0.0.10", addresses.First().ToString());
            Assert.Equal("10.0.0.20", addresses.Last().ToString());
        }

        [Fact]
        public void OversizedRangeIsRefusedWithAnActionableMessage()
        {
            // A /16 is 65,534 hosts and is essentially never what someone meant.
            Assert.False(TargetExpander.TryExpand("10.0.0.0/16", 4096, out _, out var error));
            Assert.Contains("above the limit", error);
        }

        [Fact]
        public void BackwardsRangeIsRejected()
        {
            Assert.False(TargetExpander.TryExpand(
                "10.0.0.50-10.0.0.10", 4096, out _, out var error));
            Assert.Contains("ends before it starts", error);
        }

        [Fact]
        public void Ipv6PrefixIsRefusedRatherThanAttempted()
        {
            // A /64 holds 1.8e19 addresses; enumerating it is not a strategy.
            Assert.False(TargetExpander.TryExpand("2001:db8::/64", 4096, out _, out var error));
            Assert.Contains("cannot enumerate IPv6", error);
        }

        [Fact]
        public void Ipv6SingleHostIsAccepted()
        {
            Assert.True(TargetExpander.TryExpand("2001:db8::1/128", 4096, out var addresses, out _));
            Assert.Single(addresses);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("10.0.0.0/99")]
        public void InvalidSpecsAreRejected(string spec)
        {
            Assert.False(TargetExpander.TryExpand(spec, 4096, out _, out var error));
            Assert.False(string.IsNullOrWhiteSpace(error));
        }

        [Fact]
        public void MaxHostsIsHonouredExactly()
        {
            // 10.0.0.0/24 usable == 254.
            Assert.True(TargetExpander.TryExpand("10.0.0.0/24", 254, out var addresses, out _));
            Assert.Equal(254, addresses.Count);

            Assert.False(TargetExpander.TryExpand("10.0.0.0/24", 253, out _, out _));
        }
    }
}
