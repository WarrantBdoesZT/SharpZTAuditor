using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Xunit;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Tests
{
    public class ZoneResolverTests
    {
        private static ZoneDefinition Zone(
            string id, int tier, string role, params string[] cidrs)
        {
            var zone = new ZoneDefinition
            {
                Id    = id,
                Name  = id,
                Tier  = tier,
                Role  = role,
                Cidrs = cidrs.ToList(),
            };
            foreach (var c in cidrs)
                zone.Ranges.Add(IpRange.Parse(c));
            return zone;
        }

        private static ZoneResolver Sample() => new(new[]
        {
            Zone("corp",         TrustTier.User,         ZoneRoles.User,       "10.0.0.0/8"),
            Zone("server-tier1", TrustTier.Server,       ZoneRoles.Server,     "10.20.0.0/16"),
            Zone("tier0",        TrustTier.ControlPlane, ZoneRoles.Tier0,      "10.30.1.0/24"),
            Zone("guest",        TrustTier.Untrusted,    ZoneRoles.Untrusted,  "192.168.50.0/24"),
        });

        [Fact]
        public void LongestPrefixWins_SpecificCarveOutBeatsBroadBlock()
        {
            var resolver = Sample();

            // 10.30.1.5 is inside BOTH 10.0.0.0/8 and 10.30.1.0/24.
            // The /24 is more specific and must win, or every DC would be
            // misclassified as a user workstation.
            Assert.Equal("tier0",        resolver.Resolve(IPAddress.Parse("10.30.1.5")).Id);
            Assert.Equal("server-tier1", resolver.Resolve(IPAddress.Parse("10.20.4.11")).Id);
            Assert.Equal("corp",         resolver.Resolve(IPAddress.Parse("10.99.1.1")).Id);
        }

        [Fact]
        public void UnmatchedAddress_FallsBackToUnclassified()
        {
            var resolver = Sample();

            Assert.False(resolver.TryResolve(IPAddress.Parse("172.16.9.9"), out var zone));
            Assert.Equal(resolver.UnclassifiedZone.Id, zone.Id);
            Assert.Equal("unknown", resolver.Resolve(IPAddress.Parse("172.16.9.9")).Id);
        }

        [Fact]
        public void EmptyResolver_ReportsItself()
        {
            var resolver = new ZoneResolver(Array.Empty<ZoneDefinition>());
            Assert.True(resolver.IsEmpty);
            Assert.False(resolver.TryResolve(IPAddress.Parse("10.0.0.1"), out _));
        }

        [Fact]
        public void MatchingRange_ReportsTheCidrThatMatched()
        {
            var resolver = Sample();
            var range = resolver.MatchingRange(IPAddress.Parse("10.30.1.5"));
            Assert.Equal("10.30.1.0/24", range?.ToString());
        }
    }

    public class ZonePairRiskTests
    {
        private static ZoneDefinition Z(string id, int tier, string role) =>
            new() { Id = id, Name = id, Tier = tier, Role = role };

        private static ServiceClassDefinition Svc(
            string id, ServiceRisk risk, string category = ServiceCategories.RemoteAdmin) =>
            new() { Id = id, Risk = risk, Category = category, Ports = new List<int> { 445 } };

        [Fact]
        public void UserToTier0_OverAdminProtocol_IsCritical()
        {
            var result = ZonePairRisk.Assess(
                Z("user", TrustTier.User, ZoneRoles.User),
                Z("tier0", TrustTier.ControlPlane, ZoneRoles.Tier0),
                Svc("SMB", ServiceRisk.Critical));

            Assert.Equal(Severity.Critical, result.Severity);
        }

        [Fact]
        public void ManagementToServer_IsNotTreatedAsAnAttackPath()
        {
            // The designed administration direction must not outrank a genuine
            // violation, or the report is all noise.
            var result = ZonePairRisk.Assess(
                Z("mgmt", TrustTier.ControlPlane, ZoneRoles.Management),
                Z("server", TrustTier.Server, ZoneRoles.Server),
                Svc("SMB", ServiceRisk.Critical));

            Assert.True(result.Severity < Severity.High,
                $"expected admin path to score below High, got {result.Severity}");
        }

        [Fact]
        public void GuestToAnything_IsCritical()
        {
            var result = ZonePairRisk.Assess(
                Z("guest", TrustTier.Untrusted, ZoneRoles.Untrusted),
                Z("server", TrustTier.Server, ZoneRoles.Server),
                Svc("SMB", ServiceRisk.Critical));

            Assert.Equal(Severity.Critical, result.Severity);
        }

        [Fact]
        public void ItToOt_IsEscalated()
        {
            var itToOt = ZonePairRisk.Assess(
                Z("server", TrustTier.Server, ZoneRoles.Server),
                Z("plant", TrustTier.Server, ZoneRoles.Ot),
                Svc("MODBUS", ServiceRisk.Critical, ServiceCategories.OtIcs));

            var otToOt = ZonePairRisk.Assess(
                Z("plant-a", TrustTier.Server, ZoneRoles.Ot),
                Z("plant-b", TrustTier.Server, ZoneRoles.Ot),
                Svc("MODBUS", ServiceRisk.Critical, ServiceCategories.OtIcs));

            Assert.True(itToOt.RawScore > otToOt.RawScore,
                "crossing the IT/OT boundary must score higher than staying inside OT");
            Assert.Contains("IT/OT", itToOt.Rationale);
        }

        [Fact]
        public void RationaleExplainsTheScore()
        {
            var result = ZonePairRisk.Assess(
                Z("user", TrustTier.User, ZoneRoles.User),
                Z("tier0", TrustTier.ControlPlane, ZoneRoles.Tier0),
                Svc("RDP", ServiceRisk.Critical));

            Assert.False(string.IsNullOrWhiteSpace(result.Rationale));
            Assert.Contains("control plane", result.Rationale);
        }
    }

    public class SegmentationPolicyTests
    {
        private static readonly DateTimeOffset Now = new(2026, 7, 1, 0, 0, 0, TimeSpan.Zero);

        private static SegmentationPolicy PolicyWith(params PolicyRule[] rules) =>
            new() { DefaultAction = "deny", Rules = rules.ToList() };

        [Fact]
        public void NoMatchingRule_FallsBackToDefaultDeny()
        {
            var decision = PolicyWith().Evaluate("user", "tier0", "SMB", Now);

            Assert.Equal(PolicyAction.Deny, decision.Action);
            Assert.Null(decision.MatchedRule);
            Assert.Contains("default action", decision.Reason);
        }

        [Fact]
        public void ExplicitAllow_IsHonoured()
        {
            var policy = PolicyWith(new PolicyRule
            {
                Id = "admin-path",
                From = new List<string> { "mgmt" },
                To = new List<string> { "server" },
                Services = new List<string> { "RDP" },
                Action = "allow",
            });

            var decision = policy.Evaluate("mgmt", "server", "RDP", Now);

            Assert.Equal(PolicyAction.Allow, decision.Action);
            Assert.Equal("admin-path", decision.MatchedRule?.Id);
        }

        [Fact]
        public void WildcardsMatch()
        {
            var policy = PolicyWith(new PolicyRule
            {
                Id = "deny-guest",
                From = new List<string> { "guest" },
                To = new List<string> { "*" },
                Services = new List<string> { "*" },
                Action = "deny",
            });

            Assert.Equal(PolicyAction.Deny, policy.Evaluate("guest", "tier0", "SMB", Now).Action);
        }

        [Fact]
        public void MoreSpecificRuleBeatsWildcard()
        {
            var policy = PolicyWith(
                new PolicyRule
                {
                    Id = "broad-allow",
                    From = new List<string> { "*" }, To = new List<string> { "*" },
                    Services = new List<string> { "*" }, Action = "allow",
                },
                new PolicyRule
                {
                    Id = "specific-deny",
                    From = new List<string> { "user" }, To = new List<string> { "tier0" },
                    Services = new List<string> { "SMB" }, Action = "deny",
                });

            var decision = policy.Evaluate("user", "tier0", "SMB", Now);

            Assert.Equal(PolicyAction.Deny, decision.Action);
            Assert.Equal("specific-deny", decision.MatchedRule?.Id);
        }

        [Fact]
        public void EquallySpecificConflict_FailsClosed()
        {
            var policy = PolicyWith(
                new PolicyRule
                {
                    Id = "allow", From = new List<string> { "user" },
                    To = new List<string> { "tier0" },
                    Services = new List<string> { "SMB" }, Action = "allow",
                },
                new PolicyRule
                {
                    Id = "deny", From = new List<string> { "user" },
                    To = new List<string> { "tier0" },
                    Services = new List<string> { "SMB" }, Action = "deny",
                });

            Assert.Equal(PolicyAction.Deny, policy.Evaluate("user", "tier0", "SMB", Now).Action);
        }

        [Fact]
        public void ExpiredAllowRule_DoesNotAuthoriseTraffic()
        {
            var policy = PolicyWith(new PolicyRule
            {
                Id = "stale-exception",
                From = new List<string> { "user" }, To = new List<string> { "tier0" },
                Services = new List<string> { "RDP" }, Action = "allow",
                ExpiresOn = "2026-01-01",
            });

            var decision = policy.Evaluate("user", "tier0", "RDP", Now);

            Assert.Equal(PolicyAction.Deny, decision.Action);
            Assert.True(decision.IsExpired);
            Assert.Contains("expired", decision.Reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void UnexpiredRule_IsNotFlaggedExpired()
        {
            var policy = PolicyWith(new PolicyRule
            {
                Id = "current",
                From = new List<string> { "mgmt" }, To = new List<string> { "server" },
                Services = new List<string> { "SSH" }, Action = "allow",
                ExpiresOn = "2027-01-01",
            });

            var decision = policy.Evaluate("mgmt", "server", "SSH", Now);

            Assert.Equal(PolicyAction.Allow, decision.Action);
            Assert.False(decision.IsExpired);
        }

        [Fact]
        public void ZoneMatchingIsCaseInsensitive()
        {
            var policy = PolicyWith(new PolicyRule
            {
                From = new List<string> { "MGMT" }, To = new List<string> { "Server" },
                Services = new List<string> { "rdp" }, Action = "allow",
            });

            Assert.Equal(PolicyAction.Allow, policy.Evaluate("mgmt", "server", "RDP", Now).Action);
        }
    }
}
