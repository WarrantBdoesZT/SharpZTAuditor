using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Models
{
    /// <summary>
    /// Trust tiers, following the Microsoft tier model so they compose with the AD
    /// enrichment. Lower is more trusted; 0 is the identity/control plane.
    /// </summary>
    public static class TrustTier
    {
        public const int ControlPlane = 0;   // DCs, PAWs, out-of-band management
        public const int Server       = 1;   // application / data tier
        public const int Perimeter    = 2;   // DMZ, partner-facing
        public const int User         = 3;   // corporate workstations
        public const int Untrusted    = 4;   // guest, BYOD, unclassified

        public const int Min = 0;
        public const int Max = 4;
    }

    /// <summary>Well-known zone roles. Unrecognised values are allowed but warned about.</summary>
    public static class ZoneRoles
    {
        public const string User       = "user";
        public const string Server     = "server";
        public const string Tier0      = "tier0";
        public const string Management = "management";
        public const string Dmz        = "dmz";
        public const string Ot         = "ot";
        public const string Untrusted  = "untrusted";

        public static readonly IReadOnlyCollection<string> Known = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase)
        {
            User, Server, Tier0, Management, Dmz, Ot, Untrusted
        };
    }

    /// <summary>
    /// A named region of the network, defined by CIDR blocks rather than inferred
    /// from an address octet.
    /// </summary>
    public sealed class ZoneDefinition
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("cidrs")]
        public List<string> Cidrs { get; set; } = new();

        /// <summary>0 = control plane ... 4 = untrusted. See <see cref="TrustTier"/>.</summary>
        [JsonPropertyName("trustTier")]
        public int Tier { get; set; } = TrustTier.User;

        [JsonPropertyName("role")]
        public string Role { get; set; } = ZoneRoles.User;

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Marks a zone as fragile (typically OT/ICS). Combined with a service's
        /// probePolicy this gates active probing: PLCs and BMCs can fault on an
        /// unexpected TCP connect, so the default is to never touch them.
        /// </summary>
        [JsonPropertyName("safeMode")]
        public bool SafeMode { get; set; }

        /// <summary>
        /// Explicit opt-in for active probing of a safeMode zone. Ignored unless the
        /// operator also passes the corresponding CLI flag.
        /// </summary>
        [JsonPropertyName("activeProbing")]
        public bool ActiveProbing { get; set; } = true;

        /// <summary>Parsed form of <see cref="Cidrs"/>, populated by the loader.</summary>
        [JsonIgnore]
        public List<IpRange> Ranges { get; } = new();

        [JsonIgnore]
        public string DisplayName => Name.Length > 0 ? Name : Id;

        public override string ToString() => $"{Id} (tier {Tier}, {Role})";
    }

    /// <summary>Root of zones.json.</summary>
    public sealed class ZoneSet
    {
        [JsonPropertyName("zones")]
        public List<ZoneDefinition> Zones { get; set; } = new();

        /// <summary>
        /// Where addresses matching no declared CIDR land.
        ///
        /// A large unknown zone is itself a finding: NSA's Network and Environment
        /// pillar names data flow mapping as the capability that segmentation depends
        /// on, and you cannot segment hosts you have not inventoried.
        /// </summary>
        [JsonPropertyName("unclassifiedZone")]
        public ZoneDefinition UnclassifiedZone { get; set; } = new()
        {
            Id          = "unknown",
            Name        = "Unclassified",
            Tier        = TrustTier.Untrusted,
            Role        = ZoneRoles.Untrusted,
            Description = "Addresses matching no declared zone CIDR. " +
                          "A large unclassified population means the network map is incomplete.",
        };
    }
}
