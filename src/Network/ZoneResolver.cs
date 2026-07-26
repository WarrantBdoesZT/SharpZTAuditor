using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Network
{
    /// <summary>
    /// Maps an IP address to the zone that owns it, using longest-prefix match so
    /// that a specific carve-out (10.30.1.0/24 = tier0) wins over the broad block
    /// that contains it (10.0.0.0/8 = corporate).
    ///
    /// Entries are held in a flat array sorted by descending prefix length and
    /// scanned linearly. A radix trie would be asymptotically better, but real zone
    /// maps have tens of entries, not thousands -- at 50 zones x 5,000 endpoints
    /// this is a quarter-million byte comparisons, which is not worth the extra
    /// moving parts. Revisit if zone counts ever reach the hundreds.
    /// </summary>
    public sealed class ZoneResolver
    {
        private readonly (IpRange Range, ZoneDefinition Zone)[] _entries;

        public ZoneDefinition UnclassifiedZone { get; }
        public IReadOnlyList<ZoneDefinition> Zones { get; }

        public ZoneResolver(IEnumerable<ZoneDefinition> zones, ZoneDefinition? unclassifiedZone = null)
        {
            Zones = zones.ToList();

            UnclassifiedZone = unclassifiedZone ?? new ZoneDefinition
            {
                Id   = "unknown",
                Name = "Unclassified",
                Tier = TrustTier.Untrusted,
                Role = ZoneRoles.Untrusted,
            };

            _entries = Zones
                .SelectMany(z => z.Ranges.Select(r => (Range: r, Zone: z)))
                .OrderByDescending(e => e.Range.PrefixLength)
                .ToArray();
        }

        /// <summary>True when no zone CIDRs are defined -- segmentation analysis is not possible.</summary>
        public bool IsEmpty => _entries.Length == 0;

        public int RangeCount => _entries.Length;

        /// <summary>Resolves an address, falling back to the unclassified zone.</summary>
        public ZoneDefinition Resolve(IPAddress? address)
        {
            return TryResolve(address, out var zone) ? zone : UnclassifiedZone;
        }

        /// <summary>Returns false when the address matches no declared zone.</summary>
        public bool TryResolve(IPAddress? address, out ZoneDefinition zone)
        {
            zone = UnclassifiedZone;
            if (address == null) return false;

            foreach (var entry in _entries)
            {
                if (!entry.Range.Contains(address)) continue;
                zone = entry.Zone;
                return true;
            }

            return false;
        }

        /// <summary>The specific CIDR that matched, for evidence strings.</summary>
        public IpRange? MatchingRange(IPAddress? address)
        {
            if (address == null) return null;

            foreach (var entry in _entries)
                if (entry.Range.Contains(address))
                    return entry.Range;

            return null;
        }

        public ZoneDefinition? ById(string? id) =>
            id == null
                ? null
                : Zones.FirstOrDefault(z => z.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    }
}
