using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace ZeroTrustAuditor.Models
{
    /// <summary>
    /// Intrinsic danger of a service class, independent of where it is reachable
    /// from. Final severity combines this with the zone pair -- SMB between two
    /// management hosts is expected; the same SMB from a guest VLAN is critical.
    /// </summary>
    public enum ServiceRisk
    {
        Low      = 0,
        Medium   = 1,
        High     = 2,
        Critical = 3
    }

    /// <summary>How the probe engine is permitted to interact with a service.</summary>
    public static class ProbePolicies
    {
        /// <summary>Normal TCP connect / UDP probe.</summary>
        public const string Active = "active";

        /// <summary>
        /// Never actively connected to. Reserved for OT/ICS protocols where an
        /// unexpected connection can fault a PLC. Reported from discovery data only,
        /// unless the operator explicitly opts in AND the zone allows active probing.
        /// </summary>
        public const string PassiveOnly = "passive-only";
    }

    public static class ServiceCategories
    {
        public const string RemoteAdmin     = "remote-admin";
        public const string Database        = "database";
        public const string OobManagement   = "oob-management";
        public const string Hypervisor      = "hypervisor";
        public const string CleartextLegacy = "cleartext-legacy";
        public const string FileShare       = "file-share";
        public const string Directory       = "directory";
        public const string OtIcs           = "ot-ics";
    }

    public sealed class ServiceClassDefinition
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("ports")]
        public List<int> Ports { get; set; } = new();

        [JsonPropertyName("transport")]
        public string Transport { get; set; } = "tcp";

        [JsonPropertyName("risk")]
        public ServiceRisk Risk { get; set; } = ServiceRisk.Medium;

        [JsonPropertyName("category")]
        public string Category { get; set; } = ServiceCategories.RemoteAdmin;

        [JsonPropertyName("mitre")]
        public string Mitre { get; set; } = string.Empty;

        [JsonPropertyName("note")]
        public string Note { get; set; } = string.Empty;

        [JsonPropertyName("probePolicy")]
        public string ProbePolicy { get; set; } = ProbePolicies.Active;

        [JsonIgnore]
        public bool IsPassiveOnly =>
            ProbePolicy.Equals(ProbePolicies.PassiveOnly, StringComparison.OrdinalIgnoreCase);

        public override string ToString() =>
            $"{Id} ({Transport}/{string.Join(",", Ports)})";
    }

    /// <summary>Root of services.json.</summary>
    public sealed class ServiceCatalog
    {
        [JsonPropertyName("serviceClasses")]
        public List<ServiceClassDefinition> ServiceClasses { get; set; } = new();

        [JsonIgnore]
        private Dictionary<string, ServiceClassDefinition>? _byId;

        [JsonIgnore]
        private Dictionary<(int Port, string Transport), List<ServiceClassDefinition>>? _byPort;

        /// <summary>Builds the lookup indexes. Call after deserialization.</summary>
        public void Index()
        {
            _byId = new Dictionary<string, ServiceClassDefinition>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in ServiceClasses)
                _byId[s.Id] = s;

            _byPort = new Dictionary<(int, string), List<ServiceClassDefinition>>();
            foreach (var s in ServiceClasses)
            {
                foreach (var port in s.Ports)
                {
                    var key = (port, s.Transport.ToLowerInvariant());
                    if (!_byPort.TryGetValue(key, out var list))
                        _byPort[key] = list = new List<ServiceClassDefinition>();
                    list.Add(s);
                }
            }
        }

        public ServiceClassDefinition? ById(string? id)
        {
            if (id == null) return null;
            if (_byId == null) Index();
            return _byId!.TryGetValue(id, out var s) ? s : null;
        }

        public IReadOnlyList<ServiceClassDefinition> ByPort(int port, string transport = "tcp")
        {
            if (_byPort == null) Index();
            return _byPort!.TryGetValue((port, transport.ToLowerInvariant()), out var list)
                ? list
                : Array.Empty<ServiceClassDefinition>();
        }

        public IEnumerable<ServiceClassDefinition> ActivelyProbable() =>
            ServiceClasses.Where(s => !s.IsPassiveOnly);

        /// <summary>Distinct TCP ports worth probing, for building a scan plan.</summary>
        public IEnumerable<int> ActiveTcpPorts() =>
            ServiceClasses
                .Where(s => !s.IsPassiveOnly &&
                            s.Transport.Equals("tcp", StringComparison.OrdinalIgnoreCase))
                .SelectMany(s => s.Ports)
                .Distinct()
                .OrderBy(p => p);
    }
}
