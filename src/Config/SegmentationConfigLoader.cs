using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Network;

namespace ZeroTrustAuditor.Config
{
    /// <summary>Errors block the run; warnings are printed and the run continues.</summary>
    public sealed class ValidationResult
    {
        public List<string> Errors   { get; } = new();
        public List<string> Warnings { get; } = new();

        public bool HasErrors   => Errors.Count > 0;
        public bool HasWarnings => Warnings.Count > 0;

        public void Error(string message)   => Errors.Add(message);
        public void Warn(string message)    => Warnings.Add(message);

        public void PrintTo(TextWriter output, TextWriter errorOutput)
        {
            foreach (var w in Warnings) output.WriteLine($"[warn] {w}");
            foreach (var e in Errors)   errorOutput.WriteLine($"[!] config error: {e}");
        }
    }

    /// <summary>Everything the segmentation analysis needs, loaded and validated.</summary>
    public sealed class SegmentationContext
    {
        public ZoneResolver       Zones      { get; init; } = new(Array.Empty<ZoneDefinition>());
        public SegmentationPolicy Policy     { get; init; } = new();
        public ServiceCatalog     Services   { get; init; } = new();
        public ValidationResult   Validation { get; init; } = new();

        /// <summary>
        /// False when no zone CIDRs were supplied. Segmentation analysis is then not
        /// possible: rather than guessing boundaries from an address octet, the
        /// cross-zone checks are skipped and the gap is reported explicitly.
        /// </summary>
        public bool IsConfigured => !Zones.IsEmpty;
    }

    public static class SegmentationConfigLoader
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling         = JsonCommentHandling.Skip,
            AllowTrailingCommas         = true,
            // services.json writes risk levels as names ("Critical"), not integers.
            // Without this converter every service class fails to deserialize.
            Converters                  = { new JsonStringEnumConverter() },
        };

        public const string DefaultZonesFile    = "zones.json";
        public const string DefaultPolicyFile   = "policy.json";
        public const string DefaultServicesFile = "services.json";

        public static SegmentationContext Load(
            string? zonesPath, string? policyPath, string? servicesPath, string? baseDirectory = null)
        {
            var validation = new ValidationResult();
            var baseDir    = baseDirectory ?? AppContext.BaseDirectory;

            var zoneSet  = LoadZones(Resolve(zonesPath, DefaultZonesFile, baseDir), validation);
            var policy   = LoadPolicy(Resolve(policyPath, DefaultPolicyFile, baseDir), validation);
            var services = LoadServices(Resolve(servicesPath, DefaultServicesFile, baseDir), validation);

            var resolver = new ZoneResolver(zoneSet.Zones, zoneSet.UnclassifiedZone);

            CrossValidate(resolver, policy, services, validation);

            return new SegmentationContext
            {
                Zones      = resolver,
                Policy     = policy,
                Services   = services,
                Validation = validation,
            };
        }

        private static string Resolve(string? explicitPath, string defaultName, string baseDir)
        {
            if (!string.IsNullOrWhiteSpace(explicitPath))
            {
                return Path.IsPathRooted(explicitPath)
                    ? explicitPath
                    : Path.Combine(Directory.GetCurrentDirectory(), explicitPath);
            }

            // Prefer a file next to the working directory, then next to the exe.
            var cwdCandidate = Path.Combine(Directory.GetCurrentDirectory(), defaultName);
            return File.Exists(cwdCandidate) ? cwdCandidate : Path.Combine(baseDir, defaultName);
        }

        // ── Zones ─────────────────────────────────────────────────────────────

        internal static ZoneSet LoadZones(string path, ValidationResult validation)
        {
            if (!File.Exists(path))
            {
                validation.Warn(
                    $"No zone definitions found at '{path}'. Segmentation analysis needs a zone " +
                    "map -- cross-zone checks will be skipped. Copy zones.example.json to " +
                    "zones.json and describe your network, or pass --zones <file>.");
                return new ZoneSet { Zones = new List<ZoneDefinition>() };
            }

            ZoneSet? set;
            try
            {
                set = JsonSerializer.Deserialize<ZoneSet>(File.ReadAllText(path), JsonOpts);
            }
            catch (JsonException ex)
            {
                validation.Error($"'{path}' is not valid JSON: {ex.Message}");
                return new ZoneSet { Zones = new List<ZoneDefinition>() };
            }

            if (set == null)
            {
                validation.Error($"'{path}' deserialized to nothing.");
                return new ZoneSet { Zones = new List<ZoneDefinition>() };
            }

            ValidateZones(set, path, validation);
            return set;
        }

        private static void ValidateZones(ZoneSet set, string path, ValidationResult validation)
        {
            var seenIds    = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenRanges = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var zone in set.Zones)
            {
                if (string.IsNullOrWhiteSpace(zone.Id))
                {
                    validation.Error($"{path}: a zone is missing its 'id'.");
                    continue;
                }

                if (!seenIds.Add(zone.Id))
                    validation.Error($"{path}: duplicate zone id '{zone.Id}'.");

                if (zone.Id.Equals(set.UnclassifiedZone.Id, StringComparison.OrdinalIgnoreCase))
                    validation.Error(
                        $"{path}: zone id '{zone.Id}' collides with the reserved unclassified zone id.");

                if (zone.Tier < TrustTier.Min || zone.Tier > TrustTier.Max)
                    validation.Error(
                        $"{path}: zone '{zone.Id}' has trustTier {zone.Tier}; " +
                        $"valid range is {TrustTier.Min}-{TrustTier.Max}.");

                if (!ZoneRoles.Known.Contains(zone.Role))
                    validation.Warn(
                        $"{path}: zone '{zone.Id}' has unrecognised role '{zone.Role}'. " +
                        $"Known roles: {string.Join(", ", ZoneRoles.Known)}. " +
                        "Risk scoring rules keyed to roles will not apply.");

                if (zone.Cidrs.Count == 0)
                    validation.Warn(
                        $"{path}: zone '{zone.Id}' declares no CIDRs, so no address will ever " +
                        "resolve to it.");

                foreach (var cidr in zone.Cidrs)
                {
                    if (!IpRange.TryParse(cidr, out var range, out var error))
                    {
                        validation.Error($"{path}: zone '{zone.Id}' has invalid CIDR '{cidr}': {error}");
                        continue;
                    }

                    var key = range!.ToString();
                    if (seenRanges.TryGetValue(key, out var owner) && owner != zone.Id)
                    {
                        validation.Error(
                            $"{path}: CIDR {key} is claimed by both '{owner}' and '{zone.Id}'. " +
                            "An address cannot belong to two zones.");
                        continue;
                    }

                    seenRanges[key] = zone.Id;

                    // Flag a host-bits-set CIDR: 10.1.2.3/24 almost always means /32.
                    if (!string.Equals(cidr.Trim(), key, StringComparison.OrdinalIgnoreCase) &&
                        cidr.Contains('/'))
                    {
                        validation.Warn(
                            $"{path}: zone '{zone.Id}' declares '{cidr}', which has host bits set; " +
                            $"it was normalised to {key}.");
                    }

                    zone.Ranges.Add(range);
                }
            }

            if (set.Zones.Count > 0 && set.Zones.All(z => z.Ranges.Count == 0))
                validation.Error($"{path}: no zone has a usable CIDR; segmentation analysis cannot run.");
        }

        // ── Policy ────────────────────────────────────────────────────────────

        internal static SegmentationPolicy LoadPolicy(string path, ValidationResult validation)
        {
            if (!File.Exists(path))
            {
                validation.Warn(
                    $"No segmentation policy found at '{path}'. Every cross-zone flow will be " +
                    "evaluated against the default-deny baseline with no approved exceptions, " +
                    "so expected administration paths will appear as violations. " +
                    "Copy policy.example.json to policy.json to declare them.");
                return new SegmentationPolicy();
            }

            try
            {
                var policy = JsonSerializer.Deserialize<SegmentationPolicy>(
                    File.ReadAllText(path), JsonOpts);

                if (policy == null)
                {
                    validation.Error($"'{path}' deserialized to nothing.");
                    return new SegmentationPolicy();
                }

                if (policy.ResolvedDefaultAction == PolicyAction.Allow)
                    validation.Warn(
                        $"{path}: defaultAction is 'allow'. Segmentation assessment assumes " +
                        "default-deny; with allow, only explicitly denied flows are ever reported.");

                return policy;
            }
            catch (JsonException ex)
            {
                validation.Error($"'{path}' is not valid JSON: {ex.Message}");
                return new SegmentationPolicy();
            }
        }

        // ── Services ──────────────────────────────────────────────────────────

        internal static ServiceCatalog LoadServices(string path, ValidationResult validation)
        {
            if (!File.Exists(path))
            {
                validation.Warn(
                    $"No service catalog found at '{path}'; using the built-in minimal catalog " +
                    $"({BuiltInCatalog().ServiceClasses.Count} classes). Ship services.json for " +
                    "full coverage of databases, hypervisors, OOB management and OT protocols.");
                var fallback = BuiltInCatalog();
                fallback.Index();
                return fallback;
            }

            try
            {
                var catalog = JsonSerializer.Deserialize<ServiceCatalog>(
                    File.ReadAllText(path), JsonOpts);

                if (catalog == null || catalog.ServiceClasses.Count == 0)
                {
                    validation.Error($"'{path}' contains no service classes.");
                    var fallback = BuiltInCatalog();
                    fallback.Index();
                    return fallback;
                }

                ValidateServices(catalog, path, validation);
                catalog.Index();
                return catalog;
            }
            catch (JsonException ex)
            {
                validation.Error($"'{path}' is not valid JSON: {ex.Message}");
                var fallback = BuiltInCatalog();
                fallback.Index();
                return fallback;
            }
        }

        private static void ValidateServices(
            ServiceCatalog catalog, string path, ValidationResult validation)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var service in catalog.ServiceClasses)
            {
                if (string.IsNullOrWhiteSpace(service.Id))
                {
                    validation.Error($"{path}: a service class is missing its 'id'.");
                    continue;
                }

                if (!seen.Add(service.Id))
                    validation.Error($"{path}: duplicate service class id '{service.Id}'.");

                if (service.Ports.Count == 0)
                    validation.Warn($"{path}: service '{service.Id}' declares no ports.");

                foreach (var port in service.Ports)
                    if (port is < 1 or > 65535)
                        validation.Error(
                            $"{path}: service '{service.Id}' has out-of-range port {port}.");

                if (!service.Transport.Equals("tcp", StringComparison.OrdinalIgnoreCase) &&
                    !service.Transport.Equals("udp", StringComparison.OrdinalIgnoreCase))
                    validation.Error(
                        $"{path}: service '{service.Id}' has transport '{service.Transport}'; " +
                        "expected 'tcp' or 'udp'.");
            }
        }

        // ── Cross-file validation ─────────────────────────────────────────────

        private static void CrossValidate(
            ZoneResolver zones, SegmentationPolicy policy,
            ServiceCatalog services, ValidationResult validation)
        {
            if (zones.IsEmpty) return;

            var zoneIds = new HashSet<string>(
                zones.Zones.Select(z => z.Id), StringComparer.OrdinalIgnoreCase)
            {
                zones.UnclassifiedZone.Id
            };

            var now = DateTimeOffset.UtcNow;

            foreach (var rule in policy.Rules)
            {
                var label = SegmentationPolicy.RuleLabel(rule);

                foreach (var zoneRef in rule.From.Concat(rule.To))
                {
                    if (zoneRef == "*") continue;
                    if (!zoneIds.Contains(zoneRef))
                        validation.Error(
                            $"policy rule '{label}' references unknown zone '{zoneRef}'. " +
                            "A typo here silently disables the exception and turns an approved " +
                            "path into a reported violation.");
                }

                foreach (var serviceRef in rule.Services)
                {
                    if (serviceRef == "*") continue;
                    if (services.ById(serviceRef) == null)
                        validation.Error(
                            $"policy rule '{label}' references unknown service class " +
                            $"'{serviceRef}'.");
                }

                if (rule.IsExpiredAsOf(now))
                    validation.Warn(
                        $"policy rule '{label}' expired on {rule.ExpiresOn} and no longer " +
                        "authorises traffic. Renew it or remove it.");

                if (rule.ResolvedAction == PolicyAction.Allow &&
                    string.IsNullOrWhiteSpace(rule.Owner))
                    validation.Warn(
                        $"policy rule '{label}' allows a cross-zone flow but names no owner. " +
                        "Unowned exceptions are how permanent holes start.");
            }
        }

        // ── Built-in fallback catalog ─────────────────────────────────────────

        /// <summary>
        /// A deliberately small set covering the highest-value lateral movement
        /// services, so the tool still functions without services.json. This is a
        /// fallback, not a mirror of the shipped catalog.
        /// </summary>
        internal static ServiceCatalog BuiltInCatalog() => new()
        {
            ServiceClasses = new List<ServiceClassDefinition>
            {
                Svc("SMB",         new[] { 445, 139 }, ServiceRisk.Critical, ServiceCategories.RemoteAdmin,  "T1021.002"),
                Svc("RPC_EPM",     new[] { 135 },      ServiceRisk.Critical, ServiceCategories.RemoteAdmin,  "T1021.003"),
                Svc("RDP",         new[] { 3389 },     ServiceRisk.Critical, ServiceCategories.RemoteAdmin,  "T1021.001"),
                Svc("WINRM_HTTP",  new[] { 5985 },     ServiceRisk.Critical, ServiceCategories.RemoteAdmin,  "T1021.006"),
                Svc("WINRM_HTTPS", new[] { 5986 },     ServiceRisk.High,     ServiceCategories.RemoteAdmin,  "T1021.006"),
                Svc("SSH",         new[] { 22 },       ServiceRisk.High,     ServiceCategories.RemoteAdmin,  "T1021.004"),
                Svc("VNC",         new[] { 5900 },     ServiceRisk.Critical, ServiceCategories.RemoteAdmin,  "T1021.005"),
                Svc("MSSQL",       new[] { 1433 },     ServiceRisk.High,     ServiceCategories.Database,     ""),
                Svc("MYSQL",       new[] { 3306 },     ServiceRisk.High,     ServiceCategories.Database,     ""),
                Svc("POSTGRES",    new[] { 5432 },     ServiceRisk.High,     ServiceCategories.Database,     ""),
                Svc("TELNET",      new[] { 23 },       ServiceRisk.Critical, ServiceCategories.CleartextLegacy, ""),
                Svc("FTP",         new[] { 21 },       ServiceRisk.High,     ServiceCategories.CleartextLegacy, ""),
                Svc("LDAP_CLEAR",  new[] { 389 },      ServiceRisk.High,     ServiceCategories.Directory,    ""),
                Svc("ESXI",        new[] { 902 },      ServiceRisk.Critical, ServiceCategories.Hypervisor,   ""),
            }
        };

        private static ServiceClassDefinition Svc(
            string id, int[] ports, ServiceRisk risk, string category, string mitre) =>
            new()
            {
                Id       = id,
                Ports    = ports.ToList(),
                Risk     = risk,
                Category = category,
                Mitre    = mitre,
            };
    }
}
