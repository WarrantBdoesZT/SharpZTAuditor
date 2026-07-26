using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using Xunit;
using ZeroTrustAuditor.Config;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Tests
{
    public class SegmentationConfigTests : IDisposable
    {
        private readonly string _dir;

        public SegmentationConfigTests()
        {
            _dir = Path.Combine(Path.GetTempPath(), "zta-seg-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { }
        }

        private string WriteFile(string name, string content)
        {
            var path = Path.Combine(_dir, name);
            File.WriteAllText(path, content);
            return path;
        }

        // ── Zones ─────────────────────────────────────────────────────────────

        [Fact]
        public void MissingZoneFile_WarnsRatherThanFailing()
        {
            var validation = new ValidationResult();
            var set = SegmentationConfigLoader.LoadZones(
                Path.Combine(_dir, "absent.json"), validation);

            Assert.Empty(set.Zones);
            Assert.False(validation.HasErrors);
            Assert.True(validation.HasWarnings);
        }

        [Fact]
        public void MalformedJson_IsAnError()
        {
            var path = WriteFile("bad.json", "{ this is not json ");
            var validation = new ValidationResult();

            SegmentationConfigLoader.LoadZones(path, validation);

            Assert.True(validation.HasErrors);
        }

        [Fact]
        public void InvalidCidr_IsAnError()
        {
            var path = WriteFile("zones.json", """
            { "zones": [ { "id": "a", "cidrs": ["10.0.0.0/99"], "trustTier": 1, "role": "server" } ] }
            """);
            var validation = new ValidationResult();

            SegmentationConfigLoader.LoadZones(path, validation);

            Assert.Contains(validation.Errors, e => e.Contains("10.0.0.0/99"));
        }

        [Fact]
        public void DuplicateZoneId_IsAnError()
        {
            var path = WriteFile("zones.json", """
            { "zones": [
                { "id": "a", "cidrs": ["10.1.0.0/16"], "trustTier": 1, "role": "server" },
                { "id": "a", "cidrs": ["10.2.0.0/16"], "trustTier": 1, "role": "server" }
            ] }
            """);
            var validation = new ValidationResult();

            SegmentationConfigLoader.LoadZones(path, validation);

            Assert.Contains(validation.Errors, e => e.Contains("duplicate zone id"));
        }

        [Fact]
        public void SameCidrInTwoZones_IsAnError()
        {
            // An address cannot belong to two zones; silently picking one would
            // make every result for that range arbitrary.
            var path = WriteFile("zones.json", """
            { "zones": [
                { "id": "a", "cidrs": ["10.1.0.0/16"], "trustTier": 1, "role": "server" },
                { "id": "b", "cidrs": ["10.1.0.0/16"], "trustTier": 3, "role": "user" }
            ] }
            """);
            var validation = new ValidationResult();

            SegmentationConfigLoader.LoadZones(path, validation);

            Assert.Contains(validation.Errors, e => e.Contains("claimed by both"));
        }

        [Fact]
        public void OutOfRangeTrustTier_IsAnError()
        {
            var path = WriteFile("zones.json", """
            { "zones": [ { "id": "a", "cidrs": ["10.1.0.0/16"], "trustTier": 9, "role": "server" } ] }
            """);
            var validation = new ValidationResult();

            SegmentationConfigLoader.LoadZones(path, validation);

            Assert.Contains(validation.Errors, e => e.Contains("trustTier"));
        }

        [Fact]
        public void UnknownRole_WarnsButLoads()
        {
            var path = WriteFile("zones.json", """
            { "zones": [ { "id": "a", "cidrs": ["10.1.0.0/16"], "trustTier": 1, "role": "banana" } ] }
            """);
            var validation = new ValidationResult();

            var set = SegmentationConfigLoader.LoadZones(path, validation);

            Assert.False(validation.HasErrors);
            Assert.Contains(validation.Warnings, w => w.Contains("banana"));
            Assert.Single(set.Zones);
        }

        [Fact]
        public void HostBitsSetInCidr_Warns()
        {
            var path = WriteFile("zones.json", """
            { "zones": [ { "id": "a", "cidrs": ["10.1.2.3/24"], "trustTier": 1, "role": "server" } ] }
            """);
            var validation = new ValidationResult();

            SegmentationConfigLoader.LoadZones(path, validation);

            Assert.Contains(validation.Warnings, w => w.Contains("host bits"));
        }

        // ── Cross-file validation ─────────────────────────────────────────────

        [Fact]
        public void PolicyReferencingUnknownZone_IsAnError()
        {
            // A typo here silently disables an approved exception, turning a
            // legitimate admin path into a reported violation.
            var zones = WriteFile("zones.json", """
            { "zones": [ { "id": "mgmt", "cidrs": ["10.99.0.0/24"], "trustTier": 0, "role": "management" } ] }
            """);
            var policy = WriteFile("policy.json", """
            { "defaultAction": "deny",
              "rules": [ { "id": "r1", "from": "mgmt", "to": "typo-zone", "services": "*", "action": "allow" } ] }
            """);

            var ctx = SegmentationConfigLoader.Load(zones, policy, null, _dir);

            Assert.Contains(ctx.Validation.Errors, e => e.Contains("typo-zone"));
        }

        [Fact]
        public void PolicyReferencingUnknownService_IsAnError()
        {
            var zones = WriteFile("zones.json", """
            { "zones": [ { "id": "mgmt", "cidrs": ["10.99.0.0/24"], "trustTier": 0, "role": "management" } ] }
            """);
            var policy = WriteFile("policy.json", """
            { "defaultAction": "deny",
              "rules": [ { "id": "r1", "from": "mgmt", "to": "mgmt", "services": "NOT_A_SERVICE", "action": "allow" } ] }
            """);

            var ctx = SegmentationConfigLoader.Load(zones, policy, null, _dir);

            Assert.Contains(ctx.Validation.Errors, e => e.Contains("NOT_A_SERVICE"));
        }

        [Fact]
        public void UnownedAllowRule_Warns()
        {
            var zones = WriteFile("zones.json", """
            { "zones": [ { "id": "mgmt", "cidrs": ["10.99.0.0/24"], "trustTier": 0, "role": "management" } ] }
            """);
            var policy = WriteFile("policy.json", """
            { "defaultAction": "deny",
              "rules": [ { "id": "r1", "from": "mgmt", "to": "mgmt", "services": "*", "action": "allow" } ] }
            """);

            var ctx = SegmentationConfigLoader.Load(zones, policy, null, _dir);

            Assert.Contains(ctx.Validation.Warnings, w => w.Contains("names no owner"));
        }

        // ── Policy shorthand ──────────────────────────────────────────────────

        [Fact]
        public void FromAndTo_AcceptBothStringAndArray()
        {
            var path = WriteFile("policy.json", """
            { "defaultAction": "deny",
              "rules": [ { "id": "r1", "from": "mgmt", "to": ["a", "b"], "services": "RDP", "action": "allow" } ] }
            """);
            var validation = new ValidationResult();

            var policy = SegmentationConfigLoader.LoadPolicy(path, validation);
            var rule = policy.Rules.Single();

            Assert.Equal(new[] { "mgmt" }, rule.From.ToArray());
            Assert.Equal(new[] { "a", "b" }, rule.To.ToArray());
            Assert.Equal(new[] { "RDP" }, rule.Services.ToArray());
        }

        [Fact]
        public void DefaultActionAllow_Warns()
        {
            var path = WriteFile("policy.json", """{ "defaultAction": "allow", "rules": [] }""");
            var validation = new ValidationResult();

            SegmentationConfigLoader.LoadPolicy(path, validation);

            Assert.Contains(validation.Warnings, w => w.Contains("defaultAction"));
        }

        // ── Services ──────────────────────────────────────────────────────────

        [Fact]
        public void MissingServicesFile_FallsBackToBuiltInCatalog()
        {
            var validation = new ValidationResult();
            var catalog = SegmentationConfigLoader.LoadServices(
                Path.Combine(_dir, "absent.json"), validation);

            Assert.NotEmpty(catalog.ServiceClasses);
            Assert.NotNull(catalog.ById("SMB"));
            Assert.True(validation.HasWarnings);
        }

        [Fact]
        public void ServiceLookupByPortWorks()
        {
            var catalog = SegmentationConfigLoader.BuiltInCatalog();
            catalog.Index();

            Assert.Contains(catalog.ByPort(445), s => s.Id == "SMB");
            Assert.Contains(catalog.ByPort(3389), s => s.Id == "RDP");
            Assert.Empty(catalog.ByPort(9999));
        }

        [Fact]
        public void OutOfRangePort_IsAnError()
        {
            var path = WriteFile("services.json", """
            { "serviceClasses": [ { "id": "BAD", "ports": [70000], "transport": "tcp" } ] }
            """);
            var validation = new ValidationResult();

            SegmentationConfigLoader.LoadServices(path, validation);

            Assert.Contains(validation.Errors, e => e.Contains("out-of-range port"));
        }

        [Fact]
        public void PassiveOnlyServicesAreExcludedFromActiveProbing()
        {
            var path = WriteFile("services.json", """
            { "serviceClasses": [
                { "id": "SMB",    "ports": [445], "transport": "tcp", "risk": "Critical" },
                { "id": "MODBUS", "ports": [502], "transport": "tcp", "risk": "Critical", "probePolicy": "passive-only" }
            ] }
            """);
            var validation = new ValidationResult();

            var catalog = SegmentationConfigLoader.LoadServices(path, validation);

            Assert.Contains(445, catalog.ActiveTcpPorts());
            Assert.DoesNotContain(502, catalog.ActiveTcpPorts());
            Assert.True(catalog.ById("MODBUS")!.IsPassiveOnly);
        }

        // ── The shipped example files must actually be valid ──────────────────

        [Theory]
        [InlineData("zones.example.json")]
        [InlineData("policy.example.json")]
        [InlineData("services.json")]
        public void ShippedConfigFilesAreValidJson(string fileName)
        {
            var path = FindRepoFile(fileName);
            Assert.True(File.Exists(path), $"{fileName} not found at {path}");

            using var doc = JsonDocument.Parse(
                File.ReadAllText(path),
                new JsonDocumentOptions
                {
                    CommentHandling = JsonCommentHandling.Skip,
                    AllowTrailingCommas = true,
                });

            Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        }

        [Fact]
        public void ShippedExamplesLoadAndCrossValidateCleanly()
        {
            // The examples are what users copy. If they do not validate against each
            // other, the first run every new user does is a wall of config errors.
            var ctx = SegmentationConfigLoader.Load(
                FindRepoFile("zones.example.json"),
                FindRepoFile("policy.example.json"),
                FindRepoFile("services.json"));

            Assert.False(ctx.Validation.HasErrors,
                "shipped examples produced errors: " + string.Join(" | ", ctx.Validation.Errors));
            Assert.True(ctx.IsConfigured);

            // Spot-check that the zone map actually resolves as documented.
            Assert.Equal("tier0",
                ctx.Zones.Resolve(System.Net.IPAddress.Parse("10.30.1.10")).Id);
            Assert.Equal("user-vlan",
                ctx.Zones.Resolve(System.Net.IPAddress.Parse("10.10.5.5")).Id);
        }

        /// <summary>Walks up from the test binary to the repository root.</summary>
        private static string FindRepoFile(string fileName)
        {
            var dir = AppContext.BaseDirectory;
            for (var i = 0; i < 8 && dir != null; i++)
            {
                var candidate = Path.Combine(dir, fileName);
                if (File.Exists(candidate)) return candidate;
                dir = Path.GetDirectoryName(dir.TrimEnd(Path.DirectorySeparatorChar));
            }
            return fileName;
        }
    }
}
