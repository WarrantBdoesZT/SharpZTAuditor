using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Xunit;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Reports;

namespace ZeroTrustAuditor.Tests
{
    public class SegmentationReportTests : IDisposable
    {
        private readonly string _dir;

        public SegmentationReportTests()
        {
            _dir = Path.Combine(Path.GetTempPath(), "zta-rep-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { }
        }

        private static SegmentationAnalysis Sample()
        {
            var zones = new List<ZoneDefinition>
            {
                new() { Id = "user-vlan", Name = "Users",   Tier = TrustTier.User,         Role = ZoneRoles.User },
                new() { Id = "tier0",     Name = "Tier 0",  Tier = TrustTier.ControlPlane, Role = ZoneRoles.Tier0 },
            };

            var cells = new List<ZoneMatrixCell>
            {
                new() { FromZoneId = "user-vlan", ToZoneId = "tier0", Assessed = true,
                        OpenCount = 1, ViolationCount = 1, WorstSeverity = Severity.Critical },
                new() { FromZoneId = "user-vlan", ToZoneId = "user-vlan", Assessed = true, FilteredCount = 1 },
                new() { FromZoneId = "tier0",     ToZoneId = "user-vlan" },   // never probed
                new() { FromZoneId = "tier0",     ToZoneId = "tier0" },
            };
            cells[0].CrossingServices.Add("SMB");

            var finding = new SegmentationFinding
            {
                VantageZoneId = "user-vlan", VantageIp = "10.10.5.5", VantageHost = "aud01",
                TargetIp = "10.30.1.10", TargetHostname = "DC01", TargetZoneId = "tier0",
                Port = 445, ServiceClass = "SMB",
                Verdict = ReachabilityVerdict.Open, Policy = PolicyStatus.Violation,
                Severity = Severity.Critical, RiskScore = 9.0, Confidence = 1.0,
                Description = "SMB reachable from users into tier 0.",
                Remediation = "Deny user-vlan -> tier0 on tcp/445.",
                Evidence = new ProbeEvidence { Method = "tcp-connect", Response = "syn-ack", Attempts = 1 },
                Guidance = new List<GuidanceRef>
                {
                    new()
                    {
                        Source = "CISA/NSA", Document = "AA23-278A",
                        Section = "Lack of network segmentation",
                        Url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a",
                    },
                    new() { Source = "NSA", Document = "Out-of-Band Network Management", Section = "No URL here" },
                },
            };

            return new SegmentationAnalysis
            {
                VantageHost = "aud01", VantageIp = "10.10.5.5", VantageZoneId = "user-vlan",
                Findings = new List<SegmentationFinding> { finding },
                Matrix = new ZoneMatrix { Zones = zones, Cells = cells },
                Exposures = new List<EndpointExposure>
                {
                    new()
                    {
                        TargetIp = "10.30.1.10", Hostname = "DC01",
                        ZoneId = "tier0", ZoneName = "Tier 0", ZoneRole = "tier0", ZoneTier = 0,
                        ReachableFromZones = new List<string> { "user-vlan" },
                        Services = new List<ExposedService>
                        {
                            new()
                            {
                                ServiceClassId = "SMB", Port = 445,
                                Verdict = ReachabilityVerdict.Open,
                                Policy = PolicyStatus.Violation, Severity = Severity.Critical,
                            },
                        },
                    },
                },
                Scorecard = new ZtmmScorecard
                {
                    Caveat = "Scored from 2 of 4 zone pairs.",
                    Functions = new List<ZtmmFunctionScore>
                    {
                        new() { Function = "Network Segmentation", Stage = ZtmmStage.Traditional,
                                Evidence = "1 critical violation", NextStep = "Close it" },
                        new() { Function = "Network Resilience", Assessed = false,
                                Evidence = "Not measured", NextStep = "Assess separately" },
                    },
                },
                ProgramGuidance = new List<GuidanceRef>
                {
                    new() { Source = "NSA", Document = "Top Ten Mitigation Strategies",
                            Section = "Segment Networks" },
                },
            };
        }

        [Fact]
        public void HtmlIsWrittenWithoutBom()
        {
            var path = Path.Combine(_dir, "seg.html");
            new SegmentationReportRenderer().WriteHtml(Sample(), path);

            var bytes = File.ReadAllBytes(path);
            Assert.False(bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF);
        }

        [Fact]
        public void HtmlContainsTheMatrixExposureRegisterAndScorecard()
        {
            var path = Path.Combine(_dir, "seg.html");
            new SegmentationReportRenderer().WriteHtml(Sample(), path);
            var html = File.ReadAllText(path);

            Assert.Contains("Zone reachability matrix", html);
            Assert.Contains("Endpoint exposure register", html);
            Assert.Contains("Zero Trust Maturity Model", html);
            Assert.Contains("10.30.1.10", html);
            Assert.Contains("DC01", html);
        }

        [Fact]
        public void UnassessedPairsAreRenderedDistinctly()
        {
            // The report must never let an unmeasured pair read as a clean one.
            var path = Path.Combine(_dir, "seg.html");
            new SegmentationReportRenderer().WriteHtml(Sample(), path);
            var html = File.ReadAllText(path);

            Assert.Contains("m-na", html);
            Assert.Contains("Not assessed from this vantage", html);
            Assert.Contains("not assessed", html, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void GuidanceRendersLinksWhenPresentAndPlainTextWhenNot()
        {
            var path = Path.Combine(_dir, "seg.html");
            new SegmentationReportRenderer().WriteHtml(Sample(), path);
            var html = File.ReadAllText(path);

            Assert.Contains("https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a", html);
            // A document cited without a URL must still appear, not be dropped.
            Assert.Contains("Out-of-Band Network Management", html);
        }

        [Fact]
        public void HtmlEscapesUntrustedText()
        {
            var analysis = Sample();
            analysis.Exposures[0] = new EndpointExposure
            {
                TargetIp = "10.0.0.1",
                Hostname = "<script>alert(1)</script>",
                ZoneId = "z", ZoneName = "z", ZoneRole = "server",
                Services = new List<ExposedService>
                {
                    new() { ServiceClassId = "SMB", Port = 445,
                            Verdict = ReachabilityVerdict.Open,
                            Policy = PolicyStatus.Violation, Severity = Severity.High },
                },
            };

            var path = Path.Combine(_dir, "xss.html");
            new SegmentationReportRenderer().WriteHtml(analysis, path);
            var html = File.ReadAllText(path);

            Assert.DoesNotContain("<script>alert(1)</script>", html);
            Assert.Contains("&lt;script&gt;", html);
        }

        [Fact]
        public void JsonIsValidAndBomFree()
        {
            var path = Path.Combine(_dir, "seg.json");
            new SegmentationReportRenderer().WriteJson(Sample(), path);

            var bytes = File.ReadAllBytes(path);
            Assert.False(bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF);

            using var doc = JsonDocument.Parse(bytes);
            Assert.Equal("user-vlan", doc.RootElement.GetProperty("VantageZoneId").GetString());
        }

        [Fact]
        public void ExposureCsvHasOneRowPerEndpointPlusHeader()
        {
            var path = Path.Combine(_dir, "exposure.csv");
            new SegmentationReportRenderer().WriteExposureCsv(Sample(), path);

            var lines = File.ReadAllLines(path);
            Assert.Equal(2, lines.Length);
            Assert.StartsWith("TargetIp,Hostname,Zone", lines[0]);
            Assert.Contains("10.30.1.10", lines[1]);
            Assert.Contains("Critical", lines[1]);
        }

        [Fact]
        public void EmptyExposureRegisterSaysSoExplicitly()
        {
            var analysis = Sample();
            analysis.Exposures.Clear();

            var path = Path.Combine(_dir, "empty.html");
            new SegmentationReportRenderer().WriteHtml(analysis, path);
            var html = File.ReadAllText(path);

            Assert.Contains("No endpoint was found reachable", html);
        }
    }
}
