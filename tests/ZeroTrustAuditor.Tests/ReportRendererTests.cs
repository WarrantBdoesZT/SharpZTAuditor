using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Xunit;
using ZeroTrustAuditor.Models;
using ZeroTrustAuditor.Reports;

namespace ZeroTrustAuditor.Tests
{
    /// <summary>
    /// Output encoding regression tests.
    ///
    /// Every report format shipped with a UTF-8 BOM, which makes the file invalid
    /// JSON per RFC 8259 and is rejected by Splunk HEC and Sentinel ingestion.
    /// </summary>
    public class ReportRendererTests : IDisposable
    {
        private readonly string _dir;

        public ReportRendererTests()
        {
            _dir = Path.Combine(Path.GetTempPath(), "zta-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { }
        }

        private static readonly byte[] Bom = { 0xEF, 0xBB, 0xBF };

        private static void AssertNoBom(string path)
        {
            var bytes = File.ReadAllBytes(path);
            Assert.True(bytes.Length >= 3, $"{path} is unexpectedly short");
            Assert.False(
                bytes[0] == Bom[0] && bytes[1] == Bom[1] && bytes[2] == Bom[2],
                $"{Path.GetFileName(path)} starts with a UTF-8 BOM; strict JSON parsers " +
                "and SIEM ingestion endpoints will reject it.");
        }

        private static AuditReport SampleReport() => new AuditReport
        {
            Domain      = "corp.local",
            TargetHosts = new[] { "SRV01" },
            Findings = new List<Finding>
            {
                new Finding
                {
                    Host                = "SRV01",
                    Module              = "ProtocolProbe",
                    CheckName           = "SMB_SIGNING_DISABLED",
                    Severity            = Severity.High,
                    RiskScore           = 7.0,
                    Description         = "SMB signing is not required.",
                    Evidence            = "RequireSecuritySignature=0",
                    RemediationGuidance = "Set RequireSecuritySignature=1 via GPO.",
                }
            },
            SeveritySummary = new Dictionary<Severity, int> { [Severity.High] = 1 },
        };

        [Fact]
        public void WriteJson_HasNoBom_AndParsesAsStrictJson()
        {
            var path = Path.Combine(_dir, "report.json");
            new ReportRenderer().WriteJson(SampleReport(), path);

            AssertNoBom(path);

            // Would throw on a BOM-prefixed document.
            using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
            Assert.Equal("corp.local", doc.RootElement.GetProperty("Domain").GetString());
        }

        [Fact]
        public void WriteCsv_HasNoBom()
        {
            var path = Path.Combine(_dir, "report.csv");
            new ReportRenderer().WriteCsv(SampleReport(), path);
            AssertNoBom(path);
        }

        [Fact]
        public void WriteHtml_HasNoBom()
        {
            var path = Path.Combine(_dir, "report.html");
            new ReportRenderer().WriteHtml(SampleReport(), path);
            AssertNoBom(path);
        }

        [Fact]
        public void WriteSplunkHec_HasNoBom_AndEachLineIsValidJson()
        {
            var path = Path.Combine(_dir, "report.splunk.json");
            new SiemRenderer(new AuditConfig()).WriteSplunkHec(SampleReport(), path);

            AssertNoBom(path);

            foreach (var line in File.ReadAllLines(path))
            {
                if (line.Length == 0) continue;
                using var doc = JsonDocument.Parse(line);   // throws if malformed
                Assert.True(doc.RootElement.TryGetProperty("event", out _));
            }
        }

        [Fact]
        public void WriteSentinelJson_HasNoBom_AndParses()
        {
            var path = Path.Combine(_dir, "report.sentinel.json");
            new SiemRenderer(new AuditConfig()).WriteSentinelJson(SampleReport(), path);

            AssertNoBom(path);
            using var doc = JsonDocument.Parse(File.ReadAllBytes(path));
            Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
        }

        [Fact]
        public void WriteCsv_NeutralisesFormulaInjection()
        {
            var report = SampleReport();
            // Principal and share names come from AD and can begin with '='.
            report.Findings[0].Evidence = "=cmd|'/c calc'!A1";

            var path = Path.Combine(_dir, "injection.csv");
            new ReportRenderer().WriteCsv(report, path);

            var text = File.ReadAllText(path);
            Assert.Contains("\"'=cmd", text);        // prefixed, so Excel treats it as text
            Assert.DoesNotContain("\"=cmd", text);
        }

        [Fact]
        public void WriteCsv_KeepsOneRowPerFinding_EvenWithEmbeddedNewlines()
        {
            var report = SampleReport();
            report.Findings[0].Description = "line one\r\nline two\rline three";

            var path = Path.Combine(_dir, "newlines.csv");
            new ReportRenderer().WriteCsv(report, path);

            // 1 header + 1 finding. A bare CR used to split the row.
            var lines = File.ReadAllLines(path);
            Assert.Equal(2, lines.Length);
        }
    }
}
