using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;
using ZeroTrustAuditor.Models;

namespace ZeroTrustAuditor.Tests
{
    /// <summary>
    /// The version used to be a literal in six places. These tests exist so the
    /// tool cannot print one version in its banner while stamping another into the
    /// SIEM events it exports.
    /// </summary>
    public class ToolInfoTests
    {
        [Fact]
        public void ShortVersionIsAPrefixOfVersion()
        {
            Assert.StartsWith(ToolInfo.ShortVersion, ToolInfo.Version);
        }

        [Fact]
        public void VersionIsSemver()
        {
            Assert.Matches(@"^\d+\.\d+\.\d+$", ToolInfo.Version);
        }

        [Fact]
        public void ReportsAreStampedWithTheSingleVersionConstant()
        {
            Assert.Equal(ToolInfo.Version, new AuditReport().AuditorVersion);
        }

        [Fact]
        public void VendorIsNotAnUnrelatedThirdParty()
        {
            // The CEF vendor field was hardcoded to "Anthropic". SIEM correlation
            // rules keyed on vendor would have attributed these events to a company
            // with no involvement in the tool.
            Assert.NotEqual("Anthropic", ToolInfo.Vendor);
            Assert.False(string.IsNullOrWhiteSpace(ToolInfo.Vendor));
        }

        [Fact]
        public void CsprojVersionMatchesToolInfo()
        {
            // The csproj cannot reference the constant, so it is the one place that
            // can silently drift. Assert they agree.
            var csproj = FindRepoFile("ZeroTrustAuditor.csproj");
            Assert.True(File.Exists(csproj), $"csproj not found at {csproj}");

            var match = Regex.Match(File.ReadAllText(csproj), @"<Version>([^<]+)</Version>");
            Assert.True(match.Success, "no <Version> element in the csproj");
            Assert.Equal(ToolInfo.Version, match.Groups[1].Value.Trim());
        }

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
