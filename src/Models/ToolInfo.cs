namespace ZeroTrustAuditor.Models
{
    /// <summary>
    /// Single source of truth for the tool's identity.
    ///
    /// The version previously appeared as a literal in six places -- the csproj, the
    /// console banner, two spots in the HTML report, the CEF vendor string and the
    /// report model -- which is exactly how a tool ends up printing one version in
    /// its banner and stamping another into the SIEM events it exports.
    ///
    /// Keep <c>Version</c> in step with the <c>&lt;Version&gt;</c> element in
    /// ZeroTrustAuditor.csproj; that one cannot reference this constant.
    /// </summary>
    public static class ToolInfo
    {
        public const string Version = "3.0.0";

        /// <summary>Short form for banners and report headings.</summary>
        public const string ShortVersion = "3.0";

        public const string Name = "ZeroTrustAuditor";

        /// <summary>
        /// CEF vendor field. Previously hardcoded to "Anthropic", which named the
        /// wrong party entirely -- SIEM rules keyed on vendor would have attributed
        /// these events to a company with no involvement in the tool.
        /// </summary>
        public const string Vendor = "WarrantBdoesZT";

        public const string Tagline =
            "Internal network segmentation assessment from an assumed-breach posture";
    }
}
