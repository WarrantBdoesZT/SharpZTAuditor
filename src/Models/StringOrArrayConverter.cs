using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroTrustAuditor.Models
{
    /// <summary>
    /// Accepts either a bare string or an array of strings for the same property, so
    /// policy rules can read naturally in both the single and multiple cases:
    ///
    ///   "from": "mgmt"
    ///   "to":   ["server-tier1", "tier0"]
    ///
    /// Always writes an array.
    /// </summary>
    public sealed class StringOrArrayConverter : JsonConverter<List<string>>
    {
        public override List<string> Read(
            ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var result = new List<string>();

            switch (reader.TokenType)
            {
                case JsonTokenType.Null:
                    return result;

                case JsonTokenType.String:
                    var single = reader.GetString();
                    if (!string.IsNullOrWhiteSpace(single)) result.Add(single.Trim());
                    return result;

                case JsonTokenType.StartArray:
                    while (reader.Read())
                    {
                        if (reader.TokenType == JsonTokenType.EndArray) return result;

                        if (reader.TokenType != JsonTokenType.String)
                            throw new JsonException(
                                $"Expected a string inside the array, found {reader.TokenType}.");

                        var value = reader.GetString();
                        if (!string.IsNullOrWhiteSpace(value)) result.Add(value.Trim());
                    }
                    throw new JsonException("Unterminated array.");

                default:
                    throw new JsonException(
                        $"Expected a string or an array of strings, found {reader.TokenType}.");
            }
        }

        public override void Write(
            Utf8JsonWriter writer, List<string> value, JsonSerializerOptions options)
        {
            writer.WriteStartArray();
            foreach (var item in value)
                writer.WriteStringValue(item);
            writer.WriteEndArray();
        }
    }
}
