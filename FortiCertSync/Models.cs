using System.Text.Json.Serialization;

namespace FortiCertSync;

internal sealed class SslCertPatch
{
    [JsonPropertyName("ssl-certificate")]
    public string? SslCertificate { get; init; }
}
internal sealed class ServerCertPatch
{
    [JsonPropertyName("server-cert")]
    public string? ServerCert { get; init; }
}