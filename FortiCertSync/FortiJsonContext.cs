using System.Text.Json.Serialization;

namespace FortiCertSync;

[JsonSourceGenerationOptions(WriteIndented = false)]

[JsonSerializable(typeof(SslCertPatch))]
[JsonSerializable(typeof(ServerCertPatch))]
internal partial class FortiJsonContext : JsonSerializerContext { }

