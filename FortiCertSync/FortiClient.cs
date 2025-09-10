using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

#pragma warning disable IDE0079
#pragma warning disable CA1416

namespace FortiCertSync;

internal sealed class FortiClient
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    private FortiClient(HttpClient h, string baseUrl)
    { _http = h; _baseUrl = baseUrl; }

    internal sealed record FortiCert(string Name, string Subject, DateTime ValidToUtc, string IssuerCn, string IssuerO);
    internal sealed record UsageRef(string Path, string Name, string Mkey, string Attribute, bool IsTable);

    public static async Task<FortiClient> CreateAsync(Ini.Section forti, string iniPath)
    {
        var baseUrl = forti.Get("baseUrl")?.TrimEnd('/') ?? throw new Exception("fortigate.baseUrl required");
        var tokenRaw = forti.Get("apiKey") ?? throw new Exception("fortigate.apiKey required");

        var token = tokenRaw.StartsWith("enc:", StringComparison.OrdinalIgnoreCase)
            ? Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(tokenRaw[4..]), null, DataProtectionScope.CurrentUser))
            : tokenRaw;

        var h = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        h.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var ping = await h.GetAsync($"{baseUrl}/api/v2/monitor/system/status");
        if (!ping.IsSuccessStatusCode) throw new Exception($"FortiGate auth failed: {(int)ping.StatusCode}");

        if (!tokenRaw.StartsWith("enc:", StringComparison.OrdinalIgnoreCase))
        {
            var enc = "enc:" + Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(token), null, DataProtectionScope.CurrentUser));
            Ini.UpdateKeyInPlace(iniPath, "fortigate", "apiKey", enc);
            Logger.Info("API key encrypted in INI (DPAPI CurrentUser).");
        }

        return new FortiClient(h, baseUrl);
    }

    public async Task<List<FortiCert>> ListLocalCertsAsync(string? vdom)
    {
        var json = await _http.GetStringAsync(Url("/api/v2/cmdb/vpn.certificate/local", null, vdom));
        using var doc = JsonDocument.Parse(json);

        var list = new List<FortiCert>();
        if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
            return list;

        foreach (var el in results.EnumerateArray())
        {
            var name = el.TryGetProperty("name", out var n) ? n.GetString() : null;
            if (string.IsNullOrWhiteSpace(name)) continue;

            var cert = await GetLocalCertAsync(name!, vdom);
            if (cert != null) list.Add(cert);
        }
        return list;
    }

    public async Task<FortiCert?> GetLocalCertAsync(string name, string? vdom)
    {
        try
        {
            var url = Url($"/api/v2/cmdb/vpn.certificate/local/{Uri.EscapeDataString(name)}", null, vdom);
            var resp = await _http.GetAsync(url);
            if (!resp.IsSuccessStatusCode)
            {
                Logger.Warn($"Get cert meta skipped for '{name}': {(int)resp.StatusCode} {resp.ReasonPhrase}");
                return null;
            }

            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            if (!doc.RootElement.TryGetProperty("results", out var results))
            {
                Logger.Warn($"Get cert meta skipped for '{name}': missing 'results'");
                return null;
            }

            var obj = results.ValueKind switch
            {
                JsonValueKind.Object => results,
                JsonValueKind.Array when results.GetArrayLength() > 0 => results[0],
                _ => default
            };

            if (obj.ValueKind == JsonValueKind.Undefined)
            {
                Logger.Warn($"Get cert meta skipped for '{name}': unexpected 'results' shape");
                return null;
            }

            if (!obj.TryGetProperty("certificate", out var certProp) || certProp.ValueKind != JsonValueKind.String)
            {
                Logger.Warn($"Get cert meta skipped for '{name}': 'certificate' field missing");
                return null;
            }

            var pem = certProp.GetString();
            const string begin = "-----BEGIN CERTIFICATE-----";
            const string end = "-----END CERTIFICATE-----";
            var i = pem!.IndexOf(begin, StringComparison.Ordinal);
            var j = pem.IndexOf(end, StringComparison.Ordinal);
            if (i < 0 || j < 0 || j <= i)
            {
                if (!name.StartsWith("Fortinet_", StringComparison.OrdinalIgnoreCase))
                    Logger.Warn($"Get cert meta skipped for '{name}': invalid PEM");
                return null;
            }

            var b64 = pem[(i + begin.Length)..j].Replace("\r", "").Replace("\n", "").Trim();
            using var x509 = new X509Certificate2(Convert.FromBase64String(b64));
            var cn = x509.GetNameInfo(X509NameType.DnsName, false);
            if (string.IsNullOrWhiteSpace(cn))
                cn = x509.GetNameInfo(X509NameType.SimpleName, false);

            var validToUtc = x509.NotAfter.ToUniversalTime();

            var issuerCn = string.Empty;
            var issuerO = string.Empty;
            var issuer = new X500DistinguishedName(x509.Issuer);
            var parts = issuer.Name.Split(',', StringSplitOptions.TrimEntries);

            foreach (var part in parts)
            {
                if (part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    issuerCn = part[3..];
                else if (part.StartsWith("O=", StringComparison.OrdinalIgnoreCase))
                    issuerO = part[2..];
            }

            return new FortiCert(name, cn ?? x509.Subject, validToUtc, issuerCn, issuerO);
        }
        catch (Exception ex)
        {
            Logger.Warn($"Get cert meta skipped for '{name}': {ex.Message}");
            return null;
        }
    }

    public async Task ImportLocalCertAsync(string? vdom, string mkey, string pfxPass, byte[] pfxBytes)
    {
        using var x = new X509Certificate2(pfxBytes, pfxPass, X509KeyStorageFlags.Exportable);

        var certDer = x.Export(X509ContentType.Cert);
        byte[] keyDer;
        if (x.GetRSAPrivateKey() is RSA rsa) { keyDer = rsa.ExportRSAPrivateKey(); }
        else if (x.GetECDsaPrivateKey() is ECDsa ec) { keyDer = ec.ExportECPrivateKey(); }
        else throw new Exception("Unsupported private key type; RSA or ECDSA required.");

        using var ms = new MemoryStream();
        using (var jw = new Utf8JsonWriter(ms))
        {
            jw.WriteStartObject();
            jw.WriteString("type", "regular");
            jw.WriteString("certname", mkey);
            jw.WriteString("scope", string.IsNullOrEmpty(vdom) || vdom.Equals("root", StringComparison.OrdinalIgnoreCase) ? "global" : "vdom");
            jw.WriteString("file_content", Convert.ToBase64String(certDer));
            jw.WriteString("key_file_content", Convert.ToBase64String(keyDer));
            jw.WriteEndObject();
        }
        using var content = new ByteArrayContent(ms.ToArray());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        var url = Url("/api/v2/monitor/vpn-certificate/local/import", null, vdom);
        var resp = await _http.PostAsync(url, content);
        if (!resp.IsSuccessStatusCode)
            throw new Exception($"Import cert '{mkey}' failed: {(int)resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
    }

    public async Task DeleteLocalCertAsync(string? vdom, string name)
    {
        var url = Url($"/api/v2/cmdb/vpn.certificate/local/{Uri.EscapeDataString(name)}", null, vdom);
        var resp = await _http.DeleteAsync(url);
        if (!resp.IsSuccessStatusCode) throw new Exception($"Delete cert {name} failed: {(int)resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
        Logger.Info($"Cert '{name}' has no references and was deleted.");
    }

    private string Url(string path, string? query = null, string? vdom = null)
    {
        var hasQ = !string.IsNullOrEmpty(query);
        var sb = new StringBuilder(_baseUrl.Length + path.Length + 32);
        sb.Append(_baseUrl).Append(path);
        if (hasQ) sb.Append('?').Append(query);
        if (!string.IsNullOrWhiteSpace(vdom))
            sb.Append(hasQ ? '&' : '?').Append("vdom=").Append(Uri.EscapeDataString(vdom));
        return sb.ToString();
    }

    public async Task<int> RebindAutoAsync(string? vdom, string oldSlotName, string newSlotName)
    {
        var refs = await FindUsageAsync(vdom, oldSlotName);
        if (refs.Count == 0) return 0;

        var edits = 0;
        foreach (var r in refs)
        {
            try
            {
                var cmdbUrl = Url($"/api/v2/cmdb/{r.Path}/{r.Name}/{Uri.EscapeDataString(r.Mkey)}/", null, vdom);
                edits += await PatchOneAsync(cmdbUrl, r.Attribute, r.Mkey, oldSlotName, newSlotName, r.IsTable) ? 1 : 0;
            }
            catch (Exception ex)
            {
                Logger.Error($"[{newSlotName}] Rebound failed: {ex.Message}");
            }
        }
        return edits;
    }

    public async Task<int> FindUsageCountAsync(string? vdom, string mkey)
    {
        var list = await FindUsageAsync(vdom, mkey);
        return list.Count;
    }

    private async Task<List<UsageRef>> FindUsageAsync(string? vdom, string mkey)
    {
        var query = $"q_path=vpn.certificate&q_name=local&mkey={Uri.EscapeDataString(mkey)}";
        var url = Url("/api/v2/monitor/system/object/usage", query, vdom);

        using var resp = await _http.GetAsync(url);
        if (!resp.IsSuccessStatusCode)
        {
            Logger.Error($"Failed to enumerate usage references for {mkey}: {(int)resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
            return [];
        }

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var list = new List<UsageRef>();

        if (!doc.RootElement.TryGetProperty("results", out var results)) return list;
        if (!results.TryGetProperty("currently_using", out var usingArr) || usingArr.ValueKind != JsonValueKind.Array) return list;

        foreach (var it in usingArr.EnumerateArray())
        {
            var path = it.TryGetProperty("path", out var p) ? p.GetString() : null;       // e.g. "firewall"
            var name = it.TryGetProperty("name", out var n) ? n.GetString() : null;       // e.g. "ssl-ssh-profile" (location)
            var refMk = it.TryGetProperty("mkey", out var k) ? k.GetString() : null;       // e.g. "multi-cert"
            string attr = (it.TryGetProperty("attribute", out var a) ? a.GetString() : null) ?? "ssl-certificate";
            var isTable = string.Equals((it.TryGetProperty("table_type", out var tt) ? tt.GetString() : null), "table", StringComparison.OrdinalIgnoreCase);

            if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(refMk))
                continue;

            list.Add(new UsageRef(path!, name!, refMk!, attr, isTable));
        }

        return list;
    }

    private async Task<bool> PatchOneAsync(string url, string fieldName, string objectMkey, string oldName, string newName, bool isTable)
    {
        if (string.IsNullOrWhiteSpace(fieldName) || string.IsNullOrWhiteSpace(newName)) return false;

        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            if (!string.IsNullOrWhiteSpace(objectMkey)) w.WriteString("name", objectMkey);

            if (isTable)
            {
                var existing = await GetExistingListAsync(url, fieldName);
                existing.RemoveAll(s =>
                    string.Equals(s, oldName, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(s, newName, StringComparison.OrdinalIgnoreCase));
                existing.Add(newName);

                w.WritePropertyName(fieldName);
                w.WriteStartArray();
                foreach (var n in existing)
                {
                    w.WriteStartObject();
                    w.WriteString("name", n);
                    w.WriteEndObject();
                }
                w.WriteEndArray();
                w.WriteString($"{fieldName}-mode", "replace");
            }
            else
            {
                w.WritePropertyName(fieldName);
                w.WriteStringValue(newName);
            }

            w.WriteEndObject();
            w.Flush();
        }

        var bytes = ms.ToArray();
        using var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Headers.ContentLength = bytes.Length;

        using var req = new HttpRequestMessage(HttpMethod.Put, url) { Content = content };
        using var resp = await _http.SendAsync(req); // single PUT

        var success = resp.IsSuccessStatusCode;
        if (!success) throw new Exception($"Rebind {fieldName}in {url} failed: {(int)resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
        Logger.Info($"Rebound '{fieldName}' in {url} → {newName}");
        return success;
    }

    private async Task<List<string>> GetExistingListAsync(string url, string fieldName)
    {
        using var resp = await _http.GetAsync(url);
        if (!resp.IsSuccessStatusCode)
            throw new Exception($"Failed to enumerate existed {fieldName} in {url}: {(int)resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        if (!root.TryGetProperty("results", out var results))
            throw new Exception($"Failed to enumerate existed {fieldName} in {url}: No Root");

        var obj = results.ValueKind == JsonValueKind.Array
            ? (results.GetArrayLength() > 0 ? results[0] : default)
            : results;

        if (obj.ValueKind != JsonValueKind.Object) throw new Exception($"Failed to enumerate existed {fieldName} in {url}: Incorrect JSON");

        var list = new List<string>();
        if (obj.TryGetProperty(fieldName, out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in arr.EnumerateArray())
            {
                var nm = item.TryGetProperty("name", out var n) ? n.GetString() : null;
                if (!string.IsNullOrWhiteSpace(nm)) list.Add(nm!);
            }
        }

        return list;
    }
}
