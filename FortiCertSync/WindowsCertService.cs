using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FortiCertSync;

internal static class WindowsCertService
{
    public static X509Certificate2? FindNewestCertificate(string storePath, string subject, string? issuer = null)
    {
        var (loc, name) = ParseStore(storePath);
        using var store = new X509Store(name, loc);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        var cert = store.Certificates
            .Cast<X509Certificate2>()
            .Where(c => c.HasPrivateKey && SubjectMatches(c, subject))
            .Where(c => issuer is null || IssuerMatches(c, issuer))
            .OrderByDescending(c => c.NotAfter)
            .FirstOrDefault();

        return cert is null ? null : new X509Certificate2(cert); // detached clone
    }

public static (byte[] Pfx, string Password) ExportPkcs12(X509Certificate2 cert)
{
    var pass = Guid.NewGuid().ToString("N");

    using var chain = new X509Chain
    {
        ChainPolicy =
        {
            RevocationMode = X509RevocationMode.NoCheck, // API sync tool: avoid network delays
            RevocationFlag = X509RevocationFlag.ExcludeRoot,
            VerificationFlags = X509VerificationFlags.NoFlag
        }
    };

    // Build using machine/user stores (Windows will help find intermediates if present)
    chain.Build(cert);

    // Create a PFX that contains: leaf + intermediates (+ optionally root)
    var export = new X509Certificate2Collection
    {
        cert
    };

    foreach (var element in chain.ChainElements)
    {
        var c = element.Certificate;

        // Skip duplicating the leaf
        if (c.Thumbprint == cert.Thumbprint) continue;

        // Usually: include intermediates, exclude root (Forti typically wants root in CA store separately)
        if (c.Subject == c.Issuer) continue; // root

        export.Add(c);
    }

    var bytes = export.Export(X509ContentType.Pkcs12, pass)!; // Ensure non-null
    return (bytes, pass);
}

    public static string NormalizeSubject(string s) =>
        new([.. s.ToLowerInvariant().Where(ch => char.IsLetterOrDigit(ch) || ch == '.' || ch == '*' || ch == '_')]);

    public static bool SubjectEqual(string fortiSubject, string desired) =>
        fortiSubject.Contains(desired, StringComparison.OrdinalIgnoreCase);

    static (StoreLocation, StoreName) ParseStore(string sp)
    {
        var parts = sp.Split('\\', 2, StringSplitOptions.TrimEntries);
        var loc = parts[0].Equals("LocalMachine", StringComparison.OrdinalIgnoreCase)
            ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
        var name = parts.Length > 1 ? parts[1] : "My";
        return (loc, Enum.TryParse<StoreName>(name, true, out var sn) ? sn : StoreName.My);
    }

    static bool SubjectMatches(X509Certificate2 c, string subject)
    {
        if (c.Subject.Contains(subject, StringComparison.OrdinalIgnoreCase)) return true;
        try
        {
            var ext = c.Extensions["2.5.29.17"]; // SAN
            if (ext != null)
            {
                var formatted = new AsnEncodedData(ext.Oid!, ext.RawData).Format(multiLine: false);
                return formatted.Contains(subject, StringComparison.OrdinalIgnoreCase);
            }
        }
        catch { }
        return false;
    }
    private static bool IssuerMatches(X509Certificate2 c, string filter)
    {
        var dn = c.IssuerName?.Name ?? string.Empty;
        string? cn = GetDnPart(dn, "CN");
        string? o = GetDnPart(dn, "O");
        return (cn?.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)
            || (o?.IndexOf(filter, StringComparison.OrdinalIgnoreCase)  >= 0);
    }

    private static string? GetDnPart(string dn, string key)
    {
        foreach (var part in dn.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            if (part.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                return part[(key.Length + 1)..];
        return null;
    }

}
