using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FortiCertSync;

internal static class WindowsCertService
{
    public static X509Certificate2? FindNewestCertificate(string storePath, string subject)
    {
        var (loc, name) = ParseStore(storePath);
        using var store = new X509Store(name, loc);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        return store.Certificates
            .Cast<X509Certificate2>()
            .Where(c => c.HasPrivateKey && SubjectMatches(c, subject))
            .OrderByDescending(c => c.NotAfter)
            .FirstOrDefault();
    }

    public static (byte[] Pfx, string Password) ExportPkcs12(X509Certificate2 cert)
    {
        var pass = Guid.NewGuid().ToString("N");
        var bytes = cert.Export(X509ContentType.Pkcs12, pass);
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
}
