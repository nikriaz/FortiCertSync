using FortiCertSync;
using System.Text;

try
{
    // Match INI file name with executable name
    var exePath = Environment.ProcessPath ?? AppContext.BaseDirectory;
    var exeName = Path.GetFileNameWithoutExtension(exePath);
    var iniPath = args.Length > 0
        ? args[0]
        : Path.Combine(AppContext.BaseDirectory, exeName + ".ini");

    // Add sample INI if missing
    if (!File.Exists(iniPath))
    {
        using var s = typeof(Program).Assembly.GetManifestResourceStream("FortiCertSync.SampleIni")??throw new InvalidOperationException("Embedded sample INI not found.");
        using var r = new StreamReader(s, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        File.WriteAllText(iniPath, r.ReadToEnd(), Encoding.UTF8);
    }

    Logger.Init(exeName);
    var ini = Ini.Load(iniPath);

    var forti = await FortiClient.CreateAsync(ini["fortigate"], iniPath);
    var vdom = ini["fortigate"].Get("vdom"); // null if absent or empty

    if (!ini.SectionsDict.TryGetValue("certificates", out var certsSect))
        throw new Exception("Missing [certificates] section");
    var storePath = certsSect.Get("store", "LocalMachine\\My") ?? "LocalMachine\\My";
    var subjects = certsSect.Pairs
                .Where(kv => kv.Key.Equals("subject", StringComparison.OrdinalIgnoreCase))
                .Select(kv => kv.Value)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

    foreach (var subject in subjects)
    {
        try
        {
            // 1) Find newest Windows cert for subject
            var newest = WindowsCertService.FindNewestCertificate(storePath, subject);
            if (newest is null) { Logger.Info($"[{subject}] No matching cert in Windows store."); continue; }
            var winNotAfterUtc = newest.NotAfter.ToUniversalTime();
            if (DateTime.UtcNow > winNotAfterUtc) { Logger.Warn($"[{subject}] Newest cert expired; skipping."); continue; }
            Logger.Info($"[{subject}] Windows newest: {winNotAfterUtc:yyyy-MM-dd} / {newest.Thumbprint}");

            // 2) Compare with Forti inventory
            var fortiCerts = await forti.ListLocalCertsAsync(vdom);
            var fortiForSubject = fortiCerts.Where(c => WindowsCertService.SubjectEqual(c.Subject, subject)).ToList();
            var currentForti = fortiForSubject.OrderByDescending(c => c.ValidToUtc).FirstOrDefault();
            if (currentForti is null) { Logger.Info($"[{subject}] Not found in Fortigate. Please import it first manually; skipping."); continue; }

            var forceUpdate = false; //for debugging only
            var needImport = currentForti.ValidToUtc < winNotAfterUtc || forceUpdate;
            Logger.Info($"[{subject}] Forti newest: {(currentForti == null ? "none" : currentForti.ValidToUtc.ToString("yyyy-MM-dd"))}. Import? {needImport}");

            var slotName = currentForti?.Name;
            if (needImport && !string.IsNullOrEmpty(slotName))
            {
                // 3) Import PFX
                var (pfxBytes, pfxPass) = WindowsCertService.ExportPkcs12(newest);
                await forti.ImportPkcs12Async(vdom, slotName, pfxPass, pfxBytes, replace: true);
                Logger.Info($"[{subject}] Imported into slot '{slotName}'");
            }
        }
        catch (Exception ex)
        {
            Logger.Error($"[{subject}] {ex.Message}");
        }
    }
}
catch (Exception ex)
{
    Logger.Error("FATAL " + ex.Message);
}
