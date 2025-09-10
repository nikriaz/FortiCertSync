using FortiCertSync;
using System.Globalization;
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
    var rawVdom = ini["fortigate"].Get("vdom"); var vdom = string.IsNullOrWhiteSpace(rawVdom) ? null : rawVdom;
    var certSections = ini.Sections
            .Where(s => s.Name.StartsWith("cert:", StringComparison.OrdinalIgnoreCase))
            .Where(s => !string.IsNullOrWhiteSpace(s.Name[5..]))
            .ToArray();
    if (certSections.Length < 1) throw new Exception("Missing certificate sections");

    const string defaultStore = "LocalMachine\\My";
    foreach (var sect in certSections)
    {
        string? subject = null;
        try
        {
            var slotName = sect.Name[5..]; // after "cert:"
            var certName = GetCertName(slotName);
            var store = sect.Get("store", defaultStore) ?? defaultStore;
            subject = sect.Get("subject");
            var issuer = sect.Get("issuer");

            // 1) Find current cert in Forti inventory
            var fortiCerts = await forti.ListLocalCertsAsync(vdom);
            var fortiForName = fortiCerts
                    .Where(c =>
                        string.Equals(c.Name, slotName, StringComparison.OrdinalIgnoreCase) ||
                        MatchesSlotWithDate(c.Name, slotName))
                    .ToList();
            var newestForti = fortiForName.OrderByDescending(c => c.ValidToUtc).FirstOrDefault();
            if (newestForti is null) { Logger.Info($"[{subject}] Not found in Fortigate. Please import it first manually; skipping."); continue; }
            subject ??= newestForti.Subject;
            issuer ??= !string.IsNullOrWhiteSpace(newestForti.IssuerO) ? newestForti.IssuerO : issuer;

            // 2) Find newest Windows cert for subject
            var newestWindows = WindowsCertService.FindNewestCertificate(store, subject, issuer);
            if (newestWindows is null) { Logger.Info($"[{subject}] No matching cert in Windows store."); continue; }
            var winNotAfterUtc = newestWindows.NotAfter.ToUniversalTime();
            if (DateTime.UtcNow > winNotAfterUtc) { Logger.Warn($"[{subject}] Newest cert expired; skipping."); continue; }
            Logger.Info($"[{subject}] Windows newest: {winNotAfterUtc:yyyy-MM-dd} / {newestWindows.Thumbprint}");

            var forceUpdate = false; //for debugging only
            var needImport = newestForti.ValidToUtc < winNotAfterUtc || forceUpdate;
            Logger.Info($"[{subject}] Forti newest: {newestForti.ValidToUtc:yyyy-MM-dd}.Import? {needImport}");

            if (needImport)
            {
                // 3) Import PFX
                var newSlotName = $"{certName}_{DateTime.Now.Date:ddMMyyyy}";
                var (pfxBytes, pfxPass) = WindowsCertService.ExportPkcs12(newestWindows);
                await forti.ImportLocalCertAsync(vdom, newSlotName, pfxPass, pfxBytes);
                Logger.Info($"[{subject}] Imported into slot '{newSlotName}'");

                // 4) Rebound
                var oldSlotName = newestForti.Name;
                int edits = await forti.RebindAutoAsync(vdom, oldSlotName, newSlotName);

                if (edits > 0)
                {
                    // 5) Delete old cert if rebound was successfull and no references
                    Logger.Info($"[{subject}] Rebound {edits} object(s) from '{oldSlotName}' → '{newSlotName}'");
                    var oldRefsCount = await forti.FindUsageCountAsync(vdom, oldSlotName);
                    if (oldRefsCount == 0) await forti.DeleteLocalCertAsync(vdom, oldSlotName);
                    else Logger.Info($"Cert '{oldSlotName}' still has '{oldRefsCount}' references and was kept.");
                    
                } else
                {
                    Logger.Info($"Found no references for cert '{oldSlotName}' therefore it was preserved.");
                }
            }
        }
        catch (Exception ex)
        {
            Logger.Error($"[{subject ?? "unknown"}] {ex.Message}");
        }
    }
}
catch (Exception ex)
{
    Logger.Error("FATAL " + ex.Message);
}

static bool TrySplitNameWithDate(string slotName, out string baseName, out DateTime date)
{
    baseName = slotName;
    date = default;

    var idx = slotName.LastIndexOf('_');
    if (idx <= 0 || idx == slotName.Length - 1)
        return false;

    var suffix = slotName.AsSpan(idx + 1);
    if (suffix.Length != 8) return false;

    if (DateTime.TryParseExact(suffix, "ddMMyyyy",
            CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
    {
        baseName = slotName[..idx];
        date = d;
        return true;
    }

    return false;
}
static bool MatchesSlotWithDate(string name, string slot) =>
    name.StartsWith(slot + "_", StringComparison.OrdinalIgnoreCase) &&
    TrySplitNameWithDate(name, out var baseName, out var date) &&
    baseName.Equals(slot, StringComparison.OrdinalIgnoreCase);

static string GetCertName(string slotName) =>
    TrySplitNameWithDate(slotName, out var baseName, out _) ? baseName : slotName;

