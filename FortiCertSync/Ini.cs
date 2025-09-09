using System.Text;

namespace FortiCertSync;

internal sealed class Ini
{
    public sealed record Section(string Name, Dictionary<string, string> Pairs)
    {
        public string? Get(string key, string? def = null) =>
            Pairs.TryGetValue(key, out var v) ? v : def;
        public override string ToString() => $"[{Name}]";
    }

    public Dictionary<string, Section> SectionsDict = new(StringComparer.OrdinalIgnoreCase);
    public IEnumerable<Section> Sections => SectionsDict.Values;
    public Section this[string name] => SectionsDict[name];

    public static Ini Load(string path)
    {
        var ini = new Ini();
        Section? cur = null;

        foreach (var raw in File.ReadAllLines(path, Encoding.UTF8))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('#')) continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                var name = line[1..^1].Trim();
                cur = new Section(name, new(StringComparer.OrdinalIgnoreCase));
                ini.SectionsDict[name] = cur;
            }
            else if (cur != null)
            {
                var idx = line.IndexOf('=');
                if (idx > 0)
                {
                    var k = line[..idx].Trim();
                    var v = line[(idx + 1)..].Trim();
                    cur.Pairs[k] = v;
                }
            }
        }
        return ini;
    }

    public static void UpdateKeyInPlace(string path, string section, string key, string value)
    {
        var lines = File.ReadAllLines(path, Encoding.UTF8).ToList();
        int sIdx = -1, eIdx = lines.Count;

        for (int i = 0; i < lines.Count; i++)
        {
            var l = lines[i].Trim();
            if (l.StartsWith('[') && l.EndsWith(']'))
            {
                var name = l[1..^1].Trim();
                if (sIdx >= 0) { eIdx = i; break; }
                if (name.Equals(section, StringComparison.OrdinalIgnoreCase)) sIdx = i;
            }
        }

        if (sIdx < 0)
        {
            lines.Add($"[{section}]");
            lines.Add($"{key} = {value}");
        }
        else
        {
            bool wrote = false;
            for (int i = sIdx + 1; i < eIdx; i++)
            {
                var line = lines[i];
                var idx = line.IndexOf('=');
                if (idx > 0)
                {
                    var k = line[..idx].Trim();
                    if (k.Equals(key, StringComparison.OrdinalIgnoreCase))
                    { lines[i] = $"{key} = {value}"; wrote = true; break; }
                }
            }
            if (!wrote) lines.Insert(eIdx, $"{key} = {value}");
        }

        File.WriteAllLines(path, lines, Encoding.UTF8);
    }
}
