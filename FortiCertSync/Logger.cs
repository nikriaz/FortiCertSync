using System.Text;
using System.Reflection;

namespace FortiCertSync;

internal static class Logger
{
    static string _file = "";
    static readonly object _lock = new();

    public static void Init(string baseName)
    {
        // always use <assemblyname>.log
        _file = $"{baseName}.log";
    }

    static void Write(string level, string msg)
    {
        lock (_lock)
        {
            try
            {
                var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} | {level} | {msg}";
                File.AppendAllText(_file, line + Environment.NewLine, Encoding.UTF8);
            }
            catch
            {
                // fallback: create new file with unique suffix if append failed
                var fallback = $"{Path.GetFileNameWithoutExtension(_file)}_{DateTime.Now:yyyyMMdd_HHmmss}.log";
                File.AppendAllText(fallback, msg + Environment.NewLine, Encoding.UTF8);
                _file = fallback;
            }
        }
    }

    public static void Info(string m) => Write("INFO", m);
    public static void Warn(string m) => Write("WARN", m);
    public static void Error(string m) => Write("ERROR", m);
}
