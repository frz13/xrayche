using System.Text.Json;
using XrayHub.Models;

namespace XrayHub.Services;

/// <summary>
/// Stores unresolved detections under %AppData% so closing or crashing XrayHub
/// cannot silently discard a conflict prompt.
/// </summary>
public sealed class ProxyConflictStateStore
{
    private readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "XrayHub", "proxy-conflict-state.json");

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly object _sync = new();

    public ProxyConflictState Load()
    {
        lock (_sync)
        {
            try
            {
                if (!File.Exists(_path)) return new ProxyConflictState();
                return JsonSerializer.Deserialize<ProxyConflictState>(File.ReadAllText(_path), JsonOptions)
                    ?? new ProxyConflictState();
            }
            catch { return new ProxyConflictState(); }
        }
    }

    public void Save(ProxyConflictState state)
    {
        lock (_sync)
        {
            var directory = Path.GetDirectoryName(_path)!;
            Directory.CreateDirectory(directory);
            var temp = _path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(state, JsonOptions));
            File.Move(temp, _path, overwrite: true);
        }
    }

    public void SavePending(WindowsProxySnapshot snapshot, string reason)
    {
        var current = Load();
        var fingerprint = snapshot.Fingerprint();
        if (string.Equals(current.DismissedFingerprint, fingerprint, StringComparison.OrdinalIgnoreCase))
            return;

        current.Pending = true;
        current.Fingerprint = fingerprint;
        current.ProxyServer = snapshot.ProxyServer ?? string.Empty;
        current.AutoConfigUrl = snapshot.AutoConfigUrl ?? string.Empty;
        current.ProxyEnabled = snapshot.ProxyEnable == 1;
        current.AutoDetect = snapshot.AutoDetect == 1;
        current.DetectedAtUtc = DateTimeOffset.UtcNow;
        current.DetectionReason = reason;
        Save(current);
    }

    public void Dismiss(string fingerprint)
    {
        var current = Load();
        current.Pending = false;
        current.DismissedFingerprint = fingerprint;
        Save(current);
    }

    public void ClearPending()
    {
        var current = Load();
        current.Pending = false;
        current.Fingerprint = string.Empty;
        current.ProxyServer = string.Empty;
        current.AutoConfigUrl = string.Empty;
        current.ProxyEnabled = false;
        current.AutoDetect = false;
        current.DetectedAtUtc = default;
        current.DetectionReason = string.Empty;
        Save(current);
    }
}
