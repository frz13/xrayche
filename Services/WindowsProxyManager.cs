using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Text.Json;
using XrayHub.Models;

namespace XrayHub.Services;

/// <summary>Changes only the current user's proxy settings and restores the exact saved values.</summary>
public sealed class WindowsProxyManager
{
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private static readonly string[] SavedNames = ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"];
    private readonly string _backupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "XrayHub", "system-proxy-backup.json");
    private readonly string _externalRepairBackupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "XrayHub", "external-proxy-repair-backup.json");

    /// <summary>Reads the current-user WinINET proxy values without changing them.</summary>
    public WindowsProxySnapshot ReadCurrentSnapshot()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: false)
            ?? throw new InvalidOperationException("Не удалось прочитать системные настройки прокси Windows.");
        return new WindowsProxySnapshot
        {
            ProxyEnable = ReadDword(key, "ProxyEnable"),
            ProxyServer = key.GetValue("ProxyServer") as string,
            ProxyOverride = key.GetValue("ProxyOverride") as string,
            AutoConfigUrl = key.GetValue("AutoConfigURL") as string,
            AutoDetect = ReadDword(key, "AutoDetect")
        };
    }

    /// <summary>
    /// A configured proxy is considered external unless it exactly matches the local
    /// HTTP proxy XrayHub installs. PAC/WPAD are treated as external configuration too.
    /// Network failure is checked separately before any prompt is shown.
    /// </summary>
    public static bool IsExternalProxy(WindowsProxySnapshot snapshot, int xrayHubHttpPort)
    {
        if (!snapshot.IsPotentiallyActive) return false;
        var hasPacOrWpad = !string.IsNullOrWhiteSpace(snapshot.AutoConfigUrl) || snapshot.AutoDetect == 1;
        if (hasPacOrWpad) return true;
        if (snapshot.ProxyEnable != 1) return false;

        var configured = NormalizeProxyServer(snapshot.ProxyServer);
        var expectedA = NormalizeProxyServer($"http=127.0.0.1:{xrayHubHttpPort};https=127.0.0.1:{xrayHubHttpPort}");
        var expectedB = NormalizeProxyServer($"127.0.0.1:{xrayHubHttpPort}");
        var expectedC = NormalizeProxyServer($"http=localhost:{xrayHubHttpPort};https=localhost:{xrayHubHttpPort}");
        var expectedD = NormalizeProxyServer($"localhost:{xrayHubHttpPort}");
        return configured != expectedA && configured != expectedB && configured != expectedC && configured != expectedD;
    }

    /// <summary>
    /// Persists a rollback snapshot, then disables only WinINET proxy/PAC/WPAD switches.
    /// ProxyServer and ProxyOverride are preserved, not deleted.
    /// </summary>
    public WindowsProxySnapshot BeginExternalProxyRepair()
    {
        var snapshot = ReadCurrentSnapshot();
        var directory = Path.GetDirectoryName(_externalRepairBackupPath)!;
        Directory.CreateDirectory(directory);
        var temp = _externalRepairBackupPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, _externalRepairBackupPath, overwrite: true);

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
                ?? throw new InvalidOperationException("Не удалось открыть настройки системного прокси Windows для исправления.");
            key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            key.SetValue("AutoConfigURL", string.Empty, RegistryValueKind.String);
            key.SetValue("AutoDetect", 0, RegistryValueKind.DWord);
            NotifySettingsChanged();
            return snapshot;
        }
        catch
        {
            try { RestoreSnapshot(snapshot); } catch { }
            try { File.Delete(_externalRepairBackupPath); } catch { }
            throw;
        }
    }

    /// <summary>Commits a successful repair so a later XrayHub disconnect won't restore the conflicting proxy.</summary>
    public void CompleteExternalProxyRepair()
    {
        if (File.Exists(_backupPath))
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: false)
                ?? throw new InvalidOperationException("Не удалось сохранить исправленные настройки системного прокси.");
            SaveOriginalState(key);
        }
        if (File.Exists(_externalRepairBackupPath)) File.Delete(_externalRepairBackupPath);
    }

    /// <summary>Rolls back a failed repair using the exact registry state captured before changing it.</summary>
    public void RollbackExternalProxyRepair()
    {
        if (!File.Exists(_externalRepairBackupPath)) return;
        WindowsProxySnapshot? snapshot;
        try
        {
            snapshot = JsonSerializer.Deserialize<WindowsProxySnapshot>(File.ReadAllText(_externalRepairBackupPath));
        }
        catch (Exception ex)
        {
            throw new InvalidDataException("Не удалось прочитать резервную копию постороннего прокси. Настройки не изменены.", ex);
        }
        if (snapshot is null) throw new InvalidDataException("Резервная копия постороннего прокси пуста. Настройки не изменены.");
        RestoreSnapshot(snapshot);
        File.Delete(_externalRepairBackupPath);
    }

    /// <summary>Restores a repair interrupted by an unexpected process exit.</summary>
    public void RecoverInterruptedExternalProxyRepair() => RollbackExternalProxyRepair();

    private static int? ReadDword(RegistryKey key, string name)
    {
        var value = key.GetValue(name);
        if (value is null) return null;
        try { return Convert.ToInt32(value); } catch { return null; }
    }

    private static string NormalizeProxyServer(string? value) =>
        string.Concat((value ?? string.Empty).Where(c => !char.IsWhiteSpace(c))).ToLowerInvariant();

    private static void RestoreSnapshot(WindowsProxySnapshot snapshot)
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
            ?? throw new InvalidOperationException("Не удалось открыть настройки прокси Windows для отката.");
        RestoreDword(key, "ProxyEnable", snapshot.ProxyEnable);
        RestoreString(key, "ProxyServer", snapshot.ProxyServer);
        RestoreString(key, "ProxyOverride", snapshot.ProxyOverride);
        RestoreString(key, "AutoConfigURL", snapshot.AutoConfigUrl);
        RestoreDword(key, "AutoDetect", snapshot.AutoDetect);
        NotifySettingsChanged();
    }

    private static void RestoreDword(RegistryKey key, string name, int? value)
    {
        if (value.HasValue) key.SetValue(name, value.Value, RegistryValueKind.DWord);
        else key.DeleteValue(name, throwOnMissingValue: false);
    }

    private static void RestoreString(RegistryKey key, string name, string? value)
    {
        if (value is not null) key.SetValue(name, value, RegistryValueKind.String);
        else key.DeleteValue(name, throwOnMissingValue: false);
    }

    public void Enable(string host, int port)
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
            ?? throw new InvalidOperationException("Не удалось открыть настройки системного прокси Windows.");

        // A leftover backup means the previous run may have ended unexpectedly.
        // Validate it before changing anything; never overwrite a possibly important original state.
        if (File.Exists(_backupPath))
            _ = ReadBackup();
        else
            SaveOriginalState(key);

        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", $"http={host}:{port};https={host}:{port}", RegistryValueKind.String);
        key.SetValue("ProxyOverride", "localhost;127.*;[::1]", RegistryValueKind.String);
        key.SetValue("AutoConfigURL", "", RegistryValueKind.String);
        key.SetValue("AutoDetect", 0, RegistryValueKind.DWord);
        NotifySettingsChanged();
    }

    public void Restore()
    {
        if (!File.Exists(_backupPath)) return;

        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
            ?? throw new InvalidOperationException("Не удалось открыть настройки прокси Windows для восстановления.");
        var state = ReadBackup();

        // Keep the backup until every value has been restored. If Windows rejects a write,
        // the next launch can retry instead of silently disabling a user's pre-existing proxy.
        RestoreValue(key, state, "ProxyEnable", RegistryValueKind.DWord);
        RestoreValue(key, state, "ProxyServer", RegistryValueKind.String);
        RestoreValue(key, state, "ProxyOverride", RegistryValueKind.String);
        RestoreValue(key, state, "AutoConfigURL", RegistryValueKind.String);
        RestoreValue(key, state, "AutoDetect", RegistryValueKind.DWord);

        File.Delete(_backupPath);
        NotifySettingsChanged();
    }

    private Dictionary<string, JsonElement> ReadBackup()
    {
        try
        {
            var state = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(File.ReadAllText(_backupPath));
            if (state is null || SavedNames.Any(name => !state.ContainsKey(name)))
                throw new InvalidDataException("В резервной копии отсутствуют обязательные параметры.");
            return state;
        }
        catch (Exception ex) when (ex is not InvalidDataException)
        {
            throw new InvalidDataException("Не удалось прочитать резервную копию системного прокси. Настройки Windows не изменены.", ex);
        }
    }

    private void SaveOriginalState(RegistryKey key)
    {
        var state = new Dictionary<string, object?>();
        foreach (var name in SavedNames)
            state[name] = key.GetValue(name);

        var directory = Path.GetDirectoryName(_backupPath)!;
        Directory.CreateDirectory(directory);
        var temporaryPath = _backupPath + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(state));
        File.Move(temporaryPath, _backupPath, overwrite: true);
    }

    private static void RestoreValue(RegistryKey key, Dictionary<string, JsonElement> state, string name, RegistryValueKind kind)
    {
        var value = state[name];
        if (value.ValueKind == JsonValueKind.Null)
        {
            key.DeleteValue(name, throwOnMissingValue: false);
            return;
        }

        object restored = kind == RegistryValueKind.DWord
            ? (value.ValueKind == JsonValueKind.Number ? value.GetInt32() : throw new InvalidDataException($"В резервной копии некорректное значение {name}."))
            : value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : throw new InvalidDataException($"В резервной копии некорректное значение {name}.");
        key.SetValue(name, restored, kind);
    }

    private static void NotifySettingsChanged()
    {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0); // INTERNET_OPTION_SETTINGS_CHANGED
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0); // INTERNET_OPTION_REFRESH
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
