namespace XrayHub.Models;

/// <summary>
/// Snapshot of the current-user WinINET proxy settings. Nullable values preserve
/// the distinction between a missing registry value and an explicitly stored default.
/// </summary>
public sealed class WindowsProxySnapshot
{
    public int? ProxyEnable { get; set; }
    public string? ProxyServer { get; set; }
    public string? ProxyOverride { get; set; }
    public string? AutoConfigUrl { get; set; }
    public int? AutoDetect { get; set; }

    public bool IsPotentiallyActive => ProxyEnable == 1
        || !string.IsNullOrWhiteSpace(AutoConfigUrl)
        || AutoDetect == 1;

    public string Fingerprint()
    {
        var canonical = string.Join("\n",
            ProxyEnable?.ToString() ?? "<missing>",
            ProxyServer?.Trim() ?? "<missing>",
            ProxyOverride?.Trim() ?? "<missing>",
            AutoConfigUrl?.Trim() ?? "<missing>",
            AutoDetect?.ToString() ?? "<missing>");
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical)));
    }
}
