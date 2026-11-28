namespace XrayHub.Models;

/// <summary>Persistent unresolved proxy-conflict notification.</summary>
public sealed class ProxyConflictState
{
    public bool Pending { get; set; }
    public string Fingerprint { get; set; } = string.Empty;
    public string ProxyServer { get; set; } = string.Empty;
    public string AutoConfigUrl { get; set; } = string.Empty;
    public bool ProxyEnabled { get; set; }
    public bool AutoDetect { get; set; }
    public DateTimeOffset DetectedAtUtc { get; set; }
    public string DetectionReason { get; set; } = string.Empty;
    public string DismissedFingerprint { get; set; } = string.Empty;
}
