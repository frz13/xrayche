using System.IO;

namespace XrayHub.Models;

public sealed class AppSettings
{
    // The bundled core is resolved internally; there is no user-facing core path setting.
    public string XrayPath { get; set; } = Path.Combine(AppContext.BaseDirectory, "core", "xray.exe");
    public string Mode { get; set; } = "Прокси";
    public int SocksPort { get; set; } = 10808;
    public int HttpPort { get; set; } = 10809;
    public bool UseSystemProxy { get; set; } = true;

    // DNS and TUN.
    // Retained for migration from older settings.json files. New UI always uses an explicit DNS address.
    public string DnsMode { get; set; } = "custom";
    public string DnsServers { get; set; } = "8.8.8.8";
    public bool DnsDefaultMigrated { get; set; }
    public bool ProtectDnsLeaks { get; set; } = true;
    public bool BypassPrivateNetworks { get; set; } = true;
    public bool EnableYoutubeProbe { get; set; } = true;
    public bool DisableQuic { get; set; }
    public int TunMtu { get; set; } = 1500;
    public string TunAddress { get; set; } = "10.88.0.1/30";
    // Xray Core currently has a built-in gVisor TUN stack. System/Mixed selection requires a different TUN backend.
    public string TunStack { get; set; } = "gvisor";

    // Optional local SOCKS5 credentials.
    public bool SocksAuthentication { get; set; } = true;
    public string SocksUsername { get; set; } = "";
    public string SocksPassword { get; set; } = "";

    // Xray outbound controls.
    public bool MuxEnabled { get; set; }
    public int MuxTcpConcurrency { get; set; } = 8;
    public int MuxXudpConcurrency { get; set; } = 8;
    public string MuxQuicHandling { get; set; } = "reject";
    public bool FragmentationEnabled { get; set; }
    public string FragmentationPackets { get; set; } = "tlshello";

    // Application behaviour.
    public bool AutoStartApp { get; set; }
    public bool AutoStartMinimized { get; set; }
    public bool AutoConnect { get; set; }
    public Guid? LastProfileId { get; set; }
    public bool SaveWindowPosition { get; set; } = true;
    public double WindowLeft { get; set; } = double.NaN;
    public double WindowTop { get; set; } = double.NaN;
    public double WindowWidth { get; set; } = 920;
    public double WindowHeight { get; set; } = 650;
    public string Theme { get; set; } = "dark";
    public string Language { get; set; } = "ru";

    // Subscription refresh.
    public bool AutoUpdateSubscriptions { get; set; }
    public int SubscriptionUpdateIntervalHours { get; set; } = 3;

    // Traffic routing.
    public string DefaultRoute { get; set; } = "proxy";
    public List<RoutingRule> RoutingRules { get; set; } = [];
}
