using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Net.Http;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.Json;
using Forms = System.Windows.Forms;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Navigation;
using System.Windows.Threading;
using XrayHub.Models;
using XrayHub.Services;

namespace XrayHub;

public partial class MainWindow : Window
{
    private readonly ProfileStore _store = new();
    private readonly WindowsProxyManager _systemProxy = new();
    private readonly ProxyConflictStateStore _proxyConflictStore = new();
    private readonly SemaphoreSlim _proxyConflictGate = new(1, 1);
    private WindowsProxyChangeWatcher? _proxyChangeWatcher;
    private ProxyConflictState? _activeProxyConflict;
    private bool _proxyRepairInProgress;
    private int _proxyConflictCheckQueued;
    private readonly ConnectionDiagnostics _diagnostics = new();
    private readonly ConnectionInfoService _connectionInfoService = new();
    private readonly ObservableCollection<ProxyProfile> _profiles = [];
    private readonly ObservableCollection<RoutingRule> _routingRules = [];
    private readonly DispatcherTimer _elapsedTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly DispatcherTimer _healthTimer = new() { Interval = TimeSpan.FromSeconds(25) };
    private readonly DispatcherTimer _subscriptionTimer = new() { Interval = TimeSpan.FromHours(3) };
    private readonly DispatcherTimer _noticeTimer = new() { Interval = TimeSpan.FromSeconds(8) };
    private readonly DispatcherTimer _settingsAutosaveTimer = new() { Interval = TimeSpan.FromMilliseconds(650) };
    private readonly SemaphoreSlim _probeGate = new(1, 1);
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(20) };
    private XrayCoreService _core;
    private AppSettings _settings;
    private DateTimeOffset _connectedAt;
    private bool _connected;
    private bool _disconnecting;
    private bool _closing;
    private bool _initializing = true;
    private bool _isSavingSettings;
    private int _probeFailures;
    private Guid? _activeProfileId;
    private bool _subscriptionRefreshRunning;
    private bool _passwordVisible;
    private Forms.NotifyIcon? _trayIcon;
    private System.Drawing.Icon? _baseTrayIcon;
    private CancellationTokenSource? _connectionInfoCancellation;
    private Forms.ToolStripMenuItem? _trayConnectItem;
    private Forms.ToolStripMenuItem? _trayOpenItem;
    private Forms.ToolStripMenuItem? _trayExitItem;
    private bool _exitRequested;
    private bool _shutdownInProgress;
    private bool _shutdownComplete;
    private string _noticeSourceMessage = string.Empty;
    private string _noticeSourceTitle = "XrayHub";
    private MessageBoxImage _noticeSourceImage = MessageBoxImage.Information;
    private readonly List<(DateTime Timestamp, string Message, bool IsCore)> _logEntries = [];

    public MainWindow()
    {
        _settings = _store.LoadSettings();
        var settingsMigrated = false;
        if (!_settings.DnsDefaultMigrated)
        {
            _settings.DnsDefaultMigrated = true;
            settingsMigrated = true;
        }
        // Legacy releases could save DNS-over-HTTPS URLs or a list of resolvers.
        // The current UI intentionally supports one plain IP address only.
        if (!IPAddress.TryParse((_settings.DnsServers ?? string.Empty).Trim(), out _))
        {
            _settings.DnsServers = "8.8.8.8";
            settingsMigrated = true;
        }
        if (string.IsNullOrWhiteSpace(_settings.SocksUsername) || string.IsNullOrWhiteSpace(_settings.SocksPassword))
        {
            _settings.SocksUsername = "xh_" + GenerateCredential("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", 8);
            _settings.SocksPassword = GenerateCredential("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789_-!@#$%", 24);
            _settings.SocksAuthentication = true;
            settingsMigrated = true;
        }
        if (settingsMigrated) _store.SaveSettings(_settings);
        ApplyThemePalette();
        InitializeComponent();
        _noticeTimer.Tick += (_, _) =>
        {
            _noticeTimer.Stop();
            if (InlineNoticeHost is not null) InlineNoticeHost.Visibility = Visibility.Collapsed;
        };
        _settings.Mode = string.Equals(_settings.Mode, "Туннель (TUN)", StringComparison.OrdinalIgnoreCase)
            ? "Туннель (TUN)" : "Прокси";
        _routingRules.Clear();
        foreach (var rule in _settings.RoutingRules ?? []) _routingRules.Add(rule);
        RoutingRulesGrid.ItemsSource = _routingRules;
        _core = new XrayCoreService(_store);
        _core.LogReceived += AddCoreLog;
        _core.RunningChanged += Core_RunningChanged;

        foreach (var profile in _store.LoadProfiles()) _profiles.Add(profile);
        ProfileList.ItemsSource = _profiles;
        var lastProfile = _settings.LastProfileId.HasValue
            ? _profiles.FirstOrDefault(p => p.Id == _settings.LastProfileId.Value)
            : null;
        if (lastProfile is not null) ProfileList.SelectedItem = lastProfile;
        else if (_profiles.Count > 0) ProfileList.SelectedIndex = 0;

        LoadSettingsToUi();
        RestoreWindowPlacement();
        ApplyResponsiveLayout();
        ModeCombo.SelectedIndex = _settings.Mode.Contains("Туннель", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        SettingsModeCombo.SelectedValue = ModeCombo.SelectedIndex == 1 ? "tun" : "proxy";
        DefaultRouteCombo.SelectedValue = _settings.DefaultRoute;
        _initializing = false;
        UpdateSocksAuthControls();
        UpdateNavigationState();
        UpdateModeDescription();
        UpdateRoutingModeAvailability();
        ApplyUiLanguage();
        _settingsAutosaveTimer.Tick += (_, _) =>
        {
            _settingsAutosaveTimer.Stop();
            if (_initializing || _closing || _shutdownInProgress) return;
            try
            {
                var before = JsonSerializer.Serialize(_settings);
                SaveSettingsFromUi();
                var after = JsonSerializer.Serialize(_settings);
                if (!string.Equals(before, after, StringComparison.Ordinal))
                    AddLog("Изменения настроек и правил автоматически сохранены.");
            }
            catch (Exception ex)
            {
                // Invalid intermediate text (for example, while replacing a port) is not persisted.
                AddLog("Автосохранение ожидает корректного значения: " + ex.Message);
            }
        };
        RegisterSettingsAutosaveHandlers();
        _routingRules.CollectionChanged += (_, _) => ScheduleSettingsAutosave();
        RoutingRulesGrid.CellEditEnding += (_, _) =>
            Dispatcher.BeginInvoke(new Action(ScheduleSettingsAutosave), DispatcherPriority.Background);

        _elapsedTimer.Tick += (_, _) => UpdateElapsed();
        _healthTimer.Tick += async (_, _) => await RunHealthProbeAsync();
        _subscriptionTimer.Tick += async (_, _) => await RefreshSubscriptionsAsync(false);
        ConfigureSubscriptionTimer();
        ApplyAutoStartRegistration();
        Loaded += MainWindow_Loaded;
        StateChanged += MainWindow_StateChanged;
        AddLog("XrayHub запущен. Ядро Xray загружается из встроенной папки core.");
        try { _systemProxy.RecoverInterruptedExternalProxyRepair(); }
        catch (Exception ex) { AddLog("Не удалось восстановить незавершённое исправление стороннего прокси: " + ex.Message); }
        try { _systemProxy.Restore(); }
        catch (Exception ex) { AddLog("Не удалось завершить восстановление системного прокси после предыдущего запуска: " + ex.Message); }
    }

    private void RegisterSettingsAutosaveHandlers()
    {
        TextBox[] textBoxes =
        [
            SocksPortTextBox, HttpPortTextBox, SocksUsernameTextBox,
            SocksPasswordVisibleTextBox, TunAddressTextBox,
            MuxTcpConcurrencyTextBox, MuxXudpConcurrencyTextBox, DnsServersTextBox
        ];
        foreach (var textBox in textBoxes)
            textBox.TextChanged += (_, _) => ScheduleSettingsAutosave();

        ComboBox[] comboBoxes =
        [
            ModeCombo, SettingsModeCombo, DefaultRouteCombo, TunMtuCombo,
            ThemeCombo, LanguageCombo, MuxQuicCombo, FragmentPacketsCombo,
            SubscriptionIntervalCombo
        ];
        foreach (var comboBox in comboBoxes)
            comboBox.SelectionChanged += (_, _) => ScheduleSettingsAutosave();

        ToggleButton[] toggles =
        [
            ProtectDnsLeaksCheckBox, BypassPrivateNetworksTrafficCheckBox,
            DisableQuicTrafficCheckBox, YoutubeProbeTrafficCheckBox,
            UseSystemProxyCheckBox, SocksAuthToggle, AutoStartAppToggle,
            AutoStartMinimizedToggle, AutoConnectToggle, SaveWindowPositionToggle,
            MuxEnabledToggle, FragmentationToggle, AutoUpdateSubscriptionsToggle
        ];
        foreach (var toggle in toggles)
        {
            toggle.Checked += (_, _) => ScheduleSettingsAutosave();
            toggle.Unchecked += (_, _) => ScheduleSettingsAutosave();
        }

        SocksPasswordBox.PasswordChanged += (_, _) => ScheduleSettingsAutosave();
    }

    private void ScheduleSettingsAutosave()
    {
        if (_initializing || _closing || _shutdownInProgress || _isSavingSettings) return;
        _settingsAutosaveTimer.Stop();
        _settingsAutosaveTimer.Start();
    }

    private void LoadSettingsToUi()
    {
        SocksPortTextBox.Text = _settings.SocksPort.ToString();
        HttpPortTextBox.Text = _settings.HttpPort.ToString();
        UseSystemProxyCheckBox.IsChecked = _settings.UseSystemProxy;
        // DNS is intentionally a single, simple editable field. Legacy "system"
        // mode values are migrated to the explicit default resolver.
        _settings.DnsMode = "custom";
        if (string.IsNullOrWhiteSpace(_settings.DnsServers)) _settings.DnsServers = "8.8.8.8";
        DnsServersTextBox.Text = string.IsNullOrWhiteSpace(_settings.DnsServers) ? "8.8.8.8" : _settings.DnsServers;
        DnsEditButton.Content = L("По умолчанию");
        ProtectDnsLeaksCheckBox.IsChecked = _settings.ProtectDnsLeaks;
        BypassPrivateNetworksTrafficCheckBox.IsChecked = _settings.BypassPrivateNetworks;
        DisableQuicTrafficCheckBox.IsChecked = _settings.DisableQuic;
        YoutubeProbeTrafficCheckBox.IsChecked = _settings.EnableYoutubeProbe;

        SocksAuthToggle.IsChecked = _settings.SocksAuthentication;
        SocksUsernameTextBox.Text = _settings.SocksUsername;
        SocksPasswordBox.Password = _settings.SocksPassword;
        SocksPasswordVisibleTextBox.Text = _settings.SocksPassword;
        SocksPasswordBox.Visibility = Visibility.Visible;
        SocksPasswordVisibleTextBox.Visibility = Visibility.Collapsed;
        _passwordVisible = false;
        TunMtuCombo.SelectedValue = _settings.TunMtu.ToString();
        TunAddressTextBox.Text = _settings.TunAddress;
        AutoStartAppToggle.IsChecked = _settings.AutoStartApp;
        AutoStartMinimizedToggle.IsChecked = _settings.AutoStartMinimized;
        AutoConnectToggle.IsChecked = _settings.AutoConnect;
        SaveWindowPositionToggle.IsChecked = _settings.SaveWindowPosition;
        ThemeCombo.SelectedValue = _settings.Theme;
        LanguageCombo.SelectedValue = _settings.Language;
        MuxEnabledToggle.IsChecked = _settings.MuxEnabled;
        MuxTcpConcurrencyTextBox.Text = _settings.MuxTcpConcurrency.ToString();
        MuxXudpConcurrencyTextBox.Text = _settings.MuxXudpConcurrency.ToString();
        MuxQuicCombo.SelectedValue = _settings.MuxQuicHandling;
        FragmentationToggle.IsChecked = _settings.FragmentationEnabled;
        FragmentPacketsCombo.SelectedValue = _settings.FragmentationPackets;
        AutoUpdateSubscriptionsToggle.IsChecked = _settings.AutoUpdateSubscriptions;
        SubscriptionIntervalCombo.SelectedValue = _settings.SubscriptionUpdateIntervalHours.ToString();
    }

    private void SaveSettingsFromUi()
    {
        if (_isSavingSettings) return;
        _isSavingSettings = true;
        try { SaveSettingsFromUiCore(); }
        finally { _isSavingSettings = false; }
    }

    private void SaveSettingsFromUiCore()
    {
        if (!int.TryParse(SocksPortTextBox.Text, out var socksPort) || socksPort is < 1 or > 65535)
            throw new FormatException("Некорректный SOCKS-порт.");
        if (!int.TryParse(HttpPortTextBox.Text, out var httpPort) || httpPort is < 1 or > 65535)
            throw new FormatException("Некорректный HTTP-порт.");
        if (socksPort == httpPort) throw new FormatException("SOCKS- и HTTP-порты должны отличаться.");
        if (!int.TryParse(TunMtuCombo.SelectedValue?.ToString(), out var mtu) || mtu is not (1500 or 1492 or 1380 or 1200))
            throw new FormatException("Выбери один из доступных размеров MTU: 1500, 1492, 1380 или 1200.");
        if (!int.TryParse(MuxTcpConcurrencyTextBox.Text, out var muxTcp) || muxTcp is < -1 or > 1024)
            throw new FormatException("TCP concurrency должен быть в диапазоне от −1 до 1024.");
        if (!int.TryParse(MuxXudpConcurrencyTextBox.Text, out var muxXudp) || muxXudp is < -1 or > 1024)
            throw new FormatException("XUDP concurrency должен быть в диапазоне от −1 до 1024.");

        var tunAddress = TunAddressTextBox.Text.Trim();
        if (!IsValidInterfaceAddress(tunAddress))
            throw new FormatException("Адрес интерфейса должен быть корректным IPv4/IPv6 адресом с CIDR-маской, например 10.88.0.1/30.");
        var dnsValue = DnsServersTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(dnsValue)) dnsValue = "8.8.8.8";
        if (!IPAddress.TryParse(dnsValue, out _))
            throw new FormatException("Укажи один корректный IP-адрес DNS-сервера, например 8.8.8.8.");
        var socksPassword = _passwordVisible ? SocksPasswordVisibleTextBox.Text : SocksPasswordBox.Password;
        if (SocksAuthToggle.IsChecked == true && (string.IsNullOrWhiteSpace(SocksUsernameTextBox.Text) || string.IsNullOrWhiteSpace(socksPassword)))
            throw new FormatException("Для SOCKS5 авторизации нужны и логин, и пароль.");

        _settings.SocksPort = socksPort;
        _settings.HttpPort = httpPort;
        _settings.TunMtu = mtu;
        _settings.TunAddress = tunAddress;
        _settings.UseSystemProxy = UseSystemProxyCheckBox.IsChecked == true;
        _settings.DnsMode = "custom";
        _settings.DnsServers = dnsValue;
        _settings.ProtectDnsLeaks = ProtectDnsLeaksCheckBox.IsChecked == true;
        _settings.BypassPrivateNetworks = BypassPrivateNetworksTrafficCheckBox.IsChecked == true;
        _settings.EnableYoutubeProbe = YoutubeProbeTrafficCheckBox.IsChecked == true;
        _settings.DisableQuic = DisableQuicTrafficCheckBox.IsChecked == true;
        _settings.Mode = SettingsModeCombo.SelectedValue?.ToString() == "tun" ? "Туннель (TUN)" : "Прокси";
        _settings.SocksAuthentication = SocksAuthToggle.IsChecked == true;
        _settings.SocksUsername = SocksUsernameTextBox.Text.Trim();
        _settings.SocksPassword = socksPassword;
        SocksPasswordBox.Password = socksPassword;
        SocksPasswordVisibleTextBox.Text = socksPassword;
        _settings.MuxEnabled = MuxEnabledToggle.IsChecked == true;
        _settings.MuxTcpConcurrency = muxTcp;
        _settings.MuxXudpConcurrency = muxXudp;
        _settings.MuxQuicHandling = MuxQuicCombo.SelectedValue?.ToString() is "allow" or "skip" ? MuxQuicCombo.SelectedValue.ToString()! : "reject";
        _settings.FragmentationEnabled = FragmentationToggle.IsChecked == true;
        _settings.FragmentationPackets = FragmentPacketsCombo.SelectedValue?.ToString() ?? "tlshello";
        _settings.AutoStartApp = AutoStartAppToggle.IsChecked == true;
        _settings.AutoStartMinimized = AutoStartMinimizedToggle.IsChecked == true;
        _settings.AutoConnect = AutoConnectToggle.IsChecked == true;
        _settings.SaveWindowPosition = SaveWindowPositionToggle.IsChecked == true;
        _settings.Theme = ThemeCombo.SelectedValue?.ToString() == "light" ? "light" : "dark";
        _settings.Language = LanguageCombo.SelectedValue?.ToString() == "en" ? "en" : "ru";
        _settings.AutoUpdateSubscriptions = AutoUpdateSubscriptionsToggle.IsChecked == true;
        _settings.SubscriptionUpdateIntervalHours = int.TryParse(SubscriptionIntervalCombo.SelectedValue?.ToString(), out var hours) && hours is 1 or 3 or 5 or 12 ? hours : 3;
        var validRoutingRules = new List<RoutingRule>();
        foreach (var rule in _routingRules)
        {
            var domains = SplitRuleText(rule.Domain ?? string.Empty);
            if (domains.Count == 0) continue; // Ignore an unfinished empty row until the user fills it in.
            foreach (var domain in domains)
                if (!IsValidDomainRule(domain))
                    throw new FormatException($"Некорректный домен в правиле маршрутизации: {domain}.");
            if (rule.Action is not ("proxy" or "direct" or "block" or "blocked"))
                throw new FormatException("Неизвестное действие в одном из правил маршрутизации.");
            validRoutingRules.Add(rule);
        }
        _settings.RoutingRules = validRoutingRules;
        _settings.DefaultRoute = DefaultRouteCombo.SelectedValue?.ToString() ?? "proxy";
        ModeCombo.SelectedIndex = _settings.Mode.Contains("Туннель", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        DnsServersTextBox.Text = dnsValue;
        DnsEditButton.Content = L("По умолчанию");
        _store.SaveSettings(_settings);
        ApplyAutoStartRegistration();
        ConfigureSubscriptionTimer();
        ApplyThemePalette();
        ApplyUiLanguage();
        UpdateTrayMenuLanguage();
    }

    private static bool IsValidInterfaceAddress(string value)
    {
        var parts = value.Split('/', 2);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || !int.TryParse(parts[1], out var prefix)) return false;
        return prefix >= 0 && prefix <= (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_connected)
        {
            await DisconnectAsync();
            return;
        }

        if (ProfileList.SelectedItem is not ProxyProfile profile)
        {
            ShowNotice("Сначала добавь и выбери конфигурацию.", "XrayHub", MessageBoxButton.OK, MessageBoxImage.Information);
            PageTabs.SelectedIndex = 1;
            return;
        }

        try
        {
            SaveSettingsFromUi();
            var tunnelMode = ModeCombo.SelectedIndex == 1;
            if (tunnelMode && !IsAdministrator())
            {
                ShowNotice("Для режима TUN нужны права администратора. Закрой XrayHub и запусти его через «Запуск от имени администратора».", "Требуются права администратора", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            ConnectButton.IsEnabled = false;
            SetConnectionStatus("Подключение…", connected: false);
            FooterText.Text = L("Проверка конфигурации Xray…");
            AddLog($"Подготовка подключения: {profile.DisplayName}");
            // A TUN startup can fail transiently while the Windows adapter is being
            // released by a previous Xray process. If Xray exits during startup or
            // egress verification, clean up the exited process, allow the adapter
            // driver to settle, and retry the whole startup once. Do not retry while
            // Xray is still running: that would hide ordinary proxy/network failures.
            string? egressIp = null;
            var xrayStarted = false;
            for (var startupAttempt = 1; startupAttempt <= 3; startupAttempt++)
            {
                try
                {
                    xrayStarted = false;
                    await _core.StartAsync(profile, _settings, tunnelMode);
                    xrayStarted = true;

                    if (!tunnelMode && _settings.UseSystemProxy)
                        _systemProxy.Enable("127.0.0.1", _settings.HttpPort);

                    // Do not report success merely because xray.exe started.
                    // Verify the public egress through the local SOCKS inbound.
                    using var verificationTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                    for (var attempt = 1; ; attempt++)
                    {
                        try
                        {
                            egressIp = await _connectionInfoService.GetCurrentIpAsync(_settings, verificationTimeout.Token);
                            break;
                        }
                        catch (Exception retryEx) when (attempt < 3 && IsConnectionRefused(retryEx)
                            && !verificationTimeout.IsCancellationRequested)
                        {
                            AddLog($"Локальный SOCKS ещё запускается; повторная проверка {attempt + 1}/3.");
                            await Task.Delay(450, verificationTimeout.Token);
                        }
                    }

                    break;
                }
                catch (Exception startupError) when (tunnelMode && startupAttempt < 3
                    && ((!_core.IsRunning && xrayStarted)
                        || startupError.Message.StartsWith("Xray завершился при запуске", StringComparison.Ordinal)))
                {
                    AddLog($"Xray завершился во время запуска/проверки TUN (попытка {startupAttempt}/3). Повтор после очистки процесса: " + startupError.Message);
                    await _core.StopAsync();
                    await Task.Delay(TimeSpan.FromSeconds(3));
                    AddLog("Повторный запуск TUN после ожидания освобождения адаптера.");
                }
            }

            if (string.IsNullOrWhiteSpace(egressIp))
                throw new InvalidOperationException("Не удалось подтвердить внешний IP через Xray.");

            AddLog($"Проверка выхода через Xray пройдена. Внешний IP: {egressIp}");

            _connected = true;
            UpdateTrayState();
            ModeCombo.IsEnabled = false;
            SettingsModeCombo.IsEnabled = false;
            _activeProfileId = profile.Id;
            _connectedAt = DateTimeOffset.Now;
            _probeFailures = 0;
            SetConnectionStatus("Подключено", connected: true);
            ConnectionDot.Fill = (System.Windows.Media.Brush)FindResource("Accent");
            ConnectButton.Content = L("Отключить");
            ConnectButton.Background = (System.Windows.Media.Brush)FindResource("Panel2");
            ConnectButton.BorderBrush = (System.Windows.Media.Brush)FindResource("Line");
            ConnectButton.Foreground = (System.Windows.Media.Brush)FindResource("TextMain");
            CoreStatusText.Text = L(tunnelMode ? "Xray Core · TUN активен" : "Xray Core · локальный прокси активен");
            FooterText.Text = L(tunnelMode
                ? "Подключено · TUN"
                : _settings.UseSystemProxy ? "Подключено · системный прокси Windows" : "Подключено · локальный прокси (127.0.0.1)");
            _elapsedTimer.Start();
            if (_settings.EnableYoutubeProbe) _healthTimer.Start();
            UpdateElapsed();
            AddLog("Соединение активно.");
            _ = RunHealthProbeAsync();
        }
        catch (Exception ex)
        {
            try { await Task.Run(_systemProxy.Restore).WaitAsync(TimeSpan.FromSeconds(3)); }
            catch (Exception restoreError) { AddLog("Не удалось восстановить системный прокси после ошибки подключения: " + restoreError.Message); }
            try { await _core.StopAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (Exception stopError) { AddLog("Не удалось завершить Xray после ошибки подключения: " + stopError.Message); }
            ModeCombo.IsEnabled = true;
            SetConnectionStatus("Ошибка подключения", connected: false);
            CoreStatusText.Text = L("Ядро не запущено");
            FooterText.Text = L("Ошибка подключения");
            AddLog("ОШИБКА: " + ex.Message);
            ShowNotice("Операция не выполнена. Подробности записаны в журнал.", "XrayHub — ошибка подключения", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { ConnectButton.IsEnabled = true; }
    }

    private string L(string russianText) =>
        _settings.Language == "en" && RussianEnglish.TryGetValue(russianText, out var translated)
            ? translated
            : russianText;

    private void SetConnectionStatus(string russianText, bool connected)
    {
        if (StatusText is null || ConnectedStatusButton is null) return;
        if (connected)
        {
            StatusText.Visibility = Visibility.Collapsed;
            ConnectedStatusLabel.Text = L(russianText);
            ConnectedStatusButton.Visibility = Visibility.Visible;
        }
        else
        {
            ConnectedStatusButton.Visibility = Visibility.Collapsed;
            StatusText.Visibility = Visibility.Visible;
            StatusText.Text = L(russianText);
            StatusText.Foreground = (System.Windows.Media.Brush)FindResource("TextMain");
        }
    }

    private async Task DisconnectAsync()
    {
        if (_disconnecting) return;
        _disconnecting = true;
        ConnectButton.IsEnabled = false;
        _healthTimer.Stop();
        _elapsedTimer.Stop();
        try
        {
            try
            {
                await Task.Run(_systemProxy.Restore).WaitAsync(TimeSpan.FromSeconds(3));
            }
            catch (TimeoutException)
            {
                AddLog("Восстановление системного прокси превысило 3 секунды; продолжаю отключение.");
            }
            catch (Exception ex)
            {
                AddLog("Не удалось восстановить системный прокси: " + ex.Message);
            }

            try
            {
                await _core.StopAsync().WaitAsync(TimeSpan.FromSeconds(10));
            }
            catch (Exception ex)
            {
                AddLog("Остановка ядра не подтверждена: " + ex.Message);
            }
        }
        finally
        {
            var coreStillRunning = _core.IsRunning;
            _connected = coreStillRunning;
            UpdateTrayState();
            ModeCombo.IsEnabled = !coreStillRunning;
            SettingsModeCombo.IsEnabled = !coreStillRunning;
            _connectionInfoCancellation?.Cancel();
            ConnectionDetailsOverlay.Visibility = Visibility.Collapsed;

            if (coreStillRunning)
            {
                // Do not tell the user that the VPN is disconnected while xray.exe is alive.
                SetConnectionStatus("Отключение не завершено", connected: false);
                ConnectionDot.Fill = (System.Windows.Media.Brush)FindResource("Accent");
                ConnectButton.Content = L("Повторить отключение");
                ConnectButton.Background = (System.Windows.Media.Brush)FindResource("Panel2");
                ConnectButton.BorderBrush = (System.Windows.Media.Brush)FindResource("Line");
                ConnectButton.Foreground = (System.Windows.Media.Brush)FindResource("TextMain");
                CoreStatusText.Text = L("Xray Core всё ещё работает");
                FooterText.Text = L("Остановка не подтверждена · повтори отключение");
                AddLog("Xray всё ещё работает. Состояние подключения сохранено; повторное нажатие попробует остановить ядро ещё раз.");
            }
            else
            {
                _activeProfileId = null;
                SetConnectionStatus("Отключено", connected: false);
                ConnectionDot.Fill = (System.Windows.Media.Brush)FindResource("TextMuted");
                ElapsedText.Text = "00:00:00";
                ConnectButton.Content = L("Подключить");
                ConnectButton.Background = (System.Windows.Media.Brush)FindResource("Accent");
                ConnectButton.BorderBrush = (System.Windows.Media.Brush)FindResource("Accent");
                ConnectButton.Foreground = System.Windows.Media.Brushes.White;
                CoreStatusText.Text = L("Ядро не запущено");
                FooterText.Text = L("Готово · Xray Core не запущен");
                AddLog("Остановка Xray подтверждена. Соединение отключено.");
            }

            ConnectButton.IsEnabled = true;
            _disconnecting = false;
        }
    }

    private async void ImportText_Click(object sender, RoutedEventArgs e)
    {
        var input = ImportTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(input)) return;
        try
        {
            IReadOnlyList<ProxyProfile> imported;
            if (Uri.TryCreate(input, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
            {
                AddLog("Загрузка подписки: " + uri.Host);
                var body = await _http.GetStringAsync(uri);
                imported = ProfileParser.ParseSubscription(body, input);
            }
            else imported = ProfileParser.ParseSubscription(input);

            AddProfiles(imported);
            if (imported.Count == 0)
                ShowNotice("Не найдено поддерживаемых профилей. В первой версии доступны VLESS, VMess, Trojan, Shadowsocks и полный JSON Xray.", "Импорт", MessageBoxButton.OK, MessageBoxImage.Information);
            else
                AddLog($"Импортировано профилей: {imported.Count}");
            ImportTextBox.Clear();
        }
        catch (Exception ex)
        {
            AddLog("Ошибка импорта: " + ex.Message);
            ShowNotice("Операция не выполнена. Подробности записаны в журнал.", "Ошибка импорта", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void AddProfiles(IEnumerable<ProxyProfile> profiles)
    {
        foreach (var profile in profiles)
        {
            var duplicate = _profiles.FirstOrDefault(x => x.SourceLink == profile.SourceLink && !string.IsNullOrEmpty(profile.SourceLink));
            if (duplicate is not null)
            {
                duplicate.Name = profile.Name;
                duplicate.UpdatedAt = DateTimeOffset.Now;
                continue;
            }
            _profiles.Add(profile);
        }
        _store.SaveProfiles(_profiles);
        if (ProfileList.SelectedItem is null && _profiles.Count > 0) ProfileList.SelectedIndex = 0;
        ConfigureSubscriptionTimer();
        UpdateTrayState();
    }

    private void ImportFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Импорт конфигурации или подписки",
            Filter = "Файлы конфигураций (*.json;*.txt;*.conf;*.yaml;*.yml)|*.json;*.txt;*.conf;*.yaml;*.yml|Все файлы (*.*)|*.*",
            Multiselect = true
        };
        if (dialog.ShowDialog() != true) return;
        var added = 0;
        foreach (var path in dialog.FileNames)
        {
            try
            {
                var body = File.ReadAllText(path);
                var imported = ProfileParser.ParseSubscription(body);
                if (imported.Count == 1 && imported[0].Protocol == "json") imported[0].Name = Path.GetFileName(path);
                AddProfiles(imported);
                added += imported.Count;
                AddLog($"Импортирован файл: {Path.GetFileName(path)} ({imported.Count})");
            }
            catch (Exception ex) { AddLog($"Не удалось импортировать {Path.GetFileName(path)}: {ex.Message}"); }
        }
        if (added == 0) ShowNotice("В выбранных файлах не найдено поддерживаемых ссылок или Xray JSON.", "Импорт", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async void RefreshSubscriptions_Click(object sender, RoutedEventArgs e)
    {
        var updatedCount = await RefreshSubscriptionsAsync(true);
        if (updatedCount < 0) return;
        ShowNotice($"Обновление завершено. Получено профилей: {updatedCount}.", "Подписки", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async Task<int> RefreshSubscriptionsAsync(bool interactive)
    {
        if (_subscriptionRefreshRunning) return 0;
        var urls = _profiles.Select(p => p.SubscriptionUrl)
            .Where(x => Uri.TryCreate(x, UriKind.Absolute, out var u) && (u.Scheme == "http" || u.Scheme == "https"))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (urls.Count == 0)
        {
            if (interactive) ShowNotice("В списке пока нет профилей, добавленных из HTTP(S)-подписок.", "Подписки", MessageBoxButton.OK, MessageBoxImage.Information);
            return -1;
        }

        _subscriptionRefreshRunning = true;
        var selected = ProfileList.SelectedItem as ProxyProfile;
        var selectedUrl = selected?.SubscriptionUrl;
        var selectedName = selected?.Name;
        var updatedCount = 0;
        try
        {
            foreach (var url in urls)
            {
                try
                {
                    var body = await _http.GetStringAsync(url);
                    var updated = ProfileParser.ParseSubscription(body, url);
                    foreach (var old in _profiles.Where(p => string.Equals(p.SubscriptionUrl, url, StringComparison.OrdinalIgnoreCase)).ToList())
                        _profiles.Remove(old);
                    foreach (var profile in updated) _profiles.Add(profile);
                    updatedCount += updated.Count;
                    AddLog($"Подписка обновлена: {new Uri(url).Host} — {updated.Count} профилей");
                }
                catch (Exception ex) { AddLog($"Ошибка обновления подписки {new Uri(url).Host}: {ex.Message}"); }
            }
            _store.SaveProfiles(_profiles);
            var restoreSelection = _profiles.FirstOrDefault(p => p.SubscriptionUrl == selectedUrl && p.Name == selectedName)
                ?? _profiles.FirstOrDefault(p => p.SubscriptionUrl == selectedUrl);
            if (restoreSelection is not null) ProfileList.SelectedItem = restoreSelection;
            return updatedCount;
        }
        finally { _subscriptionRefreshRunning = false; }
    }

    private void ConfigureSubscriptionTimer()
    {
        _subscriptionTimer.Stop();
        var hours = _settings.SubscriptionUpdateIntervalHours is 1 or 3 or 5 or 12 ? _settings.SubscriptionUpdateIntervalHours : 3;
        _subscriptionTimer.Interval = TimeSpan.FromHours(hours);
        if (_settings.AutoUpdateSubscriptions && _profiles.Any(p => Uri.TryCreate(p.SubscriptionUrl, UriKind.Absolute, out var u) && (u.Scheme == "http" || u.Scheme == "https")))
            _subscriptionTimer.Start();
    }

    private async void PingAll_Click(object sender, RoutedEventArgs e)
    {
        if (_profiles.Count == 0)
        {
            ShowNotice("Сначала импортируй хотя бы одну конфигурацию.", "Пинг серверов", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        PingAllButton.IsEnabled = false;
        PingAllButton.Content = _settings.Language == "en" ? "Checking…" : "Проверка…";
        foreach (var profile in _profiles) profile.PingDisplay = "…";
        AddLog($"Запущена TCP-проверка доступности {_profiles.Count} серверов.");

        using var limiter = new SemaphoreSlim(6, 6);
        try
        {
            // Adapter enumeration is slow on Windows; do it once, off the UI thread.
            var localAddress = await Task.Run(() => FindPhysicalLocalAddress());
            var profilesSnapshot = _profiles.ToList();
            var results = await Task.WhenAll(profilesSnapshot.Select(async profile =>
            {
                await limiter.WaitAsync();
                try
                {
                    return (Profile: profile, Result: await Task.Run(() => MeasureServerLatencyAsync(profile, localAddress)));
                }
                finally { limiter.Release(); }
            }));

            foreach (var result in results)
            {
                result.Profile.PingDisplay = result.Result.Display;
                if (result.Result.Milliseconds.HasValue)
                    AddLog($"Задержка {result.Profile.DisplayName}: {result.Result.Display} ({result.Result.Method}).");
                else
                    AddLog($"TCP-проверка не прошла: {result.Profile.DisplayName}.");
            }

            var success = results.Count(x => x.Result.Milliseconds.HasValue);
            ShowNotice(
                $"TCP-проверка завершена: ответили {success} из {results.Length} серверов.",
                "Пинг серверов", MessageBoxButton.OK, success > 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        finally
        {
            PingAllButton.IsEnabled = true;
            PingAllButton.Content = _settings.Language == "en" ? "Ping servers" : "Пинг серверов";
        }
    }

    private static async Task<(string Display, long? Milliseconds, string Method)> MeasureServerLatencyAsync(ProxyProfile profile, IPAddress? local)
    {
        var (host, port) = ResolveProfileEndpoint(profile);
        if (string.IsNullOrWhiteSpace(host) || port is < 1 or > 65535)
            return ("~", null, "unavailable");

        // Measure the endpoint over the physical network, not through XrayHub's own
        // TUN route. Bind the socket to a physical adapter source address, then connect
        // to a resolved IPv4 endpoint.
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var addresses = IPAddress.TryParse(host, out var literal)
                ? new[] { literal! }
                : await Dns.GetHostAddressesAsync(host, timeout.Token);
            var remote = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (remote is null) return ("~", null, "unavailable");

            if (local is null) return ("~", null, "unavailable");

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(local, 0));
            var stopwatch = Stopwatch.StartNew();
            await socket.ConnectAsync(new IPEndPoint(remote, port), timeout.Token);
            stopwatch.Stop();
            var elapsed = Math.Max(1, stopwatch.ElapsedMilliseconds);
            return ($"{elapsed} ms", elapsed, "TCP direct");
        }
        catch
        {
            return ("~", null, "unavailable");
        }
    }

    private static IPAddress? FindPhysicalLocalAddress()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                    && (n.NetworkInterfaceType == NetworkInterfaceType.Ethernet || n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211))
                .SelectMany(n =>
                {
                    var hasGateway = n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork
                        && !g.Address.Equals(IPAddress.Any));
                    return hasGateway
                        ? n.GetIPProperties().UnicastAddresses
                            .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(u.Address))
                            .Select(u => u.Address)
                        : Enumerable.Empty<IPAddress>();
                })
                .FirstOrDefault();
        }
        catch { return null; }
    }

    private static (string Host, int Port) ResolveProfileEndpoint(ProxyProfile profile)
    {
        // TCP latency checks require the actual proxy endpoint port.
        if (!string.IsNullOrWhiteSpace(profile.Server))
            return (profile.Server, profile.Port);

        // JSON imports can contain the real endpoint in outbounds instead of the simple profile fields.
        if (string.IsNullOrWhiteSpace(profile.RawJson)) return (string.Empty, 0);
        try
        {
            using var document = JsonDocument.Parse(profile.RawJson);
            if (!document.RootElement.TryGetProperty("outbounds", out var outbounds) || outbounds.ValueKind != JsonValueKind.Array)
                return (string.Empty, 0);

            foreach (var outbound in outbounds.EnumerateArray())
            {
                if (outbound.ValueKind != JsonValueKind.Object) continue;
                var protocol = outbound.TryGetProperty("protocol", out var protocolElement) ? protocolElement.GetString() : string.Empty;
                if (protocol is "freedom" or "blackhole" or "dns" or "loopback") continue;
                if (!outbound.TryGetProperty("settings", out var settings) || settings.ValueKind != JsonValueKind.Object) continue;

                if (settings.TryGetProperty("vnext", out var vnext) && vnext.ValueKind == JsonValueKind.Array && vnext.GetArrayLength() > 0)
                {
                    var server = vnext[0];
                    var address = server.TryGetProperty("address", out var a) ? a.GetString() : null;
                    var port = server.TryGetProperty("port", out var p) && p.TryGetInt32(out var value) ? value : 0;
                    if (!string.IsNullOrWhiteSpace(address)) return (address, port);
                }

                if (settings.TryGetProperty("servers", out var servers) && servers.ValueKind == JsonValueKind.Array && servers.GetArrayLength() > 0)
                {
                    var server = servers[0];
                    var address = server.TryGetProperty("address", out var a) ? a.GetString() : null;
                    var port = server.TryGetProperty("port", out var p) && p.TryGetInt32(out var value) ? value : 0;
                    if (!string.IsNullOrWhiteSpace(address)) return (address, port);
                }
            }
        }
        catch { }
        return (string.Empty, 0);
    }

    private void RemoveProfile_Click(object sender, RoutedEventArgs e)
    {
        if (ProfileList.SelectedItem is not ProxyProfile selected) return;
        if (_connected && selected.Id == _activeProfileId)
        {
            ShowNotice("Сначала отключись от профиля.", "XrayHub", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        _profiles.Remove(selected);
        if (_settings.LastProfileId == selected.Id)
        {
            _settings.LastProfileId = null;
            if (_profiles.Count > 0) ProfileList.SelectedIndex = 0;
        }
        _store.SaveProfiles(_profiles);
        _store.SaveSettings(_settings);
        UpdateTrayState();
        AddLog("Профиль удалён: " + selected.DisplayName);
    }

    private void MainWindow_PreviewMouseWheel(object sender, System.Windows.Input.MouseWheelEventArgs e)
    {
        if (e.Handled || e.Delta == 0) return;

        var source = e.OriginalSource as DependencyObject;
        if (source is null) return;

        ScrollViewer? target = null;
        var profileList = FindVisualAncestor<ListBox>(source);
        if (profileList is not null && TryScrollListWithWheel(profileList, e.Delta))
        {
            e.Handled = true;
            return;
        }

        target = FindVisualAncestor<ScrollViewer>(source);

        // If the nearest nested viewer has no extent, continue outward to the first
        // viewer that can actually move. This is important for TextBox/ListBox templates.
        while (target is not null && target.ScrollableHeight <= 0.5)
            target = FindVisualAncestor<ScrollViewer>(GetParentElement(target));

        if (target is null) return;

        var notches = Math.Max(1, Math.Abs(e.Delta) / 120.0);
        var distance = 52.0 * notches;
        var next = Math.Clamp(target.VerticalOffset - Math.Sign(e.Delta) * distance, 0, target.ScrollableHeight);
        if (Math.Abs(next - target.VerticalOffset) < 0.5) return;

        target.ScrollToVerticalOffset(next);
        e.Handled = true;
    }

    private static T? FindVisualAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match) return match;
            current = GetParentElement(current);
        }
        return null;
    }

    private static DependencyObject? GetParentElement(DependencyObject element)
    {
        if (element is System.Windows.Media.Visual or System.Windows.Media.Media3D.Visual3D)
            return VisualTreeHelper.GetParent(element);
        if (element is FrameworkContentElement contentElement)
            return contentElement.Parent;
        return LogicalTreeHelper.GetParent(element);
    }

    private void ProfileList_PreviewMouseWheel(object sender, System.Windows.Input.MouseWheelEventArgs e)
    {
        if (sender is ListBox list && TryScrollListWithWheel(list, e.Delta))
            e.Handled = true;
    }

    private static bool TryScrollListWithWheel(ListBox list, int delta)
    {
        var viewer = FindVisualChild<ScrollViewer>(list);
        if (viewer is null || viewer.ScrollableHeight <= 0.5 || delta == 0) return false;

        var before = viewer.VerticalOffset;
        var notches = Math.Max(1, Math.Abs(delta) / 120.0);
        // The profile list uses pixel-based scrolling (CanContentScroll=false),
        // so move by a predictable number of device-independent pixels per wheel notch.
        var wheelDistance = 54.0 * notches;
        var next = Math.Clamp(before - Math.Sign(delta) * wheelDistance, 0, viewer.ScrollableHeight);
        if (Math.Abs(next - before) < 0.5) return false;
        viewer.ScrollToVerticalOffset(next);
        return true;
    }

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject parent) where T : DependencyObject
    {
        var childCount = VisualTreeHelper.GetChildrenCount(parent);
        for (var i = 0; i < childCount; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) yield return match;
            foreach (var nested in FindVisualChildren<T>(child)) yield return nested;
        }
    }

    private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
    {
        var childCount = VisualTreeHelper.GetChildrenCount(parent);
        for (var i = 0; i < childCount; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T match) return match;
            var nested = FindVisualChild<T>(child);
            if (nested is not null) return nested;
        }
        return null;
    }

    private void ProfileList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_initializing && ProfileList.SelectedItem is ProxyProfile selectedProfile)
        {
            _settings.LastProfileId = selectedProfile.Id;
            _store.SaveSettings(_settings);
        }
        if (SelectedProfileText is not null)
        {
            if (ProfileList.SelectedItem is ProxyProfile p)
            {
                SelectedProfileText.Text = p.DisplayName;
                try
                {
                    SelectedProfileFlagImage.Source = string.IsNullOrWhiteSpace(p.CountryFlagImageUrl)
                        ? null : new BitmapImage(new Uri(p.CountryFlagImageUrl, UriKind.Absolute));
                }
                catch { SelectedProfileFlagImage.Source = null; }
            }
            else
            {
                SelectedProfileText.Text = "Не выбран";
                SelectedProfileFlagImage.Source = null;
            }
        }
    }

    private void ProfileInfo_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button button || button.DataContext is not ProxyProfile selected) return;

        // Reparse the original share link when available. This also enriches profiles imported
        // by an older app build before the extended detail fields were introduced.
        var profile = selected;
        if (!string.IsNullOrWhiteSpace(selected.SourceLink) && selected.Protocol != "json")
        {
            try
            {
                var parsed = ProfileParser.ParseLink(selected.SourceLink);
                parsed.Id = selected.Id;
                parsed.Name = selected.Name;
                parsed.SubscriptionUrl = selected.SubscriptionUrl;
                parsed.UpdatedAt = selected.UpdatedAt;
                profile = parsed;
            }
            catch (Exception ex)
            {
                AddLog("Не удалось повторно прочитать исходную ссылку профиля: " + ex.Message);
            }
        }

        ProfileDetailsTitle.Text = profile.DisplayName;
        ProfileDetailsSubtitle.Text = string.IsNullOrWhiteSpace(profile.Server)
            ? $"{profile.ProtocolDisplay} · Xray Core"
            : $"{profile.ProtocolDisplay} · {profile.Server}:{profile.Port}";
        ProfileDetailsContent.Children.Clear();

        AddProfileDetailsSection("ОСНОВНЫЕ ПАРАМЕТРЫ");
        AddProfileDetail("Название", profile.DisplayName, true);
        AddProfileDetail("Ядро", "Xray Core", true);
        AddProfileDetail("Протокол", profile.ProtocolDisplay, true);
        AddProfileDetail("Адрес", profile.Server, true);
        AddProfileDetail("Порт", profile.Port > 0 ? profile.Port.ToString() : "", true);
        AddProfileDetail("ID / UUID", profile.UserId);
        AddProfileDetail("Пароль", profile.Password);

        AddProfileDetailsSection("СЕТЬ И ТРАНСПОРТ");
        AddProfileDetail("Сеть", string.Equals(profile.Network, "raw", StringComparison.OrdinalIgnoreCase) ? "TCP (raw)" : profile.Network, true);
        AddProfileDetail("Service name", profile.ServiceName);
        AddProfileDetail("Host", profile.Host);
        AddProfileDetail("Path", profile.Path);
        AddProfileDetail("Mode", profile.Mode);
        AddProfileDetail("Header type", profile.HeaderType);
        AddProfileDetail("Packet encoding", profile.PacketEncoding);
        AddProfileDetail("Flow", profile.Flow);

        AddProfileDetailsSection("TLS / REALITY И ШИФРОВАНИЕ");
        AddProfileDetail("Шифрование", profile.Encryption, true);
        AddProfileDetail("Защита", profile.Security, true);
        AddProfileDetail("SNI", profile.Sni);
        if (profile.Security is "tls" or "reality")
            AddProfileDetail("Fingerprint", string.IsNullOrWhiteSpace(profile.Fingerprint) ? "chrome" : profile.Fingerprint, true);
        AddProfileDetail("ALPN", profile.Alpn);
        AddProfileDetail("Public key", profile.PublicKey);
        AddProfileDetail("Short ID", profile.ShortId);
        AddProfileDetail("Allow insecure", profile.AllowInsecure);
        AddProfileDetail("Метод", profile.Method);
        AddProfileDetail("Alter ID", profile.AlterId > 0 ? profile.AlterId.ToString() : "");

        var knownParameters = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "type", "network", "security", "encryption", "sni", "servername", "serverName", "fp", "alpn",
            "pbk", "publicKey", "sid", "shortId", "flow", "host", "path", "serviceName", "service_name",
            "mode", "packetEncoding", "packet_encoding", "headerType", "header_type", "allowInsecure", "insecure",
            "add", "port", "id", "aid", "scy", "net", "tls", "ps"
        };
        var extraParameters = profile.RawQueryParameters
            .Where(pair => !knownParameters.Contains(pair.Key))
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (extraParameters.Count > 0)
        {
            AddProfileDetailsSection("ДОПОЛНИТЕЛЬНЫЕ ПАРАМЕТРЫ ССЫЛКИ");
            foreach (var pair in extraParameters)
                AddProfileDetail(pair.Key, pair.Value, true);
        }

        if (!string.IsNullOrWhiteSpace(profile.RawProtocolDetails))
        {
            AddProfileDetailsSection("ИСХОДНЫЕ ПАРАМЕТРЫ VMESS");
            AddProfileRawText(profile.RawProtocolDetails);
        }
        if (!string.IsNullOrWhiteSpace(profile.RawJson))
        {
            AddProfileDetailsSection("ИСХОДНЫЙ XRAY JSON");
            AddProfileRawText(profile.RawJson);
        }
        if (!string.IsNullOrWhiteSpace(profile.SubscriptionUrl))
        {
            AddProfileDetailsSection("ИСТОЧНИК");
            AddProfileDetail("Подписка", profile.SubscriptionUrl, true);
        }

        ProfileDetailsOverlay.Visibility = Visibility.Visible;
    }

    private void AddProfileDetailsSection(string title)
    {
        var heading = new TextBlock
        {
            Text = title,
            FontSize = 9,
            FontWeight = FontWeights.SemiBold,
            Foreground = (System.Windows.Media.Brush)FindResource("Accent"),
            Margin = new Thickness(0, 12, 0, 8)
        };
        ProfileDetailsContent.Children.Add(heading);
    }

    private void AddProfileDetail(string label, string? value, bool showWhenEmpty = false)
    {
        if (string.IsNullOrWhiteSpace(value) && !showWhenEmpty) return;

        var row = new Grid { Margin = new Thickness(0, 0, 0, 7) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(145) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var labelText = new TextBlock
        {
            Text = label,
            FontSize = 10,
            Foreground = (System.Windows.Media.Brush)FindResource("TextMuted"),
            VerticalAlignment = VerticalAlignment.Top,
            Margin = new Thickness(0, 3, 12, 0)
        };
        var valueText = new TextBox
        {
            Text = string.IsNullOrWhiteSpace(value) ? "—" : value,
            IsReadOnly = true,
            IsTabStop = false,
            BorderThickness = new Thickness(0),
            Background = System.Windows.Media.Brushes.Transparent,
            Foreground = (System.Windows.Media.Brush)FindResource("TextMain"),
            FontSize = 11,
            Padding = new Thickness(0),
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Hidden,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Hidden,
            MinHeight = 19,
            CaretBrush = (System.Windows.Media.Brush)FindResource("TextMain")
        };
        Grid.SetColumn(valueText, 1);
        row.Children.Add(labelText);
        row.Children.Add(valueText);
        ProfileDetailsContent.Children.Add(row);
        ProfileDetailsContent.Children.Add(new Border
        {
            Height = 1,
            Background = (System.Windows.Media.Brush)FindResource("Line"),
            Margin = new Thickness(0, 0, 0, 7)
        });
    }

    private void AddProfileRawText(string text)
    {
        var raw = new TextBox
        {
            Text = text,
            IsReadOnly = true,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Hidden,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Hidden,
            MaxHeight = 180,
            Background = (System.Windows.Media.Brush)FindResource("Bg"),
            Foreground = (System.Windows.Media.Brush)FindResource("TextMain"),
            BorderBrush = (System.Windows.Media.Brush)FindResource("Line"),
            FontFamily = new System.Windows.Media.FontFamily("Consolas"),
            FontSize = 9,
            Padding = new Thickness(9)
        };
        ProfileDetailsContent.Children.Add(raw);
    }

    private void CloseProfileInfo_Click(object sender, RoutedEventArgs e) =>
        ProfileDetailsOverlay.Visibility = Visibility.Collapsed;

    private void ProfileDetailsOverlay_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ReferenceEquals(e.OriginalSource, ProfileDetailsOverlay))
            ProfileDetailsOverlay.Visibility = Visibility.Collapsed;
    }

    private void SaveTrafficSettings_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            SaveSettingsFromUi();
            AddLog("Правила трафика сохранены.");
            ShowNotice(
                _connected ? "Правила сохранены. Они вступят в силу после следующего подключения." : "Правила трафика сохранены.",
                "Правила трафика", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AddLog("Ошибка правил трафика: " + ex.Message);
            ShowNotice("Операция не выполнена. Подробности записаны в журнал.", "Правила трафика", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void AddRoutingRule_Click(object sender, RoutedEventArgs e)
    {
        var rule = new RoutingRule();
        _routingRules.Add(rule);
        RoutingRulesGrid.SelectedItem = rule;
        RoutingRulesGrid.ScrollIntoView(rule);

        // Wait until the new row is generated and laid out before beginning edit.
        Dispatcher.BeginInvoke(new Action(() =>
        {
            var row = RoutingRulesGrid.ItemContainerGenerator.ContainerFromItem(rule) as DataGridRow;
            if (row is null)
            {
                RoutingRulesGrid.UpdateLayout();
                row = RoutingRulesGrid.ItemContainerGenerator.ContainerFromItem(rule) as DataGridRow;
            }
            if (row is null) return;

            var domainColumn = RoutingRulesGrid.Columns[0];
            RoutingRulesGrid.CurrentCell = new DataGridCellInfo(rule, domainColumn);
            RoutingRulesGrid.Focus();
            RoutingRulesGrid.BeginEdit();

            // CellEditingTemplate is applied on a later layout pass. Focus the editor
            // after that pass so DataGrid does not immediately restore row focus.
            Dispatcher.BeginInvoke(new Action(() =>
            {
                RoutingRulesGrid.UpdateLayout();
                row = RoutingRulesGrid.ItemContainerGenerator.ContainerFromItem(rule) as DataGridRow;
                if (row is null) return;
                var cell = FindVisualChildren<DataGridCell>(row)
                    .FirstOrDefault(c => c.Column == domainColumn);
                var editor = cell is null ? null : FindVisualChild<TextBox>(cell);
                if (editor is null) return;
                editor.Focus();
                editor.SelectAll();
                Keyboard.Focus(editor);
            }), DispatcherPriority.ContextIdle);
        }), DispatcherPriority.Loaded);
    }

    private void RemoveRoutingRule_Click(object sender, RoutedEventArgs e)
    {
        if (RoutingRulesGrid.SelectedItem is not RoutingRule selected) return;
        _routingRules.Remove(selected);
    }

    private void MoveRoutingRuleUp_Click(object sender, RoutedEventArgs e)
    {
        if (RoutingRulesGrid.SelectedItem is not RoutingRule selected) return;
        var index = _routingRules.IndexOf(selected);
        if (index <= 0) return;
        _routingRules.Move(index, index - 1);
        RoutingRulesGrid.SelectedItem = selected;
    }

    private void MoveRoutingRuleDown_Click(object sender, RoutedEventArgs e)
    {
        if (RoutingRulesGrid.SelectedItem is not RoutingRule selected) return;
        var index = _routingRules.IndexOf(selected);
        if (index < 0 || index >= _routingRules.Count - 1) return;
        _routingRules.Move(index, index + 1);
        RoutingRulesGrid.SelectedItem = selected;
    }

    private void SaveRoutingRules_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            RoutingRulesGrid.CommitEdit(DataGridEditingUnit.Cell, true);
            RoutingRulesGrid.CommitEdit(DataGridEditingUnit.Row, true);
            // Empty rows are unfinished drafts, not routing rules: discard them on save.
            var emptyRules = _routingRules
                .Where(rule => SplitRuleText(rule.Domain ?? string.Empty).Count == 0)
                .ToList();
            foreach (var emptyRule in emptyRules)
                _routingRules.Remove(emptyRule);

            foreach (var rule in _routingRules)
            {
                var domains = SplitRuleText(rule.Domain ?? string.Empty);
                foreach (var domain in domains)
                {
                    if (!IsValidDomainRule(domain))
                        throw new FormatException($"Некорректный домен: {domain}. Введи доменное имя, например google.com или sub.example.org.");
                }
                if (rule.Action is not ("proxy" or "direct" or "block" or "blocked"))
                    throw new FormatException("Неизвестное действие в одном из правил маршрутизации.");
            }

            _settings.RoutingRules = _routingRules.ToList();
            _settings.DefaultRoute = DefaultRouteCombo.SelectedValue?.ToString() ?? "proxy";
            _store.SaveSettings(_settings);
            AddLog($"Маршрутизация сохранена. Пользовательских правил: {_routingRules.Count}.");
            ShowNotice(
                _connected ? "Маршрутизация сохранена. Новые правила применятся после следующего подключения." : "Маршрутизация сохранена.",
                "Маршрутизация", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AddLog("Ошибка маршрутизации: " + ex.Message);
            ShowNotice("Операция не выполнена. Подробности записаны в журнал.", "Маршрутизация", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static bool IsValidDomainRule(string value)
    {
        var token = value.Trim();
        if (token.Length == 0 || token.Any(char.IsWhiteSpace)) return false;

        // Only actual domain names are accepted in the simplified custom-rules UI.
        // Xray's domain: and full: match prefixes are supported; regex/geosite/ext,
        // URLs, IP addresses, ports, wildcards and arbitrary text are rejected.
        var colon = token.IndexOf(':');
        if (colon >= 0)
        {
            var kind = token[..colon].ToLowerInvariant();
            if (kind is not ("domain" or "full") || token.IndexOf(':', colon + 1) >= 0)
                return false;
            token = token[(colon + 1)..];
        }

        // Permit a single DNS root dot, but reject repeated trailing dots.
        if (token.EndsWith('.')) token = token[..^1];
        if (token.Length is < 4 or > 253 || token.StartsWith('.') || token.EndsWith('.') || token.Contains(".."))
            return false;
        if (IPAddress.TryParse(token, out _)) return false;

        string ascii;
        try
        {
            ascii = new System.Globalization.IdnMapping { UseStd3AsciiRules = true }.GetAscii(token)
                .ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return false;
        }

        if (ascii.Length > 253 || Uri.CheckHostName(ascii) != UriHostNameType.Dns)
            return false;

        var labels = ascii.Split('.');
        if (labels.Length < 2) return false;
        foreach (var label in labels)
        {
            if (label.Length is < 1 or > 63) return false;
            if (label[0] == '-' || label[^1] == '-') return false;
            if (label.Any(c => !(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')))
                return false;
        }

        var tld = labels[^1];
        var validTld = tld.StartsWith("xn--", StringComparison.Ordinal)
            ? tld.Length >= 5 && tld.Length <= 63
            : tld.Length >= 2 && tld.All(c => c is >= 'a' and <= 'z');
        return validTld;
    }

    private static List<string> SplitRuleText(string value) => value
        .Split(new[] { ',', ';', '\r', '\n' }, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
        .ToList();

    private void DnsEditButton_Click(object sender, RoutedEventArgs e)
    {
        DnsServersTextBox.Text = "8.8.8.8";
        _settings.DnsServers = "8.8.8.8";
        _settings.DnsMode = "custom";
        _settings.DnsDefaultMigrated = true;
        _store.SaveSettings(_settings);
        DnsServersTextBox.Focus();
        DnsServersTextBox.CaretIndex = DnsServersTextBox.Text.Length;
        ShowNotice(_connected
            ? "DNS сброшен на 8.8.8.8. Новое значение будет применено после следующего подключения."
            : "DNS сброшен на 8.8.8.8.", "XrayHub", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void SocksAuthToggle_Changed(object sender, RoutedEventArgs e) => UpdateSocksAuthControls();

    private void UpdateSocksAuthControls()
    {
        if (SocksAuthFields is null || SocksAuthToggle is null) return;
        SocksAuthFields.IsEnabled = SocksAuthToggle.IsChecked == true;
        SocksUsernameTextBox.IsEnabled = SocksAuthToggle.IsChecked == true;
        SocksPasswordBox.IsEnabled = SocksAuthToggle.IsChecked == true;
        SocksPasswordVisibleTextBox.IsEnabled = SocksAuthToggle.IsChecked == true;
    }

    private static string GenerateCredential(string alphabet, int count)
    {
        var result = new char[count];
        for (var i = 0; i < result.Length; i++)
            result[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        return new string(result);
    }

    private void SocksPasswordBox_PreviewMouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (_passwordVisible) return;
        SocksPasswordVisibleTextBox.Text = SocksPasswordBox.Password;
        SocksPasswordBox.Visibility = Visibility.Collapsed;
        SocksPasswordVisibleTextBox.Visibility = Visibility.Visible;
        _passwordVisible = true;
        e.Handled = true;
        SocksPasswordVisibleTextBox.Focus();
        SocksPasswordVisibleTextBox.CaretIndex = SocksPasswordVisibleTextBox.Text.Length;
    }

    private void SocksPasswordVisibleTextBox_PreviewMouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (!_passwordVisible) return;
        SocksPasswordBox.Password = SocksPasswordVisibleTextBox.Text;
        SocksPasswordVisibleTextBox.Visibility = Visibility.Collapsed;
        SocksPasswordBox.Visibility = Visibility.Visible;
        _passwordVisible = false;
        e.Handled = true;
        SocksPasswordBox.Focus();
    }

    private void SocksPasswordVisibleTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_passwordVisible && SocksPasswordBox is not null)
            SocksPasswordBox.Password = SocksPasswordVisibleTextBox.Text;
    }

    private void GenerateSocksCredentials_Click(object sender, RoutedEventArgs e)
    {
        const string chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        SocksUsernameTextBox.Text = "xh_" + GenerateCredential(chars, 8);
        var password = GenerateCredential(chars + "_-!@#$%", 24);
        SocksPasswordBox.Password = password;
        SocksPasswordVisibleTextBox.Text = password;
        SocksPasswordVisibleTextBox.Visibility = Visibility.Collapsed;
        SocksPasswordBox.Visibility = Visibility.Visible;
        _passwordVisible = false;
        SocksAuthToggle.IsChecked = true;
        UpdateSocksAuthControls();
    }

    private void SettingsModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_initializing || SettingsModeCombo.SelectedValue is null || ModeCombo is null) return;
        ModeCombo.SelectedIndex = SettingsModeCombo.SelectedValue.ToString() == "tun" ? 1 : 0;
    }

    private void ThemeLanguage_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_initializing) return;
        if (ThemeCombo?.SelectedValue is string theme) _settings.Theme = theme;
        if (LanguageCombo?.SelectedValue is string language) _settings.Language = language;
        ApplyThemePalette();
        ApplyUiLanguage();
        try { _store.SaveSettings(_settings); } catch (Exception ex) { AddLog("Не удалось сохранить тему или язык: " + ex.Message); }
    }

    private void ApplyAutoStartRegistration()
    {
        const string runKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        try
        {
            using var runKey = Registry.CurrentUser.CreateSubKey(runKeyPath, true);
            if (runKey is null) return;
            if (!_settings.AutoStartApp)
            {
                runKey.DeleteValue("XrayHub", false);
                return;
            }
            var exe = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(exe)) throw new InvalidOperationException("Не удалось определить путь к XrayHub.exe.");
            var args = _settings.AutoStartMinimized ? " --minimized" : string.Empty;
            runKey.SetValue("XrayHub", $"\"{exe}\"{args}");
        }
        catch (Exception ex) { AddLog("Не удалось изменить автозапуск Windows: " + ex.Message); }
    }

    private void MainWindow_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        ApplyResponsiveLayout();
    }

    private void ApplyResponsiveLayout()
    {
        if (!IsInitialized || RootLayoutGrid.ActualWidth <= 0 || RootLayoutGrid.ActualHeight <= 0 || _closing) return;

        var clientWidth = RootLayoutGrid.ActualWidth;
        var clientHeight = RootLayoutGrid.ActualHeight;
        // At the unchanged minimum window size, reclaim vertical space for the
        // profile list instead of forcing its card/list to keep large minimum heights.
        var compactProfilesHeight = clientHeight < 485;

        // Keep the main navigation useful while reclaiming horizontal space on small windows.
        var compact = clientWidth < 980;
        var narrow = clientWidth < 860;
        SidebarColumn.Width = new GridLength(narrow ? 126 : compact ? 150 : 178);
        SidebarDockPanel.Margin = narrow
            ? new Thickness(7, 10, 7, 9)
            : compact ? new Thickness(9, 12, 9, 10) : new Thickness(11, 14, 11, 12);
        HeaderContentGrid.Margin = narrow
            ? new Thickness(10, 0, 10, 0)
            : compact ? new Thickness(14, 0, 14, 0) : new Thickness(20, 0, 20, 0);

        var pageMargin = narrow ? new Thickness(10, 12, 10, 14)
            : compact ? new Thickness(14, 15, 14, 16) : new Thickness(20, 18, 20, 18);
        SetScrollContentMargin(HomePageScrollViewer, narrow ? new Thickness(10, 12, 10, 14) : compact ? new Thickness(14, 15, 14, 16) : new Thickness(20, 17, 20, 18));
        ProfilesPageRoot.Margin = pageMargin;
        ProfilesDescriptionText.Visibility = compactProfilesHeight ? Visibility.Collapsed : Visibility.Visible;
        ProfilesImportCard.Padding = compactProfilesHeight ? new Thickness(10) : new Thickness(16);
        ProfilesImportCard.Margin = compactProfilesHeight ? new Thickness(0, 0, 0, 7) : new Thickness(0, 0, 0, 10);
        ImportTextBox.MinHeight = compactProfilesHeight ? 36 : 54;
        ImportTextBox.MaxHeight = compactProfilesHeight ? 42 : 74;
        ImportTextBox.Margin = compactProfilesHeight ? new Thickness(0, 6, 0, 6) : new Thickness(0, 9, 0, 8);
        ProfileListCard.MinHeight = 0;
        ProfileListCard.Padding = compactProfilesHeight ? new Thickness(9) : new Thickness(12);
        ProfileListHeader.Margin = compactProfilesHeight ? new Thickness(0, 0, 0, 5) : new Thickness(0, 0, 0, 8);
        SetScrollContentMargin(TrafficPageScrollViewer, pageMargin);
        SetScrollContentMargin(RoutingPageScrollViewer, pageMargin);
        SetScrollContentMargin(SettingsPageScrollViewer, narrow ? new Thickness(10, 12, 10, 16) : compact ? new Thickness(14, 15, 14, 18) : new Thickness(20, 18, 20, 22));
        SetScrollContentMargin(AboutPageScrollViewer, pageMargin);

        HeaderAddProfileButton.Content = compact ? L("Добавить") : L("Добавить профиль");
        HeaderAddProfileButton.Padding = compact ? new Thickness(9, 7, 9, 7) : new Thickness(12, 8, 12, 8);
        HeaderLogsButton.Padding = compact ? new Thickness(9, 7, 9, 7) : new Thickness(12, 8, 12, 8);

        // The two dashboard card pairs become vertical stacks before their text gets cramped.
        SetTwoColumnGridLayout(HomeModeProfileGrid, narrow);
        SetTwoColumnGridLayout(HomeQuickLinksGrid, narrow);

        // Relax fixed control widths in compact settings layouts.
        SettingsModeCombo.MinWidth = compact ? 190 : 230;
        DefaultRouteCombo.MinWidth = compact ? 190 : 220;
        MuxQuicCombo.MinWidth = compact ? 210 : 250;
        FragmentPacketsCombo.MinWidth = compact ? 210 : 250;

        // Modal cards stay fully inside the current client area, including on short displays.
        var availableWidth = Math.Max(300, clientWidth - 44);
        var availableHeight = Math.Max(260, clientHeight - 44);
        ProfileDetailsCard.Width = Math.Min(650, availableWidth);
        ProfileDetailsCard.MaxHeight = Math.Min(590, availableHeight);
        ConnectionDetailsCard.Width = Math.Min(590, availableWidth);
        ConnectionDetailsCard.MaxHeight = Math.Min(650, availableHeight);
        ProxyConflictCard.Width = Math.Min(520, availableWidth);
        ProxyConflictCard.MaxHeight = Math.Min(390, availableHeight);

    }

    private static void SetScrollContentMargin(ScrollViewer viewer, Thickness margin)
    {
        if (viewer.Content is FrameworkElement content) content.Margin = margin;
    }

    private static void SetTwoColumnGridLayout(Grid grid, bool stackVertically)
    {
        if (grid.Children.Count < 2) return;
        grid.ColumnDefinitions.Clear();
        grid.RowDefinitions.Clear();

        if (stackVertically)
        {
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(grid.Children[0], 0);
            Grid.SetColumn(grid.Children[0], 0);
            Grid.SetRow(grid.Children[1], 1);
            Grid.SetColumn(grid.Children[1], 0);
            grid.Children[0].SetValue(FrameworkElement.MarginProperty, new Thickness(0, 0, 0, 6));
            grid.Children[1].SetValue(FrameworkElement.MarginProperty, new Thickness(0, 6, 0, 0));
        }
        else
        {
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            Grid.SetRow(grid.Children[0], 0);
            Grid.SetColumn(grid.Children[0], 0);
            Grid.SetRow(grid.Children[1], 0);
            Grid.SetColumn(grid.Children[1], 1);
            grid.Children[0].SetValue(FrameworkElement.MarginProperty, new Thickness(0, 0, 5, 0));
            grid.Children[1].SetValue(FrameworkElement.MarginProperty, new Thickness(5, 0, 0, 0));
        }
    }

    private void RestoreWindowPlacement()
    {
        if (!_settings.SaveWindowPosition) return;
        var width = Math.Clamp(_settings.WindowWidth, MinWidth, 1800);
        var height = Math.Clamp(_settings.WindowHeight, MinHeight, 1200);
        var left = _settings.WindowLeft;
        var top = _settings.WindowTop;
        if (!double.IsFinite(left) || !double.IsFinite(top)) return;
        var right = SystemParameters.VirtualScreenLeft + SystemParameters.VirtualScreenWidth;
        var bottom = SystemParameters.VirtualScreenTop + SystemParameters.VirtualScreenHeight;
        if (left + width < SystemParameters.VirtualScreenLeft + 40 || left > right - 40 || top + height < SystemParameters.VirtualScreenTop + 40 || top > bottom - 40) return;
        Left = left; Top = top; Width = width; Height = height;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        EnsureTrayIcon();

        // Watch only Windows' proxy-registry change notifications. This is event-driven;
        // XrayHub does not poll internet connectivity in the background.
        _proxyChangeWatcher = new WindowsProxyChangeWatcher();
        _proxyChangeWatcher.ProxySettingsChanged += ProxyChangeWatcher_ProxySettingsChanged;
        _proxyChangeWatcher.Start();

        await RestoreOrDetectPendingProxyConflictAsync();

        // Keep a pending repair prompt visible even when the app was configured to start minimized.
        if (ProxyConflictOverlay.Visibility != Visibility.Visible
            && Environment.GetCommandLineArgs().Any(a => string.Equals(a, "--minimized", StringComparison.OrdinalIgnoreCase))
            && _settings.AutoStartMinimized)
            HideToTray();

        // Do not auto-connect over an unresolved Windows proxy conflict prompt.
        if (ProxyConflictOverlay.Visibility == Visibility.Visible) return;

        if (_settings.AutoConnect && _settings.LastProfileId.HasValue)
        {
            var profile = _profiles.FirstOrDefault(p => p.Id == _settings.LastProfileId.Value);
            if (profile is not null)
            {
                ProfileList.SelectedItem = profile;
                _ = Dispatcher.InvokeAsync(async () =>
                {
                    await Task.Delay(500);
                    if (!_connected && !_closing && ProxyConflictOverlay.Visibility != Visibility.Visible)
                        ConnectButton_Click(ConnectButton, new RoutedEventArgs());
                });
            }
        }
    }

    private async void ProxyChangeWatcher_ProxySettingsChanged(object? sender, EventArgs e)
    {
        if (_closing || _shutdownInProgress || _proxyRepairInProgress) return;
        try
        {
            var operation = Dispatcher.InvokeAsync(() =>
            {
                if (_closing || _shutdownInProgress) return Task.CompletedTask;
                return DetectExternalProxyConflictAsync();
            });
            await operation.Task.Unwrap();
        }
        catch (Exception ex)
        {
            AddLog("Не удалось проверить изменившиеся настройки прокси Windows: " + ex.Message);
        }
    }

    private async Task RestoreOrDetectPendingProxyConflictAsync()
    {
        var saved = _proxyConflictStore.Load();
        if (saved.Pending)
        {
            try
            {
                var current = _systemProxy.ReadCurrentSnapshot();
                if (!WindowsProxyManager.IsExternalProxy(current, _settings.HttpPort))
                {
                    _proxyConflictStore.ClearPending();
                    AddLog("Сохранённый конфликт прокси больше не существует; предупреждение снято.");
                    return;
                }

                if (!string.Equals(saved.Fingerprint, current.Fingerprint(), StringComparison.OrdinalIgnoreCase))
                {
                    _proxyConflictStore.SavePending(current,
                        "Посторонний системный прокси изменился во время отсутствия XrayHub.");
                    saved = _proxyConflictStore.Load();
                }

                var probe = await ProbeProxyPathsAsync();
                if (probe.DirectInternetWorks && probe.SystemProxyWorks)
                {
                    _proxyConflictStore.ClearPending();
                    AddLog("Сохранённый конфликт прокси больше не влияет на доступ в интернет; предупреждение снято.");
                    return;
                }

                _activeProxyConflict = saved;
                ShowProxyConflictOverlay(saved, previouslyConfirmed: true);
                if (!probe.DirectInternetWorks)
                    ProxyConflictDescriptionText.Text += "\n\n" + L("Сейчас прямая проверка тоже не проходит. XrayHub сохранит исходные настройки и не будет менять прокси без успешной проверки.");
                AddLog("Восстановлено незавершённое предупреждение о стороннем прокси из предыдущего запуска.");
                return;
            }
            catch (Exception ex)
            {
                _activeProxyConflict = saved;
                ShowProxyConflictOverlay(saved, previouslyConfirmed: true);
                AddLog("Не удалось перепроверить сохранённый конфликт прокси; предупреждение оставлено: " + ex.Message);
                return;
            }
        }

        await DetectExternalProxyConflictAsync();
    }

    private async Task DetectExternalProxyConflictAsync()
    {
        if (_proxyRepairInProgress || _closing || _shutdownInProgress) return;
        if (!await _proxyConflictGate.WaitAsync(0))
        {
            Interlocked.Exchange(ref _proxyConflictCheckQueued, 1);
            return;
        }
        try
        {
            if (_closing || _shutdownInProgress || _proxyRepairInProgress) return;
            var snapshot = _systemProxy.ReadCurrentSnapshot();
            if (!WindowsProxyManager.IsExternalProxy(snapshot, _settings.HttpPort))
            {
                var pending = _proxyConflictStore.Load();
                if (pending.Pending && !string.Equals(pending.Fingerprint, snapshot.Fingerprint(), StringComparison.OrdinalIgnoreCase))
                    _proxyConflictStore.ClearPending();
                return;
            }

            var state = _proxyConflictStore.Load();
            var fingerprint = snapshot.Fingerprint();
            if (string.Equals(state.DismissedFingerprint, fingerprint, StringComparison.OrdinalIgnoreCase))
                return;

            var probe = await ProbeProxyPathsAsync();
            // A third-party proxy is not enough by itself. The warning is created only when
            // the direct route has internet access but the Windows-configured proxy route does not.
            if (!probe.DirectInternetWorks || probe.SystemProxyWorks)
                return;

            _proxyConflictStore.SavePending(snapshot,
                "Прямое подключение к интернету работает, а через системный прокси Windows — нет.");
            var pendingState = _proxyConflictStore.Load();
            if (!pendingState.Pending) return;
            _activeProxyConflict = pendingState;
            ShowProxyConflictOverlay(pendingState, previouslyConfirmed: false);
            AddLog("Подтверждён конфликт стороннего системного прокси: " + GetProxyDescription(snapshot));
        }
        catch (Exception ex)
        {
            AddLog("Ошибка диагностики стороннего прокси: " + ex.Message);
        }
        finally
        {
            _proxyConflictGate.Release();
            if (Interlocked.Exchange(ref _proxyConflictCheckQueued, 0) == 1
                && !_proxyRepairInProgress && !_closing && !_shutdownInProgress)
            {
                try { _ = Dispatcher.BeginInvoke(new Action(async () => await DetectExternalProxyConflictAsync())); } catch { }
            }
        }
    }

    private sealed record ProxyPathProbe(bool DirectInternetWorks, bool SystemProxyWorks);

    private async Task<ProxyPathProbe> ProbeProxyPathsAsync()
    {
        var direct = await ProbeInternetRouteAsync(useSystemProxy: false);
        if (!direct) return new ProxyPathProbe(false, false);
        var throughWindowsProxy = await ProbeInternetRouteAsync(useSystemProxy: true);
        return new ProxyPathProbe(true, throughWindowsProxy);
    }

    private static async Task<bool> ProbeInternetRouteAsync(bool useSystemProxy)
    {
        var endpoints = new[]
        {
            "https://www.msftconnecttest.com/connecttest.txt",
            "https://connectivitycheck.gstatic.com/generate_204"
        };

        foreach (var endpoint in endpoints)
        {
            try
            {
                using var handler = new HttpClientHandler { UseProxy = useSystemProxy };
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(4) };
                using var response = await client.GetAsync(endpoint, HttpCompletionOption.ResponseHeadersRead);
                if (response.IsSuccessStatusCode) return true;
            }
            catch { }
        }
        return false;
    }

    private static string GetProxyDescription(WindowsProxySnapshot snapshot)
    {
        var parts = new List<string>();
        if (snapshot.ProxyEnable == 1 && !string.IsNullOrWhiteSpace(snapshot.ProxyServer))
            parts.Add(snapshot.ProxyServer.Trim());
        if (!string.IsNullOrWhiteSpace(snapshot.AutoConfigUrl))
            parts.Add("PAC: " + snapshot.AutoConfigUrl.Trim());
        if (snapshot.AutoDetect == 1)
            parts.Add("WPAD / auto-detect");
        return parts.Count == 0 ? "Автоматическая настройка прокси" : string.Join(" · ", parts);
    }

    private void ShowProxyConflictOverlay(ProxyConflictState state, bool previouslyConfirmed)
    {
        _activeProxyConflict = state;
        if (!IsVisible) RestoreFromTray();
        ProxyConflictDescriptionText.Text = previouslyConfirmed
            ? L("Ранее этот системный прокси уже был подтверждён как причина потери доступа через Windows. Настройки всё ещё не изменились. Выбери, отключить ли конфликтующий прокси.")
            : L("Проверка подтвердила конфликт: интернет доступен напрямую, но не работает через системный прокси Windows. Можно отключить только эту настройку.");
        var address = !string.IsNullOrWhiteSpace(state.ProxyServer) ? state.ProxyServer
            : !string.IsNullOrWhiteSpace(state.AutoConfigUrl) ? "PAC: " + state.AutoConfigUrl
            : state.AutoDetect ? "WPAD / auto-detect" : L("Неизвестный прокси");
        ProxyConflictAddressText.Text = L("Обнаруженная настройка") + ": " + address;
        ProxyConflictDetectedText.Text = L("Обнаружено") + ": " + state.DetectedAtUtc.ToLocalTime().ToString("g");
        ProxyConflictOverlay.Visibility = Visibility.Visible;
    }

    private async void FixProxyConflict_Click(object sender, RoutedEventArgs e)
    {
        if (_activeProxyConflict is null) return;
        FixProxyConflictButton.IsEnabled = false;
        LeaveProxyConflictButton.IsEnabled = false;
        try
        {
            var current = _systemProxy.ReadCurrentSnapshot();
            if (!WindowsProxyManager.IsExternalProxy(current, _settings.HttpPort))
            {
                _proxyConflictStore.ClearPending();
                _activeProxyConflict = null;
                ProxyConflictOverlay.Visibility = Visibility.Collapsed;
                ShowNotice("Посторонний прокси уже отсутствует. Настройки Windows не изменялись.", "XrayHub", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            // Always verify the current situation at the moment the user asks to repair.
            // If the whole physical internet is down, don't alter a proxy setting blindly.
            var beforeRepairProbe = await ProbeProxyPathsAsync();
            if (beforeRepairProbe.SystemProxyWorks)
            {
                _proxyConflictStore.ClearPending();
                _activeProxyConflict = null;
                ProxyConflictOverlay.Visibility = Visibility.Collapsed;
                ShowNotice("Доступ через текущий системный прокси уже работает. Ничего менять не требуется.", "XrayHub", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (!beforeRepairProbe.DirectInternetWorks)
            {
                ProxyConflictDescriptionText.Text = L("Прямая проверка также не имеет доступа к интернету. XrayHub не будет отключать системный прокси, пока не подтверждено, что проблема именно в нём.");
                return;
            }

            if (!string.Equals(current.Fingerprint(), _activeProxyConflict.Fingerprint, StringComparison.OrdinalIgnoreCase))
            {
                _proxyConflictStore.SavePending(current, "Текущие настройки прокси изменились; конфликт повторно подтверждён перед исправлением.");
                _activeProxyConflict = _proxyConflictStore.Load();
            }

            _proxyRepairInProgress = true;
            _systemProxy.BeginExternalProxyRepair();
            await Task.Delay(600);
            var recovered = false;
            for (var attempt = 0; attempt < 3 && !recovered; attempt++)
            {
                recovered = await ProbeInternetRouteAsync(useSystemProxy: true);
                if (!recovered) await Task.Delay(900);
            }

            if (recovered)
            {
                _systemProxy.CompleteExternalProxyRepair();
                _proxyConflictStore.ClearPending();
                _activeProxyConflict = null;
                ProxyConflictOverlay.Visibility = Visibility.Collapsed;
                AddLog("Посторонний системный прокси отключён; доступ к интернету восстановлен.");
                ShowNotice("Конфликтующий системный прокси отключён. Доступ к интернету восстановлен.", "XrayHub", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                _systemProxy.RollbackExternalProxyRepair();
                ProxyConflictDescriptionText.Text = L("Прокси был временно отключён, но проверка не подтвердила восстановление интернета. Исходные настройки Windows возвращены; предупреждение сохранено.");
                AddLog("Отключение стороннего прокси не восстановило доступ; исходные настройки возвращены.");
            }
        }
        catch (Exception ex)
        {
            try { _systemProxy.RollbackExternalProxyRepair(); } catch (Exception rollbackEx) { AddLog("Ошибка отката настроек прокси: " + rollbackEx.Message); }
            ProxyConflictDescriptionText.Text = L("Не удалось безопасно изменить настройки прокси. Исходные параметры сохранены.");
            AddLog("Не удалось исправить конфликт прокси: " + ex.Message);
        }
        finally
        {
            _proxyRepairInProgress = false;
            FixProxyConflictButton.IsEnabled = true;
            LeaveProxyConflictButton.IsEnabled = true;
        }
    }

    private void LeaveProxyConflict_Click(object sender, RoutedEventArgs e)
    {
        if (_activeProxyConflict is not null)
            _proxyConflictStore.Dismiss(_activeProxyConflict.Fingerprint);
        _activeProxyConflict = null;
        ProxyConflictOverlay.Visibility = Visibility.Collapsed;
        AddLog("Пользователь решил оставить сторонние настройки системного прокси без изменений.");
    }

    private void ApplyThemePalette()
    {
        if (Application.Current is null) return;
        var light = string.Equals(_settings.Theme, "light", StringComparison.OrdinalIgnoreCase);
        var colors = light
            ? new Dictionary<string, string>
            {
                ["Bg"]="#F4F6F9", ["Sidebar"]="#FFFFFF", ["Panel"]="#FFFFFF", ["Panel2"]="#F0F3F7",
                ["PanelHover"]="#E8EDF4", ["Line"]="#DCE2EA", ["TextMain"]="#202938", ["TextMuted"]="#657286",
                ["Accent"]="#256FE5", ["AccentHover"]="#1D63D1", ["AccentSoft"]="#E8F0FF", ["Green"]="#16865F", ["NavSelected"]="#EAF1FF",
                ["InputBg"]="#FFFFFF", ["ButtonHover"]="#E8EEF7", ["ButtonHoverBorder"]="#B9C8DB", ["ButtonPressed"]="#DDE8F8",
                ["PopupBg"]="#FFFFFF", ["ComboItemHover"]="#E8F0FC", ["ComboItemSelected"]="#DCE9FF", ["ListSelected"]="#EAF1FF",
                ["ListHover"]="#F1F5FA", ["InputSelection"]="#BBD4FF", ["SwitchOff"]="#C5CEDA", ["GridAltRow"]="#F5F7FA",
                ["GridHeader"]="#EDF1F6", ["FooterBg"]="#FFFFFF", ["InsetBg"]="#F7F9FC", ["OverlayBg"]="#FFFFFF", ["OverlayLine"]="#D4DDE8"
            }
            : new Dictionary<string, string>
            {
                ["Bg"]="#0B0D11", ["Sidebar"]="#080A0E", ["Panel"]="#12161D", ["Panel2"]="#181E28",
                ["PanelHover"]="#202938", ["Line"]="#252D39", ["TextMain"]="#F3F6FB", ["TextMuted"]="#8994A4",
                ["Accent"]="#287BEA", ["AccentHover"]="#398BFA", ["AccentSoft"]="#172B46", ["Green"]="#36B887", ["NavSelected"]="#17263B",
                ["InputBg"]="#0E1218", ["ButtonHover"]="#242D3A", ["ButtonHoverBorder"]="#36465B", ["ButtonPressed"]="#1A2636",
                ["PopupBg"]="#151B24", ["ComboItemHover"]="#24364E", ["ComboItemSelected"]="#1C3554", ["ListSelected"]="#172B45",
                ["ListHover"]="#1A222E", ["InputSelection"]="#315F9B", ["SwitchOff"]="#343C49", ["GridAltRow"]="#151B24",
                ["GridHeader"]="#171D27", ["FooterBg"]="#0D1015", ["InsetBg"]="#0E141D", ["OverlayBg"]="#111720", ["OverlayLine"]="#303B4B"
            };

        foreach (var pair in colors)
        {
            var color = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(pair.Value);
            // Replace the resource. Never mutate a SolidColorBrush: WPF may have frozen it.
            Application.Current.Resources[pair.Key] = new System.Windows.Media.SolidColorBrush(color);
        }
    }

    private static readonly Dictionary<string, string> RussianEnglish = new(StringComparer.Ordinal)
    {
        ["Ядро · Xray Core"]="Core · Xray Core",
        ["Главная"]="Home", ["Конфигурации"]="Configurations", ["Правила трафика"]="Traffic rules", ["Маршрутизация"]="Routing", ["Настройки"]="Settings", ["О программе"]="About", ["Добавить профиль"]="Add profile", ["Журнал"]="Logs",
        ["Управление подключением"]="Connection", ["Подключение к выбранному серверу и параметры режима работы."]="Connect to the selected server and configure the connection mode.", ["СОСТОЯНИЕ СОЕДИНЕНИЯ"]="CONNECTION STATUS", ["Отключено"]="Disconnected", ["Ядро не запущено"]="Core is not running", ["Подключить"]="Connect", ["Отключить"]="Disconnect", ["РЕЖИМ РАБОТЫ"]="CONNECTION MODE", ["Прокси"]="Proxy", ["Туннель (TUN)"]="Tunnel (TUN)", ["АКТИВНЫЙ ПРОФИЛЬ"]="ACTIVE PROFILE", ["Не выбран"]="Not selected", ["Выбрать конфигурацию"]="Select configuration", ["Добавить конфигурацию"]="Add configuration", ["Импортировать"]="Import", ["Загрузить файл"]="Load file", ["Обновить подписки"]="Update subscriptions", ["Мои конфигурации"]="My configurations", ["Удалить выбранную"]="Remove selected",
        ["Защита трафика"]="Traffic protection", ["Проверка доступности"]="Connectivity checks", ["Проверить сейчас"]="Check now", ["Сохранить правила трафика"]="Save traffic rules", ["Маршрут по умолчанию"]="Default route", ["Через прокси"]="Via proxy", ["Напрямую"]="Direct", ["Блокировать"]="Block", ["Пользовательские правила"]="Custom rules", ["Добавить"]="Add", ["Удалить"]="Delete", ["Выше"]="Move up", ["Ниже"]="Move down", ["Домен"]="Domain", ["Порт"]="Port", ["Сеть"]="Network", ["Действие"]="Action", ["Сохранить маршрутизацию"]="Save routing",
        ["Параметры ядра, локальных входов и сетевого поведения."]="Core, local inbound and network settings.", ["ПОДКЛЮЧЕНИЕ"]="CONNECTION", ["Режим подключения"]="Connection mode", ["DNS-сервер"]="DNS server", ["По умолчанию используется 8.8.8.8. При необходимости укажи другой IP-адрес DNS-сервера."]="8.8.8.8 is used by default. Enter a different DNS server IP if needed.", ["По умолчанию"]="Default", ["Пинг серверов"]="Ping servers", ["Изменить"]="Edit", ["Готово"]="Done", ["Порт SOCKS5"]="SOCKS5 port", ["Порт HTTP"]="HTTP port", ["Использовать системный прокси Windows в режиме «Прокси»"]="Use Windows system proxy in Proxy mode",
        ["SOCKS5 АВТОРИЗАЦИЯ"]="SOCKS5 AUTHENTICATION", ["Запрашивать логин и пароль при подключении к локальному SOCKS5"]="Require a username and password for local SOCKS5", ["Логин"]="Username", ["Пароль"]="Password", ["Сгенерировать новые данные"]="Generate new credentials", ["TUN / СЕТЕВОЙ ИНТЕРФЕЙС"]="TUN / NETWORK INTERFACE", ["TCP/IP стек"]="TCP/IP stack", ["gVisor · встроенный стек Xray"]="gVisor · built-in Xray stack", ["Используется текущим TUN-движком"]="Used by the current TUN engine", ["АКТИВЕН"]="ACTIVE", ["System и Mixed доступны в Sing-box/Mihomo, но не являются параметрами TUN-конфигурации Xray Core. Не показываем неработающий переключатель: выбор других стеков появится после добавления отдельного TUN-движка."]="System and Mixed are available in Sing-box/Mihomo, but are not TUN settings in Xray Core. This build uses Xray's built-in gVisor stack. Other stacks require a separate TUN engine.", ["Размер сетевого пакета (MTU)"]="Network packet size (MTU)", ["Адрес сетевого интерфейса"]="Network interface address", ["Для запуска TUN требуются права администратора."]="TUN requires administrator privileges.",
        ["ПРИЛОЖЕНИЕ"]="APPLICATION", ["Запускать приложение вместе с Windows"]="Start with Windows", ["Запускать свёрнутым"]="Start minimized", ["Автоматически подключаться к последнему серверу"]="Connect to the last server automatically", ["Сохранять положение и размер окна"]="Save window position and size", ["Тема"]="Theme", ["Тёмная"]="Dark", ["Светлая"]="Light", ["Язык"]="Language", ["Русский"]="Russian", ["НАСТРОЙКИ ЯДРА XRAY"]="XRAY CORE SETTINGS", ["Использовать мультиплексирование (Mux)"]="Enable multiplexing (Mux)", ["TCP соединения · от −1 до 1024"]="TCP connections · −1 to 1024", ["XUDP · от −1 до 1024"]="XUDP · −1 to 1024", ["Обработка QUIC (UDP/443) в Mux"]="QUIC (UDP/443) handling in Mux", ["Отклонять"]="Reject", ["Разрешать"]="Allow", ["Пропускать мимо Mux"]="Skip Mux", ["Использовать фрагментирование"]="Enable fragmentation", ["Фрагментируемые пакеты"]="Packets to fragment", ["Автоматически"]="Automatic", ["АВТОМАТИЧЕСКОЕ ОБНОВЛЕНИЕ ПОДПИСОК"]="AUTOMATIC SUBSCRIPTION UPDATES", ["Обновлять подписки автоматически"]="Update subscriptions automatically", ["Интервал обновления"]="Update interval", ["час"]="hour", ["часа"]="hours", ["часов"]="hours", ["1 час"]="1 hour", ["3 часа"]="3 hours", ["5 часов"]="5 hours", ["12 часов"]="12 hours", ["Сохранить настройки"]="Save settings", ["Очистить журнал"]="Clear log", ["События приложения и вывод Xray Core."]="Application events and Xray Core output.",
        ["DNS, защита от утечек и сетевые проверки."]="DNS, leak protection and network checks.",
        ["DNS, защита соединения и сетевые ограничения."]="DNS, connection protection and network limits.",
        ["Открыть"]="Open",
        ["Импортируйте сервер или подписку. Поддерживаются VLESS, VMess, Trojan, Shadowsocks и Xray JSON."]="Import a server or subscription. VLESS, VMess, Trojan, Shadowsocks and Xray JSON are supported.",
        ["Блокировать DNS-утечки в режиме TUN"]="Block DNS leaks in TUN mode",
        ["Использует Windows Filtering Platform Xray для блокировки обходных DNS-запросов."]="Uses Xray Windows Filtering Platform rules to block DNS bypass requests.",
        ["Локальные сети направлять напрямую"]="Route local networks directly",
        ["Частные IP-диапазоны (geoip:private) не отправляются на удалённый сервер."]="Private IP ranges (geoip:private) are not sent to the remote server.",
        ["Блокировать QUIC (UDP/443) в режиме TUN"]="Block QUIC (UDP/443) in TUN mode",
        ["Браузеры обычно переключаются с HTTP/3 на TCP/HTTPS. Влияет только на UDP-порт 443."]="Browsers usually fall back from HTTP/3 to TCP/HTTPS. Only UDP port 443 is affected.",
        ["Проверка выполняется через локальный HTTP-вход XrayHub."]="The check runs through the local XrayHub HTTP inbound.",
        ["Изменения DNS и маршрутов применяются при следующем подключении."]="DNS and routing changes apply on the next connection.",
        ["Задай, через какой выход отправлять отдельные домены, IP-адреса и порты."]="Choose which outbound handles specific domains, IP addresses and ports.",
        ["Используется для трафика, который не совпал ни с одним правилом."]="Used for traffic that does not match any rule.",
        ["Введи домен, например google.com или domain:google.com, затем выбери действие. Можно указать несколько доменов через запятую."]="Enter a domain, for example google.com or domain:google.com, then choose an action. Multiple domains can be separated by commas.",
        ["Правила применяются сверху вниз. Более точные правила размещай выше."]="Rules are applied from top to bottom. Place more specific rules first.",
        ["Правила записываются в конфигурацию Xray и применяются при следующем подключении."]="Rules are written to the Xray configuration and apply on the next connection.",
        ["Основные параметры подключения, приложения и Xray Core."]="Core connection, application and Xray Core settings.",
        ["IP-адрес DNS-сервера, например 8.8.8.8"]="DNS server IP address, for example 8.8.8.8",
        ["Сбросить DNS на 8.8.8.8"]="Reset DNS to 8.8.8.8",
        ["Нажми, чтобы показать пароль"]="Click to show the password",
        ["Нажми ещё раз, чтобы скрыть пароль"]="Click again to hide the password",
        ["Текущая реализация TUN в Xray Core использует встроенный gVisor-стек"]="The current Xray Core TUN implementation uses its built-in gVisor stack",
        ["Xray ограничивает TCP concurrency значением 128; XUDP поддерживает до 1024. Значение −1 отключает соответствующий режим."]="Xray limits TCP concurrency to 128; XUDP supports up to 1024. A value of −1 disables the corresponding mode.",
        ["Фрагментирование TCP/TLS при установлении исходящего соединения."]="Fragment TCP/TLS during outbound connection establishment.",
        ["Сетевые параметры применяются при следующем подключении."]="Network settings apply on the next connection.",
        ["Готово · Xray Core не запущен"]="Ready · Xray Core is not running",
        ["Прокси перенаправляет трафик через локальный вход и системные настройки Windows."]="Proxy mode routes traffic through a local inbound and Windows system settings.",
        ["TUN перенаправляет системный трафик через виртуальный сетевой интерфейс. Для запуска требуются права администратора."]="TUN routes system traffic through a virtual network interface. Administrator privileges are required.",
        ["Прокси использует локальные SOCKS/HTTP-входы и, при включении, системные настройки Windows."]="Proxy uses local SOCKS/HTTP inbounds and, when enabled, Windows system proxy settings.",
        ["Туннель создаёт виртуальный сетевой интерфейс и направляет через Xray системный трафик."]="Tunnel mode creates a virtual network interface and routes system traffic through Xray.",
        ["Подключение…"]="Connecting…",
        ["Проверка конфигурации Xray…"]="Checking Xray configuration…",
        ["Подключено"]="Connected",
        ["Ошибка подключения"]="Connection failed",
        ["Соединение прервано"]="Connection interrupted",
        ["Xray Core · TUN активен"]="Xray Core · TUN active",
        ["Xray Core · локальный прокси активен"]="Xray Core · local proxy active",
        ["Подключено · TUN"]="Connected · TUN",
        ["Подключено · системный прокси Windows"]="Connected · Windows system proxy",
        ["Подключено · локальный прокси (127.0.0.1)"]="Connected · local proxy (127.0.0.1)",
        ["Подключено · проверка YouTube/Google пройдена"]="Connected · YouTube/Google check passed",
        ["Подключено · есть проблема с одним из контрольных адресов"]="Connected · one of the test endpoints has a problem",
        ["Ядро остановлено"]="Core stopped",
        ["Данные текущего подключения"]="Current connection details",
        ["Внешний адрес и геоданные активного соединения"]="Public IP and geolocation of the active connection",
        ["Обновить"]="Refresh",
        ["Внешний IP"]="Public IP",
        ["Подсеть"]="Network range",
        ["Версия IP"]="IP version",
        ["Протокол"]="Protocol",
        ["Сервер"]="Server",
        ["Страна"]="Country",
        ["Регион"]="Region",
        ["Город"]="City",
        ["Часовой пояс"]="Time zone",
        ["Почтовый индекс"]="Postal code",
        ["Широта"]="Latitude",
        ["Долгота"]="Longitude",
        ["Провайдер"]="ISP",
        ["ASN"]="ASN",
        ["Точность геолокации"]="Location accuracy",
        ["Не удалось определить геоданные"]="Could not retrieve geolocation data",
        ["Загрузка данных подключения…"]="Loading connection details…",
        ["Нет данных"]="No data",
        ["Данные внешнего IP и геолокации"]="Public IP and geolocation data",
        ["Информация о сервере"]="Server information",
        ["Значения показаны из импортированной конфигурации; отсутствующие параметры скрыты."]="Values are taken from the imported configuration; unavailable parameters are hidden.",
        ["Внешний IP и сведения о сети запрашиваются через активное подключение."]="Public IP and network information are requested through the active connection.",
        ["Уже подключено"]="Already connected",
        ["Сначала добавь и выбери конфигурацию."]="Add and select a configuration first.",
        ["Сначала добавь конфигурацию сервера."]="Add a server configuration first.",
        ["Сначала подключись к профилю."]="Connect to a profile first.",
        ["Сначала отключись от профиля."]="Disconnect from this profile first.",
        ["Сначала импортируй хотя бы одну конфигурацию."]="Import at least one configuration first.",
        ["Не удалось определить внешний IP."]="Could not determine the public IP.",
        ["XrayHub — настольный клиент Windows для управления подключениями через Xray Core. Приложение позволяет хранить профили, настраивать DNS и маршруты, управлять локальными входами и проверять доступность сервисов."]="XrayHub is a Windows desktop client for managing connections through Xray Core. It stores profiles, configures DNS and routes, manages local inbounds and checks service availability.",
        ["vless://, vmess://, trojan://, ss:// или HTTPS-ссылка подписки"]="vless://, vmess://, trojan://, ss:// or an HTTPS subscription URL",
        ["Время ответа ICMP Echo от сервера."]="ICMP Echo reply time from the server.",
        ["Направление трафика: прокси, напрямую или блокировать."]="Choose whether traffic is proxied, sent directly or blocked.",
        ["Проверять YouTube и Google во время подключения"]="Check YouTube and Google while connected",
        ["XrayHub · Подключено"]="XrayHub · Connected",
        ["XrayHub · Готово"]="XrayHub · Ready",
        ["Обнаружен сторонний прокси"]="External proxy detected",
        ["Проверка подтвердила конфликт: интернет доступен напрямую, но не работает через системный прокси Windows. Можно отключить только эту настройку."]="The check confirmed a conflict: direct internet access works, but access through the Windows system proxy does not. Only this proxy setting can be disabled.",
        ["Ранее этот системный прокси уже был подтверждён как причина потери доступа через Windows. Настройки всё ещё не изменились. Выбери, отключить ли конфликтующий прокси."]="This system proxy was previously confirmed as the reason Windows could not access the internet. The settings are still unchanged. Choose whether to disable the conflicting proxy.",
        ["Настройки Windows изменились после обнаружения. Перед исправлением XrayHub повторно проверит текущее состояние и ничего не отключит вслепую."]="Windows settings have changed since detection. Before repairing, XrayHub will recheck the current state and will not disable anything blindly.",
        ["Обнаруженная настройка"]="Detected setting",
        ["Обнаружено"]="Detected",
        ["Неизвестный прокси"]="Unknown proxy",
        ["Исправить"]="Fix",
        ["Оставить как есть"]="Leave as is",
        ["Прокси был временно отключён, но проверка не подтвердила восстановление интернета. Исходные настройки Windows возвращены; предупреждение сохранено."]="The proxy was temporarily disabled, but internet recovery was not confirmed. Original Windows settings were restored; the warning remains pending.",
        ["Не удалось безопасно изменить настройки прокси. Исходные параметры сохранены."]="Could not safely change proxy settings. Original settings were preserved.",
        ["Посторонний прокси уже отсутствует. Настройки Windows не изменялись."]="The external proxy is no longer configured. Windows settings were not changed.",
        ["Доступ через текущий системный прокси уже работает. Ничего менять не требуется."]="The current system proxy has internet access. No changes are needed.",
        ["Прямая проверка также не имеет доступа к интернету. XrayHub не будет отключать системный прокси, пока не подтверждено, что проблема именно в нём."]="Direct internet access is also unavailable. XrayHub will not disable the system proxy until it confirms that the proxy is the cause.",
        ["Конфликтующий системный прокси отключён. Доступ к интернету восстановлен."]="The conflicting system proxy was disabled. Internet access has been restored.",
        ["Xray Core не запущен"]="Xray Core is not running",
        ["Причина"]="Reason",
        ["Геоданные"]="Geolocation",
        ["Версия 0.3.6"]="Version 0.3.6", ["XRAYHUB 0.3.6"]="XRAYHUB 0.3.6",
        ["Версия 0.3.7"]="Version 0.3.7", ["XRAYHUB 0.3.7"]="XRAYHUB 0.3.7",
        ["Версия 0.3.8"]="Version 0.3.8", ["XRAYHUB 0.3.8"]="XRAYHUB 0.3.8",
        ["Версия 0.3.9"]="Version 0.3.9", ["XRAYHUB 0.3.9"]="XRAYHUB 0.3.9",
        ["Версия 0.3.14"]="Version 0.3.14", ["XRAYHUB 0.3.14"]="XRAYHUB 0.3.14",
        ["Закрыть"]="Close", ["created by: "]="created by: ",
        ["Требуются права администратора"]="Administrator privileges required",
        ["Для режима TUN нужны права администратора. Закрой XrayHub и запусти его через «Запуск от имени администратора»."]="TUN mode requires administrator privileges. Close XrayHub and run it as administrator.",
        ["XrayHub — ошибка подключения"]="XrayHub — connection error",
        ["Не найдено поддерживаемых профилей. В первой версии доступны VLESS, VMess, Trojan, Shadowsocks и полный JSON Xray."]="No supported profiles were found. Supported formats are VLESS, VMess, Trojan, Shadowsocks and full Xray JSON.",
        ["Ошибка импорта"]="Import error",
        ["В выбранных файлах не найдено поддерживаемых ссылок или Xray JSON."]="No supported links or Xray JSON were found in the selected files.",
        ["В списке пока нет профилей, добавленных из HTTP(S)-подписок."]="There are no profiles imported from HTTP(S) subscriptions yet.",
        ["В каждом правиле укажи хотя бы один домен или удали пустую строку."]="Enter at least one domain in every rule or remove the empty row.",
        ["Неизвестное действие в одном из правил маршрутизации."]="An unknown action was found in one of the routing rules.",
        ["Правила трафика сохранены."]="Traffic rules saved.",
        ["Маршрутизация сохранена. Новые правила применятся после следующего подключения."]="Routing saved. The new rules will apply after the next connection.",
        ["Маршрутизация сохранена."]="Routing saved.",
        ["DNS сброшен на 8.8.8.8."]="DNS reset to 8.8.8.8.",
        ["DNS сброшен на 8.8.8.8. Новое значение будет применено после следующего подключения."]="DNS reset to 8.8.8.8. The new value will apply after the next connection.",
        ["XrayHub уже подключён к серверу."]="XrayHub is already connected to a server.",
        ["Импорт"]="Import", ["Подписки"]="Subscriptions", ["Проверка сети"]="Network check",
        ["Настройки сохранены. Параметры ядра и сети будут применены после следующего подключения."]="Settings saved. Core and network changes will apply after the next connection.",
        ["Правила сохранены. Они вступят в силу после следующего подключения."]="Rules saved. They will take effect after the next connection.",
        ["Не удалось открыть ссылку. Подробности записаны в журнал."]="Could not open the link. Details were written to the log.",
        ["Настройки сохранены."]="Settings saved.",
        ["Операция не выполнена. Подробности записаны в журнал."]="The operation failed. Details were written to the log.",
        ["Сейчас прямая проверка тоже не проходит. XrayHub сохранит исходные настройки и не будет менять прокси без успешной проверки."]="Direct internet access is also unavailable right now. XrayHub will preserve the original settings and will not change the proxy without a successful verification."
    };

    private string TranslateNoticeText(string text)
    {
        if (_settings.Language != "en" || string.IsNullOrWhiteSpace(text)) return text;
        if (RussianEnglish.TryGetValue(text, out var translated)) return translated;

        var update = System.Text.RegularExpressions.Regex.Match(text,
            @"^Обновление завершено\. Получено профилей: (\d+)\.$");
        if (update.Success) return $"Update complete. Profiles received: {update.Groups[1].Value}.";

        var ping = System.Text.RegularExpressions.Regex.Match(text,
            @"^Проверка ICMP завершена: получен ответ от (\d+) из (\d+) серверов\.$");
        if (ping.Success)
            return $"ICMP ping complete: replies received from {ping.Groups[1].Value} of {ping.Groups[2].Value} servers.";

        var invalidDomain = System.Text.RegularExpressions.Regex.Match(text,
            @"^Некорректный домен: (.+)\. Введи доменное имя, например google\.com или sub\.example\.org\.$");
        if (invalidDomain.Success)
            return $"Invalid domain: {invalidDomain.Groups[1].Value}. Enter a domain name, for example google.com or sub.example.org.";

        return text;
    }

    private void RenderInlineNotice()
    {
        if (InlineNoticeHost is null || InlineNoticeText is null) return;
        var message = TranslateNoticeText(_noticeSourceMessage);
        var title = TranslateNoticeText(_noticeSourceTitle);
        var display = string.IsNullOrWhiteSpace(title) || title.Equals("XrayHub", StringComparison.OrdinalIgnoreCase)
            ? message : $"{title}: {message}";
        InlineNoticeText.Text = display;
        var borderColor = _noticeSourceImage switch
        {
            MessageBoxImage.Error or MessageBoxImage.Stop or MessageBoxImage.Hand => System.Windows.Media.Color.FromRgb(205, 74, 88),
            MessageBoxImage.Warning or MessageBoxImage.Exclamation => System.Windows.Media.Color.FromRgb(207, 145, 48),
            _ => System.Windows.Media.Color.FromRgb(40, 123, 234)
        };
        InlineNoticeHost.BorderBrush = new System.Windows.Media.SolidColorBrush(borderColor);
    }

    private void ApplyUiLanguage()
    {
        if (!IsLoaded && !IsInitialized) return;
        var english = string.Equals(_settings.Language, "en", StringComparison.OrdinalIgnoreCase);
        var map = english ? RussianEnglish : RussianEnglish.GroupBy(kv => kv.Value, StringComparer.Ordinal).ToDictionary(group => group.Key, group => group.First().Key, StringComparer.Ordinal);
        // Walk both logical and visual trees. A TabControl virtualizes the content of
        // inactive tabs, so a visual-only walk leaves those pages in the old language.
        // The visited set prevents processing templated elements twice.
        TranslateElementTree(this, map, new HashSet<DependencyObject>(ReferenceEqualityComparer.Instance));
        foreach (var column in RoutingRulesGrid.Columns)
            if (column.Header is string header && map.TryGetValue(header, out var translated)) column.Header = translated;
        UpdateNavigationState();
        UpdateTrayMenuLanguage();
        if (PingAllButton is not null) PingAllButton.Content = english ? "Ping servers" : "Пинг серверов";
        RenderLogEntries();
        if (InlineNoticeHost?.Visibility == Visibility.Visible) RenderInlineNotice();
    }

    private static void TranslateElementTree(
        DependencyObject root,
        Dictionary<string, string> map,
        HashSet<DependencyObject> visited)
    {
        if (!visited.Add(root)) return;

        if (root is TextBlock textBlock && map.TryGetValue(textBlock.Text, out var translatedText))
            textBlock.Text = translatedText;

        if (root is AccessText accessText && map.TryGetValue(accessText.Text, out var translatedAccessText))
            accessText.Text = translatedAccessText;

        if (root is ContentControl contentControl && contentControl.Content is string content && map.TryGetValue(content, out var translatedContent))
            contentControl.Content = translatedContent;

        if (root is HeaderedContentControl headeredContent && headeredContent.Header is string headerText && map.TryGetValue(headerText, out var translatedHeader))
            headeredContent.Header = translatedHeader;

        if (root is HeaderedItemsControl headeredItems && headeredItems.Header is string itemsHeader && map.TryGetValue(itemsHeader, out var translatedItemsHeader))
            headeredItems.Header = translatedItemsHeader;

        var toolTip = ToolTipService.GetToolTip(root);
        if (toolTip is string toolTipText && map.TryGetValue(toolTipText, out var translatedToolTip))
            ToolTipService.SetToolTip(root, translatedToolTip);

        if (root is TextBlock inlineBlock)
        {
            foreach (var inline in inlineBlock.Inlines)
                TranslateInline(inline, map);
        }

        // Logical traversal reaches content hosted by inactive TabItems and controls
        // whose visual template has not yet been created.
        foreach (var child in LogicalTreeHelper.GetChildren(root))
        {
            if (child is DependencyObject logicalChild)
                TranslateElementTree(logicalChild, map, visited);
        }

        if (root is Visual or System.Windows.Media.Media3D.Visual3D)
        {
            var count = System.Windows.Media.VisualTreeHelper.GetChildrenCount(root);
            for (var i = 0; i < count; i++)
                TranslateElementTree(System.Windows.Media.VisualTreeHelper.GetChild(root, i), map, visited);
        }
    }

    private static void TranslateInline(System.Windows.Documents.Inline inline, Dictionary<string, string> map)
    {
        if (inline is System.Windows.Documents.Run run && map.TryGetValue(run.Text, out var translatedRun))
            run.Text = translatedRun;
        if (inline is System.Windows.Documents.Span span)
        {
            foreach (var child in span.Inlines)
                TranslateInline(child, map);
        }
    }

    private void SaveSettings_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            SaveSettingsFromUi();
            AddLog("Настройки сохранены.");
            ShowNotice(_connected ? "Настройки сохранены. Параметры ядра и сети будут применены после следующего подключения." : "Настройки сохранены.", "XrayHub", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AddLog("Ошибка сохранения настроек: " + ex.Message);
            ShowNotice("Операция не выполнена. Подробности записаны в журнал.", "Настройки", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ModeCombo is null || ModeCombo.SelectedIndex < 0) return;
        if (!_initializing && _settings is not null && !_connected)
        {
            _settings.Mode = ModeCombo.SelectedIndex == 1 ? "Туннель (TUN)" : "Прокси";
            if (SettingsModeCombo is not null) SettingsModeCombo.SelectedValue = ModeCombo.SelectedIndex == 1 ? "tun" : "proxy";
            _store.SaveSettings(_settings);
        }
        UpdateModeDescription();
        UpdateRoutingModeAvailability();
    }

    private void UpdateRoutingModeAvailability()
    {
        if (ModeCombo is null || RoutingPageContent is null || RoutingProxyNotice is null) return;
        var tunnelMode = ModeCombo.SelectedIndex == 1;
        RoutingPageContent.IsEnabled = tunnelMode;
        RoutingPageContent.Opacity = tunnelMode ? 1.0 : 0.45;
        RoutingProxyNotice.Visibility = tunnelMode ? Visibility.Collapsed : Visibility.Visible;
        RoutingNavButton.IsEnabled = true;
        if (!tunnelMode && PageTabs.SelectedIndex == 3) PageTabs.SelectedIndex = 0;
    }

    private void UpdateModeDescription()
    {
        if (ModeDescription is null || ModeCombo is null) return;
        ModeDescription.Text = L(ModeCombo.SelectedIndex == 1
            ? "TUN перенаправляет системный трафик через виртуальный сетевой интерфейс. Для запуска требуются права администратора."
            : "Прокси использует локальные SOCKS/HTTP-входы и, при включении, системные настройки Windows.");
    }

    private async Task RunHealthProbeAsync()
    {
        if (!_connected || !_settings.EnableYoutubeProbe || !_probeGate.Wait(0)) return;
        try
        {
            var result = await _diagnostics.ProbeAsync(_settings.HttpPort);
            if (result.YouTube && result.Google)
            {
                _probeFailures = 0;
                FooterText.Text = L("Подключено · проверка YouTube/Google пройдена");
            }
            else
            {
                _probeFailures++;
                AddLog($"Проверка сети ({_probeFailures}/3): {result.Message}");
                FooterText.Text = L("Подключено · есть проблема с одним из контрольных адресов");
                if (_probeFailures >= 3)
                {
                    AddLog("Предупреждение: три проверки подряд не прошли. Ядро не перезапускается автоматически, чтобы не прерывать рабочий трафик без подтверждения причины.");
                    _probeFailures = 0;
                }
            }
        }
        catch (Exception ex) { AddLog("Диагностика: " + ex.Message); }
        finally { _probeGate.Release(); }
    }

    private async void ProbeNow_Click(object sender, RoutedEventArgs e)
    {
        if (!_connected)
        {
            ShowNotice("Сначала подключись к профилю.", "Проверка сети", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        await RunHealthProbeAsync();
    }

    private void Core_RunningChanged(bool running)
    {
        if (running) return;
        // Process.Exited can run on a worker thread. Never synchronously wait for the
        // dispatcher here: the UI may itself be awaiting process shutdown.
        Dispatcher.BeginInvoke(new Action(async () =>
        {
            if (!_connected || _closing || _disconnecting) return;
            _connected = false;
            UpdateTrayState();
            ModeCombo.IsEnabled = true;
            SettingsModeCombo.IsEnabled = true;
            _activeProfileId = null;
            _connectionInfoCancellation?.Cancel();
            if (ConnectionDetailsOverlay is not null) ConnectionDetailsOverlay.Visibility = Visibility.Collapsed;
            _elapsedTimer.Stop();
            _healthTimer.Stop();
            try { await Task.Run(_systemProxy.Restore).WaitAsync(TimeSpan.FromSeconds(3)); }
            catch (Exception ex) { AddLog("Не удалось восстановить системный прокси после остановки ядра: " + ex.Message); }
            SetConnectionStatus("Соединение прервано", connected: false);
            ConnectionDot.Fill = (System.Windows.Media.Brush)FindResource("TextMuted");
            CoreStatusText.Text = L("Xray Core остановлен");
            ConnectButton.Content = L("Подключить");
            ConnectButton.Background = (System.Windows.Media.Brush)FindResource("Accent");
            ConnectButton.BorderBrush = (System.Windows.Media.Brush)FindResource("Accent");
            ConnectButton.Foreground = System.Windows.Media.Brushes.White;
            ElapsedText.Text = "00:00:00";
            FooterText.Text = L("Ядро остановлено");
            AddLog("Ядро завершило работу. Системный прокси восстановлен.");
        }));
    }

    private void UpdateElapsed()
    {
        if (!_connected) return;
        var span = DateTimeOffset.Now - _connectedAt;
        ElapsedText.Text = $"{(int)span.TotalHours:00}:{span.Minutes:00}:{span.Seconds:00}";
    }

    private void ShowNotice(string message, string title = "XrayHub", MessageBoxButton buttons = MessageBoxButton.OK, MessageBoxImage image = MessageBoxImage.Information)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(() => ShowNotice(message, title, buttons, image)));
            return;
        }
        if (InlineNoticeHost is null || InlineNoticeText is null)
        {
            AddLog(message);
            return;
        }

        _noticeSourceMessage = message;
        _noticeSourceTitle = title;
        _noticeSourceImage = image;
        RenderInlineNotice();
        InlineNoticeHost.Visibility = Visibility.Visible;
        _noticeTimer.Stop();
        _noticeTimer.Start();
        AddLog(message);
    }

    private void DismissNotice_Click(object sender, RoutedEventArgs e)
    {
        _noticeTimer.Stop();
        InlineNoticeHost.Visibility = Visibility.Collapsed;
    }

    private void AddLog(string message) => AddLogEntry(message, isCore: false);

    private void AddCoreLog(string message) => AddLogEntry(message, isCore: true);

    private void AddLogEntry(string message, bool isCore)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(() => AddLogEntry(message, isCore)));
            return;
        }

        _logEntries.Add((DateTime.Now, message ?? string.Empty, isCore));
        if (_logEntries.Count > 1500) _logEntries.RemoveRange(0, _logEntries.Count - 1200);
        RenderLogEntries();
    }

    private void RenderLogEntries()
    {
        if (LogTextBox is null) return;
        var english = string.Equals(_settings?.Language, "en", StringComparison.OrdinalIgnoreCase);
        var lines = _logEntries.Select(entry =>
        {
            var message = entry.IsCore ? TranslateCoreLog(entry.Message, english) : TranslateLogMessage(entry.Message, english);
            return $"[{entry.Timestamp:HH:mm:ss}] {message}";
        });
        LogTextBox.Text = string.Join(Environment.NewLine, lines);
        LogTextBox.CaretIndex = LogTextBox.Text.Length;
        LogTextBox.ScrollToEnd();
    }

    private string TranslateLogMessage(string message, bool english)
    {
        if (!english || string.IsNullOrWhiteSpace(message)) return message;
        var translated = TranslateNoticeText(message);
        if (!string.Equals(translated, message, StringComparison.Ordinal)) return translated;

        (string Prefix, string English)[] prefixes =
        [
            ("Подготовка подключения: ", "Preparing connection: "),
            ("Загрузка подписки: ", "Loading subscription: "),
            ("Импортировано профилей: ", "Profiles imported: "),
            ("Ошибка импорта: ", "Import error: "),
            ("Импортирован файл: ", "Imported file: "),
            ("Не удалось импортировать ", "Could not import "),
            ("Подписка обновлена: ", "Subscription updated: "),
            ("Ошибка обновления подписки ", "Subscription update failed "),
            ("Запущена ICMP-проверка для ", "Started ICMP check for "),
            ("Сервер не ответил на ICMP: ", "No ICMP reply from server: "),
            ("Задержка ", "Latency "),
            ("Профиль удалён: ", "Profile removed: "),
            ("Не удалось повторно прочитать исходную ссылку профиля: ", "Could not reread the original profile link: "),
            ("Ошибка правил трафика: ", "Traffic rules error: "),
            ("Ошибка маршрутизации: ", "Routing error: "),
            ("Не удалось сохранить тему или язык: ", "Could not save the theme or language: "),
            ("Не удалось изменить автозапуск Windows: ", "Could not change Windows startup settings: "),
            ("Не удалось проверить изменившиеся настройки прокси Windows: ", "Could not check changed Windows proxy settings: "),
            ("Восстановлено незавершённое предупреждение о стороннем прокси из предыдущего запуска.", "Restored a pending external-proxy warning from the previous run."),
            ("Подтверждён конфликт стороннего системного прокси: ", "Confirmed an external system proxy conflict: "),
            ("Ошибка диагностики стороннего прокси: ", "External proxy diagnosis error: "),
            ("Посторонний системный прокси отключён; доступ к интернету восстановлен.", "The external system proxy was disabled; internet access was restored."),
            ("Отключение стороннего прокси не восстановило доступ; исходные настройки возвращены.", "Disabling the external proxy did not restore access; original settings were restored."),
            ("Ошибка отката настроек прокси: ", "Proxy settings rollback error: "),
            ("Не удалось исправить конфликт прокси: ", "Could not repair the proxy conflict: "),
            ("Не удалось открыть страницу автора: ", "Could not open the author page: "),
            ("Данные текущего подключения получены: ", "Current connection details received: "),
            ("Не удалось получить данные текущего подключения: ", "Could not retrieve current connection details: "),
            ("Диагностика: ", "Diagnostics: "),
            ("Проверка сети (", "Network check ("),
            ("XrayHub запущен. Ядро Xray загружается из встроенной папки core.", "XrayHub started. Xray Core is loading from the bundled core folder."),
            ("Соединение активно.", "Connection is active."),
            ("Соединение остановлено.", "Connection stopped."),
            ("Ядро завершило работу. Системный прокси восстановлен.", "Core stopped. The system proxy was restored."),
            ("Ядро не удалось запустить: ", "Could not start the core: "),
            ("ОШИБКА: ", "ERROR: ")
        ];
        foreach (var item in prefixes)
        {
            if (message.StartsWith(item.Prefix, StringComparison.Ordinal))
                return item.English + message[item.Prefix.Length..];
        }
        return message;
    }

    private static string TranslateCoreLog(string message, bool english)
    {
        if (string.IsNullOrWhiteSpace(message)) return message;
        if (english) return message; // Xray Core emits its own diagnostics in English.
        var trimmed = message.Trim();
        if (trimmed.StartsWith("accepted ", StringComparison.OrdinalIgnoreCase))
            return "Xray Core: принято соединение — " + trimmed[9..];
        if (trimmed.StartsWith("rejected ", StringComparison.OrdinalIgnoreCase))
            return "Xray Core: отклонено соединение — " + trimmed[9..];
        if (trimmed.StartsWith("failed to ", StringComparison.OrdinalIgnoreCase))
            return "Xray Core: не удалось выполнить операцию — " + trimmed[10..];
        if (trimmed.StartsWith("warning", StringComparison.OrdinalIgnoreCase))
            return "Xray Core: предупреждение — " + trimmed[7..].TrimStart(':', ' ');
        if (trimmed.StartsWith("error", StringComparison.OrdinalIgnoreCase))
            return "Xray Core: ошибка — " + trimmed[5..].TrimStart(':', ' ');
        return "Xray Core: " + message;
    }

    private static bool IsConnectionRefused(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
            if (e is System.Net.Sockets.SocketException { SocketErrorCode: System.Net.Sockets.SocketError.ConnectionRefused })
                return true;
        return false;
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void PageTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.OriginalSource, PageTabs)) return;
        UpdateNavigationState();
    }

    private void UpdateNavigationState()
    {
        if (PageTabs is null || HeaderTitle is null) return;
        var titlesRu = new[] { "Главная", "Конфигурации", "Правила трафика", "Маршрутизация", "Настройки", "Журнал", "О программе" };
        var titlesEn = new[] { "Home", "Configurations", "Traffic rules", "Routing", "Settings", "Logs", "About" };
        var titles = _settings?.Language == "en" ? titlesEn : titlesRu;
        var buttons = new[] { HomeNavButton, ProfilesNavButton, TrafficNavButton, RoutingNavButton, SettingsNavButton, AboutNavButton };
        var selected = PageTabs.SelectedIndex;
        HeaderTitle.Text = selected >= 0 && selected < titles.Length ? titles[selected] : "XrayHub";

        for (var i = 0; i < buttons.Length; i++)
        {
            var active = (i < 5 && i == selected) || (i == 5 && selected == 6);
            buttons[i].Background = active
                ? (System.Windows.Media.Brush)FindResource("NavSelected")
                : System.Windows.Media.Brushes.Transparent;
            buttons[i].Foreground = active
                ? (System.Windows.Media.Brush)FindResource("TextMain")
                : (System.Windows.Media.Brush)FindResource("TextMuted");
        }
    }

    private void GoHome_Click(object sender, RoutedEventArgs e) => PageTabs.SelectedIndex = 0;
    private void GoToProfiles_Click(object sender, RoutedEventArgs e) => PageTabs.SelectedIndex = 1;
    private void GoToTraffic_Click(object sender, RoutedEventArgs e) => PageTabs.SelectedIndex = 2;
    private void GoToRouting_Click(object sender, RoutedEventArgs e)
    {
        if (ModeCombo.SelectedIndex != 1)
        {
            UpdateRoutingModeAvailability();
            PageTabs.SelectedIndex = 3;
            return;
        }
        PageTabs.SelectedIndex = 3;
    }
    private void GoToSettings_Click(object sender, RoutedEventArgs e) => PageTabs.SelectedIndex = 4;
    private void OpenLogs_Click(object sender, RoutedEventArgs e) => PageTabs.SelectedIndex = 5;
    private void ClearLogs_Click(object sender, RoutedEventArgs e)
    {
        _logEntries.Clear();
        LogTextBox.Clear();
    }

    private void About_Click(object sender, RoutedEventArgs e) => PageTabs.SelectedIndex = 6;

    private void CreatorLink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            AddLog("Не удалось открыть страницу автора: " + ex.Message);
            ShowNotice("Не удалось открыть ссылку. Подробности записаны в журнал.", "XrayHub", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        e.Handled = true;
    }

    private void MainWindow_StateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized && !_exitRequested)
            HideToTray();
    }

    private void EnsureTrayIcon()
    {
        if (_trayIcon is not null) return;
        _baseTrayIcon = LoadBaseTrayIcon();

        var menu = new Forms.ContextMenuStrip();
        _trayConnectItem = new Forms.ToolStripMenuItem();
        _trayConnectItem.Click += (_, _) => Dispatcher.BeginInvoke(new Action(async () => await ConnectLastProfileFromTrayAsync()));
        _trayOpenItem = new Forms.ToolStripMenuItem();
        _trayOpenItem.Click += (_, _) => RestoreFromTray();
        _trayExitItem = new Forms.ToolStripMenuItem();
        _trayExitItem.Click += (_, _) =>
        {
            _exitRequested = true;
            Close();
        };
        menu.Items.Add(_trayConnectItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(_trayOpenItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(_trayExitItem);

        _trayIcon = new Forms.NotifyIcon
        {
            Icon = CreateTrayDisplayIcon(_baseTrayIcon, _connected),
            Text = "XrayHub · Готово",
            ContextMenuStrip = menu,
            Visible = true
        };
        _trayIcon.DoubleClick += (_, _) => RestoreFromTray();
        _trayIcon.MouseClick += (_, e) =>
        {
            if (e.Button == Forms.MouseButtons.Left) RestoreFromTray();
        };
        UpdateTrayMenuLanguage();
        UpdateTrayState();
    }

    private static System.Drawing.Icon LoadBaseTrayIcon()
    {
        try
        {
            var resource = System.Windows.Application.GetResourceStream(
                new Uri("pack://application:,,,/Assets/XrayHub.ico", UriKind.Absolute));
            if (resource?.Stream is null) throw new InvalidOperationException("Embedded XrayHub icon was not found.");
            using var iconStream = resource.Stream;
            using var embeddedIcon = new System.Drawing.Icon(iconStream);
            return (System.Drawing.Icon)embeddedIcon.Clone();
        }
        catch
        {
            var exePath = Environment.ProcessPath;
            try
            {
                return !string.IsNullOrWhiteSpace(exePath)
                    ? (System.Drawing.Icon.ExtractAssociatedIcon(exePath) ?? (System.Drawing.Icon)System.Drawing.SystemIcons.Application.Clone())
                    : (System.Drawing.Icon)System.Drawing.SystemIcons.Application.Clone();
            }
            catch
            {
                return (System.Drawing.Icon)System.Drawing.SystemIcons.Application.Clone();
            }
        }
    }

    private static System.Drawing.Icon CreateTrayDisplayIcon(System.Drawing.Icon baseIcon, bool connected)
    {
        if (!connected) return (System.Drawing.Icon)baseIcon.Clone();

        using var source = baseIcon.ToBitmap();
        using var canvas = new System.Drawing.Bitmap(32, 32, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        using (var graphics = System.Drawing.Graphics.FromImage(canvas))
        {
            graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            graphics.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            graphics.DrawImage(source, new System.Drawing.Rectangle(0, 0, 32, 32));

            // A small blue lightning mark at the lower-right corner indicates an active tunnel.
            var bolt = new[]
            {
                new System.Drawing.PointF(21.2f, 15.2f),
                new System.Drawing.PointF(16.3f, 22.1f),
                new System.Drawing.PointF(19.6f, 22.1f),
                new System.Drawing.PointF(17.6f, 28.0f),
                new System.Drawing.PointF(25.8f, 19.0f),
                new System.Drawing.PointF(22.2f, 19.0f)
            };
            using var outline = new System.Drawing.Pen(System.Drawing.Color.FromArgb(245, 5, 12, 24), 1.5f);
            using var fill = new System.Drawing.SolidBrush(System.Drawing.Color.FromArgb(255, 55, 145, 255));
            graphics.FillPolygon(fill, bolt);
            graphics.DrawPolygon(outline, bolt);
        }

        var handle = canvas.GetHicon();
        try
        {
            using var temporaryIcon = System.Drawing.Icon.FromHandle(handle);
            return (System.Drawing.Icon)temporaryIcon.Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    private void UpdateTrayMenuLanguage()
    {
        if (_trayConnectItem is null || _trayOpenItem is null || _trayExitItem is null) return;
        var english = _settings.Language == "en";
        _trayConnectItem.Text = _connected
            ? (english ? "Disconnect from current server" : "Отключиться от текущего сервера")
            : (english ? "Connect to last server" : "Подключиться к последнему серверу");
        _trayOpenItem.Text = english ? "Open XrayHub" : "Открыть XrayHub";
        _trayExitItem.Text = english ? "Exit" : "Выход";
    }

    private void UpdateTrayState()
    {
        if (_trayIcon is null) return;
        if (_trayConnectItem is not null)
        {
            _trayConnectItem.Text = _connected
                ? (_settings.Language == "en" ? "Disconnect from current server" : "Отключиться от текущего сервера")
                : (_settings.Language == "en" ? "Connect to last server" : "Подключиться к последнему серверу");
            _trayConnectItem.Enabled = _connected || _profiles.Count > 0;
        }
        _trayIcon.Text = _connected ? (L("XrayHub · Подключено")) : (L("XrayHub · Готово"));

        if (_baseTrayIcon is not null)
        {
            var replacement = CreateTrayDisplayIcon(_baseTrayIcon, _connected);
            var previous = _trayIcon.Icon;
            _trayIcon.Icon = replacement;
            if (previous is not null && !ReferenceEquals(previous, _baseTrayIcon)) previous.Dispose();
        }
    }

    private async Task ConnectLastProfileFromTrayAsync()
    {
        if (_disconnecting) return;
        if (_connected)
        {
            await DisconnectAsync();
            return;
        }
        var profile = _settings.LastProfileId.HasValue
            ? _profiles.FirstOrDefault(p => p.Id == _settings.LastProfileId.Value)
            : null;
        profile ??= _profiles.FirstOrDefault();
        if (profile is null)
        {
            RestoreFromTray();
            ShowNotice("Сначала добавь конфигурацию сервера.", "XrayHub", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        ProfileList.SelectedItem = profile;
        await Dispatcher.InvokeAsync(() => ConnectButton_Click(ConnectButton, new RoutedEventArgs()));
    }

    public void ActivateFromSecondInstance()
    {
        if (_exitRequested || _shutdownInProgress) return;
        RestoreFromTray();
    }

    private void RestoreFromTray()
    {
        ShowInTaskbar = true;
        if (!IsVisible) Show();
        WindowState = WindowState.Normal;
        Activate();
        Topmost = true;
        Topmost = false;
    }

    private async void ConnectedStatusButton_Click(object sender, RoutedEventArgs e)
    {
        if (!_connected || _activeProfileId is null) return;
        ConnectionDetailsOverlay.Visibility = Visibility.Visible;
        await LoadConnectionDetailsAsync();
    }

    private async void RefreshConnectionDetails_Click(object sender, RoutedEventArgs e)
    {
        if (!_connected) return;
        await LoadConnectionDetailsAsync();
    }

    private void CloseConnectionDetails_Click(object sender, RoutedEventArgs e)
    {
        _connectionInfoCancellation?.Cancel();
        ConnectionDetailsOverlay.Visibility = Visibility.Collapsed;
    }

    private void ConnectionDetailsOverlay_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ReferenceEquals(e.OriginalSource, sender))
            CloseConnectionDetails_Click(sender, new RoutedEventArgs());
    }

    private async Task LoadConnectionDetailsAsync()
    {
        if (!_connected || _activeProfileId is null) return;
        var profile = _profiles.FirstOrDefault(p => p.Id == _activeProfileId);
        if (profile is null) return;

        _connectionInfoCancellation?.Cancel();
        _connectionInfoCancellation?.Dispose();
        _connectionInfoCancellation = new CancellationTokenSource();
        var token = _connectionInfoCancellation.Token;

        ConnectionDetailsContent.Children.Clear();
        AddConnectionDetailRow("Сервер", $"{profile.Server}:{profile.Port}");
        AddConnectionDetailRow("Протокол", profile.Protocol.ToUpperInvariant());
        AddConnectionDetailRow("Внешний IP", L("Загрузка данных подключения…"));

        try
        {
            var info = await _connectionInfoService.GetCurrentAsync(_settings, token);
            if (token.IsCancellationRequested || !_connected) return;
            ConnectionDetailsContent.Children.Clear();
            AddConnectionDetailRow("Сервер", $"{profile.Server}:{profile.Port}");
            AddConnectionDetailRow("Протокол", profile.Protocol.ToUpperInvariant());
            AddConnectionDetailRow("Внешний IP", info.Ip);
            AddConnectionDetailRow("Подсеть", info.Network);
            AddConnectionDetailRow("Версия IP", info.IpVersion);
            AddConnectionDetailRow("Страна", info.Country);
            AddConnectionDetailRow("Регион", info.Region);
            AddConnectionDetailRow("Город", info.City);
            AddConnectionDetailRow("Часовой пояс", info.TimeZone);
            AddConnectionDetailRow("Почтовый индекс", info.PostalCode);
            AddConnectionDetailRow("Широта", info.Latitude);
            AddConnectionDetailRow("Долгота", info.Longitude);
            AddConnectionDetailRow("Провайдер", info.Isp);
            AddConnectionDetailRow("ASN", info.Asn);
            AddConnectionDetailRow("Точность геолокации", info.AccuracyRadius == "—" ? "—" : info.AccuracyRadius + " km");
            AddLog($"Данные текущего подключения получены: {info.Ip} ({info.Country}, {info.City}).");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (token.IsCancellationRequested) return;
            ConnectionDetailsContent.Children.Clear();
            AddConnectionDetailRow("Сервер", $"{profile.Server}:{profile.Port}");
            AddConnectionDetailRow("Протокол", profile.Protocol.ToUpperInvariant());
            AddConnectionDetailRow("Геоданные", L("Не удалось определить геоданные"));
            AddConnectionDetailRow("Причина", ex.Message);
            AddLog("Не удалось получить данные текущего подключения: " + ex.Message);
        }
    }

    private void AddConnectionDetailRow(string label, string value)
    {
        var row = new Grid { Margin = new Thickness(0, 0, 0, 1), MinHeight = 34 };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(190) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var labelText = new TextBlock
        {
            Text = L(label),
            FontSize = 10,
            Foreground = (System.Windows.Media.Brush)FindResource("TextMuted"),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 7, 12, 7)
        };
        var valueText = new TextBlock
        {
            Text = string.IsNullOrWhiteSpace(value) ? "—" : value,
            FontSize = 11,
            Foreground = (System.Windows.Media.Brush)FindResource("TextMain"),
            VerticalAlignment = VerticalAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 7, 0, 7)
        };
        Grid.SetColumn(valueText, 1);
        row.Children.Add(labelText);
        row.Children.Add(valueText);

        var divider = new Border
        {
            BorderBrush = (System.Windows.Media.Brush)FindResource("Line"),
            BorderThickness = new Thickness(0, 0, 0, 1),
            Child = row
        };
        ConnectionDetailsContent.Children.Add(divider);
    }

    private void SaveWindowPlacement()
    {
        if (!_settings.SaveWindowPosition) return;
        var bounds = RestoreBounds;
        if (bounds.Width > 0 && bounds.Height > 0)
        {
            _settings.WindowLeft = bounds.Left;
            _settings.WindowTop = bounds.Top;
            _settings.WindowWidth = bounds.Width;
            _settings.WindowHeight = bounds.Height;
        }
    }

    private void HideToTray()
    {
        if (_exitRequested) return;
        SaveWindowPlacement();
        try { _store.SaveSettings(_settings); } catch { }
        EnsureTrayIcon();
        ShowInTaskbar = false;
        Hide();
    }

    private async void Window_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        // Closing the main window hides it to the tray. The tray menu has the real Exit command.
        if (!_exitRequested)
        {
            e.Cancel = true;
            HideToTray();
            return;
        }

        if (_shutdownComplete) return;
        e.Cancel = true;
        if (_shutdownInProgress) return;
        _shutdownInProgress = true;
        _closing = true;
        _elapsedTimer.Stop();
        _healthTimer.Stop();
        _subscriptionTimer.Stop();
        SaveWindowPlacement();
        try { _systemProxy.Restore(); } catch { }
        try { await _core.StopAsync(); } catch { }
        try { _store.SaveProfiles(_profiles); } catch { }
        try { _store.SaveSettings(_settings); } catch { }
        _http.Dispose();
        _proxyChangeWatcher?.Dispose();
        _proxyChangeWatcher = null;
        if (_trayIcon is not null)
        {
            _trayIcon.Visible = false;
            var trayImage = _trayIcon.Icon;
            _trayIcon.Dispose();
            if (trayImage is not null && !ReferenceEquals(trayImage, _baseTrayIcon)) trayImage.Dispose();
            _trayIcon = null;
        }
        _baseTrayIcon?.Dispose();
        _baseTrayIcon = null;
        _connectionInfoCancellation?.Cancel();
        _shutdownComplete = true;
        Dispatcher.BeginInvoke(new Action(Close));
    }

}
