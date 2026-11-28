using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace XrayHub.Services;

/// <summary>
/// Event-driven watcher for HKCU Internet Settings. It waits for Windows registry
/// notifications; it does not poll the network or repeatedly inspect the registry.
/// </summary>
public sealed class WindowsProxyChangeWatcher : IDisposable
{
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const uint RegNotifyChangeLastSet = 0x00000004;
    private readonly CancellationTokenSource _cancellation = new();
    private Thread? _thread;
    private int _started;

    public event EventHandler? ProxySettingsChanged;

    public void Start()
    {
        if (Interlocked.Exchange(ref _started, 1) != 0) return;
        _thread = new Thread(WatchLoop)
        {
            IsBackground = true,
            Name = "XrayHub Windows proxy change watcher"
        };
        _thread.Start();
    }

    private void WatchLoop()
    {
        while (!_cancellation.IsCancellationRequested)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: false);
                if (key is null) return;
                using var signal = new AutoResetEvent(false);
                var result = RegNotifyChangeKeyValue(
                    key.Handle, false, RegNotifyChangeLastSet, signal.SafeWaitHandle, true);
                if (result != 0) return;

                var signaled = WaitHandle.WaitAny(new WaitHandle[] { signal, _cancellation.Token.WaitHandle });
                if (signaled == 1 || _cancellation.IsCancellationRequested) return;

                // Registry updates commonly arrive in small batches. Debounce those writes
                // after receiving an actual registry notification (not a polling interval).
                Thread.Sleep(350);
                if (!_cancellation.IsCancellationRequested)
                {
                    try { ProxySettingsChanged?.Invoke(this, EventArgs.Empty); } catch { }
                }
            }
            catch
            {
                // Do not spin if Windows denies registry notification access.
                return;
            }
        }
    }

    public void Dispose()
    {
        _cancellation.Cancel();
        try { _thread?.Join(TimeSpan.FromSeconds(1)); } catch { }
        _cancellation.Dispose();
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegNotifyChangeKeyValue(
        SafeRegistryHandle hKey,
        [MarshalAs(UnmanagedType.Bool)] bool bWatchSubtree,
        uint dwNotifyFilter,
        SafeWaitHandle hEvent,
        [MarshalAs(UnmanagedType.Bool)] bool fAsynchronous);
}
