using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Nodes;
using XrayHub.Models;

namespace XrayHub.Services;

public sealed class XrayCoreService : IAsyncDisposable
{
    private readonly ProfileStore _store;
    private Process? _process;
    private readonly SemaphoreSlim _gate = new(1, 1);
    public event Action<string>? LogReceived;
    public event Action<bool>? RunningChanged;
    public bool IsRunning
    {
        get
        {
            try { return _process is { } process && !process.HasExited; }
            catch { return false; }
        }
    }

    public XrayCoreService(ProfileStore store) => _store = store;

    public async Task StartAsync(ProxyProfile profile, AppSettings settings, bool tunnelMode, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await StopInternalAsync();
            if (!File.Exists(settings.XrayPath))
                throw new FileNotFoundException("Не найден встроенный Xray Core. Проверь, что рядом с XrayHub.exe присутствует папка core с файлом xray.exe.", settings.XrayPath);

            var config = XrayConfigBuilder.Build(profile, settings, tunnelMode);
            var configPath = Path.Combine(_store.RuntimeDirectory, "config.json");
            await File.WriteAllTextAsync(configPath, config.ToJsonString(new JsonSerializerOptions { WriteIndented = true }), cancellationToken);

            // Validate before touching routes or the Windows system proxy.
            var test = await RunValidationAsync(settings.XrayPath, configPath, cancellationToken);
            if (test.ExitCode != 0)
                throw new InvalidOperationException("Xray отклонил конфигурацию:\n" + test.Output);

            // TUN only: remove an orphaned xray.exe / stale adapter left by a crashed earlier run.
            if (tunnelMode)
                await PrepareTunAsync(settings.XrayPath, GetTunName(config), cancellationToken);

            var start = new ProcessStartInfo
            {
                FileName = settings.XrayPath,
                WorkingDirectory = Path.GetDirectoryName(settings.XrayPath) ?? AppContext.BaseDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            start.Environment["XRAY_LOCATION_ASSET"] = Path.GetDirectoryName(settings.XrayPath) ?? AppContext.BaseDirectory;
            start.ArgumentList.Add("run");
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add(configPath);

            var process = new Process { StartInfo = start, EnableRaisingEvents = true };
            _process = process;
            var startedSignal = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            process.OutputDataReceived += (_, e) => HandleCoreLine(e.Data, startedSignal);
            process.ErrorDataReceived += (_, e) => HandleCoreLine(e.Data, startedSignal);
            process.Exited += (_, _) =>
            {
                try { LogReceived?.Invoke($"Процесс Xray завершился. Код выхода: {process.ExitCode}."); }
                catch { LogReceived?.Invoke("Процесс Xray завершился; код выхода получить не удалось."); }
                if (ReferenceEquals(Volatile.Read(ref _process), process))
                    RunningChanged?.Invoke(false);
            };
            if (!process.Start()) throw new InvalidOperationException("Не удалось запустить xray.exe.");
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await Task.Delay(900, cancellationToken);
            if (process.HasExited)
            {
                var code = process.ExitCode;
                if (tunnelMode) _tunDirty = true;
                await StopInternalAsync();
                throw new InvalidOperationException($"Xray завершился при запуске (код {code}). Проверь лог ядра.");
            }

            // In TUN mode the SOCKS inbound answers long before the Windows adapter is actually
            // created. Xray can still die ~10-15 s later with "Failed to setup adapter" (0xB7).
            // Do not report success until Xray itself says it started (or the adapter is really up).
            if (tunnelMode)
            {
                LogReceived?.Invoke("Ожидание создания TUN-адаптера…");
                var tunName = GetTunName(config);
                var tunIp = settings.TunAddress.Split('/')[0];
                var deadline = DateTime.UtcNow + TunReadyTimeout;
                var ready = false;
                while (DateTime.UtcNow < deadline)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (process.HasExited) break;
                    if (startedSignal.Task.IsCompleted || IsTunAdapterUp(tunName, tunIp)) { ready = true; break; }
                    await Task.Delay(250, cancellationToken);
                }

                if (!ready)
                {
                    var exited = process.HasExited;
                    var exitCode = exited ? process.ExitCode : 0;
                    _tunDirty = true;
                    await StopInternalAsync();
                    throw new InvalidOperationException(exited
                        ? $"Xray завершился при запуске (код {exitCode}): не удалось создать TUN-адаптер. Проверь лог ядра."
                        : $"Xray завершился при запуске: TUN-адаптер не создан за {(int)TunReadyTimeout.TotalSeconds} с.");
                }
            }

            RunningChanged?.Invoke(true);
            LogReceived?.Invoke($"Xray запущен. Режим: {(tunnelMode ? "TUN" : "Прокси")}");
        }
        finally { _gate.Release(); }
    }

    private static readonly TimeSpan TunReadyTimeout = TimeSpan.FromSeconds(30);

    private void HandleCoreLine(string? line, TaskCompletionSource<bool> startedSignal)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        LogReceived?.Invoke(line);
        // Xray prints "[Warning] core: Xray <version> started" once every inbound (including TUN) is up.
        if (line.Contains("core: Xray", StringComparison.Ordinal) && line.TrimEnd().EndsWith("started", StringComparison.Ordinal))
            startedSignal.TrySetResult(true);
    }

    private static string GetTunName(JsonObject config)
    {
        try
        {
            if (config["inbounds"] is JsonArray inbounds)
            {
                foreach (var inbound in inbounds.OfType<JsonObject>())
                {
                    if (!string.Equals(inbound["protocol"]?.GetValue<string>(), "tun", StringComparison.OrdinalIgnoreCase)) continue;
                    var name = inbound["settings"]?["name"]?.GetValue<string>();
                    if (!string.IsNullOrWhiteSpace(name)) return name;
                }
            }
        }
        catch { }
        return "XrayHub";
    }

    private static bool IsTunAdapterUp(string name, string ipv4)
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!string.Equals(nic.Name, name, StringComparison.OrdinalIgnoreCase)) continue;
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.GetIPProperties().UnicastAddresses.Any(a => a.Address.ToString() == ipv4)) return true;
            }
        }
        catch { }
        return false;
    }

    // True until a cleanup has run in this session, and again after any failed TUN start.
    private bool _tunDirty = true;

    private async Task PrepareTunAsync(string xrayPath, string tunName, CancellationToken token)
    {
        try
        {
            // 1) An orphaned xray.exe (from a crashed earlier XrayHub) keeps the adapter busy -> 0xB7.
            var fullPath = Path.GetFullPath(xrayPath);
            foreach (var other in Process.GetProcessesByName("xray"))
            {
                try
                {
                    using (other)
                    {
                        var path = other.MainModule?.FileName;
                        if (path is not null && string.Equals(Path.GetFullPath(path), fullPath, StringComparison.OrdinalIgnoreCase))
                        {
                            LogReceived?.Invoke($"Найден незавершённый xray.exe от прошлого запуска (PID {other.Id}); завершаю.");
                            other.Kill(entireProcessTree: true);
                            await other.WaitForExitAsync(token).WaitAsync(TimeSpan.FromSeconds(4), token);
                        }
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { }
            }

            // 2) A leftover adapter with our name. Only when it is visible, or after a failed start,
            //    so the normal connect path does not pay for starting PowerShell.
            var visible = NetworkInterface.GetAllNetworkInterfaces()
                .Any(n => string.Equals(n.Name, tunName, StringComparison.OrdinalIgnoreCase));
            if (!visible && !_tunDirty) return;
            if (!IsSafeAdapterName(tunName)) return;

            LogReceived?.Invoke("Очистка возможных остатков TUN-адаптера перед запуском…");
            var script =
                "$ErrorActionPreference='SilentlyContinue';" +
                $"$a=@(Get-NetAdapter -Name '{tunName}' -IncludeHidden);" +
                "foreach($x in $a){ if($x.PnPDeviceID){ pnputil /remove-device $x.PnPDeviceID | Out-Null } };" +
                "if($a.Count -gt 0){ Start-Sleep -Milliseconds 800;" +
                $" $b=@(Get-NetAdapter -Name '{tunName}' -IncludeHidden); if($b.Count -gt 0){ $b | Remove-NetAdapter -Confirm:$false } }";
            await RunPowerShellAsync(script, TimeSpan.FromSeconds(12), token);
            _tunDirty = false;
            if (visible) await Task.Delay(1000, token);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Best effort: never block a connection because cleanup failed.
            LogReceived?.Invoke("Очистка TUN-адаптера не выполнена: " + ex.Message);
        }
    }

    private static bool IsSafeAdapterName(string name) =>
        !string.IsNullOrWhiteSpace(name) && name.All(c => char.IsLetterOrDigit(c) || c is ' ' or '-' or '_' or '.');

    private static async Task RunPowerShellAsync(string script, TimeSpan timeout, CancellationToken token)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("Bypass");
        psi.ArgumentList.Add("-Command");
        psi.ArgumentList.Add(script);
        using var process = Process.Start(psi);
        if (process is null) return;
        _ = process.StandardOutput.ReadToEndAsync();
        _ = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync(token).WaitAsync(timeout, token); }
        catch (TimeoutException)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
        }
    }

    public async Task StopAsync()
    {
        // Never let a stuck process or an in-progress start operation freeze the UI.
        // If StartAsync currently owns the gate, give it a short chance to finish.
        var acquired = false;
        try
        {
            acquired = await _gate.WaitAsync(TimeSpan.FromSeconds(2));
            if (!acquired)
                throw new TimeoutException("Не удалось получить блокировку Xray за 2 секунды; предыдущая операция ещё выполняется.");

            await StopInternalAsync();
        }
        catch (TimeoutException ex)
        {
            LogReceived?.Invoke("Остановка Xray не подтверждена: " + ex.Message);
            throw;
        }
        finally
        {
            if (acquired) _gate.Release();
        }
    }

    private async Task StopInternalAsync()
    {
        var process = _process;
        if (process is null) return;

        try
        {
            if (!process.HasExited)
            {
                // Kill(entireProcessTree) can itself block on Windows. Run it away from
                // the dispatcher and bound both the kill request and process wait.
                await Task.Run(() =>
                {
                    try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                    catch (InvalidOperationException) { }
                }).WaitAsync(TimeSpan.FromSeconds(2));
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(4));
            }

            if (process.HasExited)
            {
                process.Dispose();
                if (ReferenceEquals(_process, process)) _process = null;
            }
            else
            {
                throw new TimeoutException("Xray продолжает работать после запроса остановки.");
            }
        }
        catch (Exception ex)
        {
            LogReceived?.Invoke("Ошибка остановки ядра: " + ex.Message);
            throw;
        }
        finally
        {
            RunningChanged?.Invoke(_process is { HasExited: false });
        }
    }

    private static async Task<(int ExitCode, string Output)> RunValidationAsync(string executable, string config, CancellationToken token)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = Path.GetDirectoryName(executable) ?? AppContext.BaseDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.Environment["XRAY_LOCATION_ASSET"] = Path.GetDirectoryName(executable) ?? AppContext.BaseDirectory;
        start.ArgumentList.Add("run");
        start.ArgumentList.Add("-test");
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add(config);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Не удалось проверить конфигурацию Xray.");
        var stdout = process.StandardOutput.ReadToEndAsync(token);
        var stderr = process.StandardError.ReadToEndAsync(token);
        try
        {
            await process.WaitForExitAsync(token).WaitAsync(TimeSpan.FromSeconds(15), token);
        }
        catch
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            throw;
        }
        var output = (await stdout) + Environment.NewLine + (await stderr);
        return (process.ExitCode, output.Trim());
    }

    public async ValueTask DisposeAsync() => await StopAsync();
}
