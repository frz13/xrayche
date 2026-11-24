using System.Diagnostics;
using System.Text.Json;
using XrayHub.Models;

namespace XrayHub.Services;

public sealed class XrayCoreService : IAsyncDisposable
{
    private readonly ProfileStore _store;
    private Process? _process;
    private readonly SemaphoreSlim _gate = new(1, 1);
    public event Action<string>? LogReceived;
    public event Action<bool>? RunningChanged;
    public bool IsRunning => _process is { HasExited: false };

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

            _process = new Process { StartInfo = start, EnableRaisingEvents = true };
            _process.OutputDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) LogReceived?.Invoke(e.Data); };
            _process.ErrorDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) LogReceived?.Invoke(e.Data); };
            _process.Exited += (_, _) => RunningChanged?.Invoke(false);
            if (!_process.Start()) throw new InvalidOperationException("Не удалось запустить xray.exe.");
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
            await Task.Delay(900, cancellationToken);
            if (_process.HasExited)
            {
                var code = _process.ExitCode;
                await StopInternalAsync();
                throw new InvalidOperationException($"Xray завершился при запуске (код {code}). Проверь лог ядра.");
            }
            RunningChanged?.Invoke(true);
            LogReceived?.Invoke($"Xray запущен. Режим: {(tunnelMode ? "TUN" : "Прокси")}");
        }
        finally { _gate.Release(); }
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
            {
                LogReceived?.Invoke("Остановка Xray не дождалась блокировки запуска; интерфейс продолжит работу.");
                return;
            }

            await StopInternalAsync();
        }
        catch (TimeoutException)
        {
            LogReceived?.Invoke("Остановка Xray превысила лимит времени; интерфейс разблокирован.");
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
                LogReceived?.Invoke("Xray ещё работает после запроса остановки; ссылка на процесс сохранена для повторной попытки.");
            }
        }
        catch (Exception ex)
        {
            LogReceived?.Invoke("Ошибка остановки ядра: " + ex.Message);
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
