using System.Net;
using System.Net.Http;

namespace XrayHub.Services;

public sealed class ConnectionDiagnostics
{
    public async Task<(bool YouTube, bool Google, string Message)> ProbeAsync(int httpProxyPort, CancellationToken token = default)
    {
        var proxy = new WebProxy($"http://127.0.0.1:{httpProxyPort}");
        using var handler = new HttpClientHandler { Proxy = proxy, UseProxy = true };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        var youtube = await ProbeUrlAsync(client, "https://www.youtube.com/generate_204", token);
        var google = await ProbeUrlAsync(client, "https://www.google.com/generate_204", token);
        var message = youtube && google ? "YouTube и Google отвечают через Xray."
            : !youtube && google ? "Google доступен, YouTube не отвечает через прокси: проверь доменные правила, DNS и UDP/QUIC."
            : youtube && !google ? "YouTube доступен, Google не отвечает через прокси."
            : "Оба контрольных адреса не ответили через локальный HTTP-прокси.";
        return (youtube, google, message);
    }

    private static async Task<bool> ProbeUrlAsync(HttpClient client, string url, CancellationToken token)
    {
        try
        {
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token);
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }
}
