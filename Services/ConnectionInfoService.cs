using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using XrayHub.Models;

namespace XrayHub.Services;

public sealed record ConnectionInfo(
    string Ip,
    string IpVersion,
    string Network,
    string Country,
    string Region,
    string City,
    string TimeZone,
    string PostalCode,
    string Latitude,
    string Longitude,
    string Isp,
    string Asn,
    string AccuracyRadius);

/// <summary>
/// Looks up the public egress IP and approximate IP geolocation through the active
/// XrayHub SOCKS5 inbound, so the lookup follows the currently selected Xray route.
/// </summary>
public sealed class ConnectionInfoService
{
    public async Task<ConnectionInfo> GetCurrentAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(18));

        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = true,
            ConnectTimeout = TimeSpan.FromSeconds(8),
            PooledConnectionLifetime = TimeSpan.FromMinutes(1),
            ConnectCallback = (context, token) => ConnectThroughSocksAsync(context, settings, token)
        };

        using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("XrayHub/0.3.5");

        using var geoResponse = await client.GetAsync("https://ipwho.is/", HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        geoResponse.EnsureSuccessStatusCode();
        await using var geoStream = await geoResponse.Content.ReadAsStreamAsync(timeout.Token);
        using var geoDocument = await JsonDocument.ParseAsync(geoStream, cancellationToken: timeout.Token);
        var root = geoDocument.RootElement;

        if (TryGet(root, "success", out var success) && success.ValueKind == JsonValueKind.False)
        {
            var message = GetString(root, "message");
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(message)
                ? "Сервис геолокации не смог определить внешний IP."
                : "Сервис геолокации: " + message);
        }

        var ip = GetString(root, "ip");
        if (!IPAddress.TryParse(ip, out _))
            throw new InvalidOperationException("Сервис геолокации вернул некорректный IP-адрес.");

        var connection = GetObject(root, "connection");
        var timezone = GetObject(root, "timezone");
        var network = await TryGetNetworkCidrAsync(client, ip, timeout.Token);

        return new ConnectionInfo(
            Ip: ip,
            IpVersion: ValueOrDash(GetString(root, "type")),
            Network: ValueOrDash(network),
            Country: ValueOrDash(GetString(root, "country")),
            Region: ValueOrDash(GetString(root, "region")),
            City: ValueOrDash(GetString(root, "city")),
            TimeZone: ValueOrDash(GetString(timezone, "id")),
            PostalCode: ValueOrDash(GetString(root, "postal")),
            Latitude: GetNumber(root, "latitude"),
            Longitude: GetNumber(root, "longitude"),
            Isp: ValueOrDash(GetString(connection, "isp")),
            Asn: ValueOrDash(GetScalarString(connection, "asn")),
            AccuracyRadius: GetNumber(root, "accuracy_radius"));
    }

    private static async Task<string> TryGetNetworkCidrAsync(HttpClient client, string ip, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await client.GetAsync(
                "https://rdap.org/ip/" + Uri.EscapeDataString(ip),
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);
            if (!response.IsSuccessStatusCode) return "—";
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            var root = document.RootElement;

            if (TryGet(root, "cidr0_cidrs", out var cidrs) && cidrs.ValueKind == JsonValueKind.Array)
            {
                foreach (var cidr in cidrs.EnumerateArray())
                {
                    var prefix = GetString(cidr, "v4prefix");
                    if (string.IsNullOrWhiteSpace(prefix)) prefix = GetString(cidr, "v6prefix");
                    var length = GetScalarString(cidr, "length");
                    if (!string.IsNullOrWhiteSpace(prefix) && !string.IsNullOrWhiteSpace(length))
                        return prefix + "/" + length;
                }
            }

            var start = GetString(root, "startAddress");
            var end = GetString(root, "endAddress");
            if (!string.IsNullOrWhiteSpace(start) && !string.IsNullOrWhiteSpace(end))
                return start + " – " + end;
        }
        catch
        {
            // RDAP data is supplementary. Keep the egress IP and geolocation even if
            // the registrar does not expose a CIDR range or the RDAP service is offline.
        }

        return "—";
    }

    private static async ValueTask<Stream> ConnectThroughSocksAsync(
        SocketsHttpConnectionContext context,
        AppSettings settings,
        CancellationToken cancellationToken)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        NetworkStream? stream = null;
        try
        {
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, settings.SocksPort), cancellationToken);
            stream = new NetworkStream(socket, ownsSocket: true);

            var useAuthentication = settings.SocksAuthentication;
            await stream.WriteAsync(useAuthentication
                ? new byte[] { 0x05, 0x01, 0x02 }
                : new byte[] { 0x05, 0x01, 0x00 }, cancellationToken);

            var methodReply = new byte[2];
            await ReadExactlyAsync(stream, methodReply, cancellationToken);
            if (methodReply[0] != 0x05 || methodReply[1] == 0xFF)
                throw new IOException("Локальный SOCKS5 не принял метод авторизации.");

            if (methodReply[1] == 0x02)
            {
                var user = Encoding.UTF8.GetBytes(settings.SocksUsername ?? string.Empty);
                var password = Encoding.UTF8.GetBytes(settings.SocksPassword ?? string.Empty);
                if (user.Length is 0 or > 255 || password.Length is 0 or > 255)
                    throw new IOException("Некорректные SOCKS5 учётные данные.");

                var auth = new byte[3 + user.Length + password.Length];
                auth[0] = 0x01;
                auth[1] = (byte)user.Length;
                Buffer.BlockCopy(user, 0, auth, 2, user.Length);
                auth[2 + user.Length] = (byte)password.Length;
                Buffer.BlockCopy(password, 0, auth, 3 + user.Length, password.Length);
                await stream.WriteAsync(auth, cancellationToken);

                var authReply = new byte[2];
                await ReadExactlyAsync(stream, authReply, cancellationToken);
                if (authReply[0] != 0x01 || authReply[1] != 0x00)
                    throw new IOException("Локальный SOCKS5 отклонил логин или пароль.");
            }
            else if (methodReply[1] != 0x00)
            {
                throw new IOException("Локальный SOCKS5 выбрал неподдерживаемый метод авторизации.");
            }

            var request = BuildSocksConnectRequest(context.DnsEndPoint);
            await stream.WriteAsync(request, cancellationToken);

            var replyHeader = new byte[4];
            await ReadExactlyAsync(stream, replyHeader, cancellationToken);
            if (replyHeader[0] != 0x05 || replyHeader[1] != 0x00)
                throw new IOException($"SOCKS5 не смог подключиться к {context.DnsEndPoint.Host}:{context.DnsEndPoint.Port} (код {replyHeader[1]}).");

            var addressLength = replyHeader[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => await ReadDomainLengthAsync(stream, cancellationToken),
                _ => throw new IOException("Некорректный SOCKS5 ответ.")
            };
            var discard = new byte[addressLength + 2]; // bound address plus bound port
            await ReadExactlyAsync(stream, discard, cancellationToken);

            var result = stream;
            stream = null;
            return result;
        }
        catch
        {
            if (stream is not null) await stream.DisposeAsync();
            else socket.Dispose();
            throw;
        }
    }

    private static byte[] BuildSocksConnectRequest(DnsEndPoint endpoint)
    {
        var host = endpoint.Host.Trim('[', ']');
        byte addressType;
        byte[] addressBytes;
        if (IPAddress.TryParse(host, out var ip))
        {
            addressType = ip.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
            addressBytes = ip.GetAddressBytes();
        }
        else
        {
            var asciiHost = new IdnMapping().GetAscii(host);
            addressBytes = Encoding.ASCII.GetBytes(asciiHost);
            if (addressBytes.Length is 0 or > 255) throw new IOException("Имя хоста слишком длинное для SOCKS5.");
            addressType = 0x03;
        }

        var domainLength = addressType == 0x03 ? 1 : 0;
        var request = new byte[4 + domainLength + addressBytes.Length + 2];
        request[0] = 0x05;
        request[1] = 0x01; // CONNECT
        request[2] = 0x00;
        request[3] = addressType;
        var offset = 4;
        if (addressType == 0x03) request[offset++] = (byte)addressBytes.Length;
        Buffer.BlockCopy(addressBytes, 0, request, offset, addressBytes.Length);
        offset += addressBytes.Length;
        request[offset++] = (byte)(endpoint.Port >> 8);
        request[offset] = (byte)(endpoint.Port & 0xFF);
        return request;
    }

    private static async Task<int> ReadDomainLengthAsync(Stream stream, CancellationToken cancellationToken)
    {
        var length = new byte[1];
        await ReadExactlyAsync(stream, length, cancellationToken);
        return length[0];
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken);
            if (read == 0) throw new EndOfStreamException("Локальный SOCKS5 закрыл соединение во время рукопожатия.");
            offset += read;
        }
    }

    private static JsonElement GetObject(JsonElement parent, string name) =>
        TryGet(parent, name, out var value) && value.ValueKind == JsonValueKind.Object ? value : default;

    private static bool TryGet(JsonElement parent, string name, out JsonElement value)
    {
        if (parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out value)) return true;
        value = default;
        return false;
    }

    private static string GetString(JsonElement parent, string name) =>
        TryGet(parent, name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;

    private static string GetScalarString(JsonElement parent, string name)
    {
        if (!TryGet(parent, name, out var value)) return string.Empty;
        return value.ValueKind is JsonValueKind.String or JsonValueKind.Number ? value.ToString() : string.Empty;
    }

    private static string GetNumber(JsonElement parent, string name)
    {
        if (!TryGet(parent, name, out var value)) return "—";
        return value.ValueKind == JsonValueKind.Number
            ? value.GetDouble().ToString("0.######", CultureInfo.InvariantCulture)
            : "—";
    }

    private static string ValueOrDash(string? value) => string.IsNullOrWhiteSpace(value) ? "—" : value.Trim();
}
