using System.Text;
using System.Text.Json;
using XrayHub.Models;

namespace XrayHub.Services;

/// <summary>Parses common Xray share links and Base64/plain-text subscriptions.</summary>
public static class ProfileParser
{
    public static ProxyProfile ParseLink(string input)
    {
        var text = input.Trim();
        if (text.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
            return ParseVmess(text);

        var separator = text.IndexOf("://", StringComparison.Ordinal);
        if (separator <= 0) throw new FormatException("Неизвестный формат ссылки.");

        var scheme = text[..separator].ToLowerInvariant();
        if (scheme is "ss" or "shadowsocks") return ParseShadowsocks(text);
        if (scheme is not ("vless" or "trojan"))
            throw new NotSupportedException($"Протокол {scheme} пока не реализован в первой версии XrayHub.");

        var uriText = text;
        if (!Uri.TryCreate(uriText, UriKind.Absolute, out var uri))
            throw new FormatException("Не удалось разобрать ссылку. Проверьте адрес, порт и параметры.");

        var profile = new ProxyProfile
        {
            Protocol = scheme,
            Server = uri.Host,
            Port = uri.Port,
            Name = DecodeFragment(uri.Fragment),
            SourceLink = text,
            Network = "raw"
        };

        var userInfo = Uri.UnescapeDataString(uri.UserInfo);
        if (scheme is "vless" or "trojan")
        {
            if (scheme == "vless") profile.UserId = userInfo;
            else profile.Password = userInfo;
        }

        var q = ParseQuery(uri.Query);
        profile.Security = Get(q, "security", scheme == "trojan" ? "tls" : "none").ToLowerInvariant();
        profile.Encryption = Get(q, "encryption", scheme == "vless" ? "none" : "");
        profile.Network = NormalizeNetwork(Get(q, "type", Get(q, "network", "raw")));
        profile.Sni = Get(q, "sni", Get(q, "servername", Get(q, "serverName", "")));
        profile.Fingerprint = Get(q, "fp", "chrome");
        profile.Alpn = Get(q, "alpn", "");
        profile.PublicKey = Get(q, "pbk", Get(q, "publicKey", ""));
        profile.ShortId = Get(q, "sid", Get(q, "shortId", ""));
        profile.Flow = Get(q, "flow", "");
        profile.Host = Get(q, "host", "");
        profile.Path = Get(q, "path", "");
        profile.ServiceName = Get(q, "serviceName", Get(q, "service_name", ""));
        profile.Mode = Get(q, "mode", "");
        profile.PacketEncoding = Get(q, "packetEncoding", Get(q, "packet_encoding", ""));
        profile.HeaderType = Get(q, "headerType", Get(q, "header_type", ""));
        profile.AllowInsecure = Get(q, "allowInsecure", Get(q, "insecure", ""));
        profile.RawQueryParameters = new Dictionary<string, string>(q, StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(profile.Name))
            profile.Name = $"{profile.Protocol.ToUpperInvariant()} · {profile.Server}";
        if (profile.Port is < 1 or > 65535)
            throw new FormatException("Порт должен быть от 1 до 65535.");
        if (scheme == "vless" && string.IsNullOrWhiteSpace(profile.UserId))
            throw new FormatException("В ссылке VLESS отсутствует UUID.");
        if (scheme == "trojan" && string.IsNullOrWhiteSpace(profile.Password))
            throw new FormatException("В ссылке Trojan отсутствует пароль.");
        return profile;
    }


    private static ProxyProfile ParseShadowsocks(string text)
    {
        var body = text[(text.IndexOf("://", StringComparison.Ordinal) + 3)..].Trim();
        var fragmentIndex = body.IndexOf('#');
        var name = fragmentIndex >= 0 ? DecodeFragment(body[fragmentIndex..]) : "";
        if (fragmentIndex >= 0) body = body[..fragmentIndex];
        var queryIndex = body.IndexOf('?');
        var query = queryIndex >= 0 ? body[(queryIndex + 1)..] : "";
        if (queryIndex >= 0) body = body[..queryIndex];

        string credentials;
        string endpoint;
        var at = body.LastIndexOf('@');
        if (at >= 0)
        {
            credentials = body[..at];
            endpoint = body[(at + 1)..];
        }
        else
        {
            var decodedWhole = TryDecodeBase64(body) ?? throw new FormatException("Не удалось декодировать ссылку Shadowsocks.");
            at = decodedWhole.LastIndexOf('@');
            if (at < 0) throw new FormatException("В ссылке Shadowsocks отсутствует разделитель @.");
            credentials = decodedWhole[..at];
            endpoint = decodedWhole[(at + 1)..];
        }

        credentials = Uri.UnescapeDataString(credentials);
        credentials = TryDecodeBase64(credentials) ?? credentials;
        var colon = credentials.IndexOf(':');
        if (colon <= 0) throw new FormatException("Неверные данные Shadowsocks: ожидается method:password.");
        if (!Uri.TryCreate("ss://" + endpoint, UriKind.Absolute, out var endpointUri) || endpointUri.Port is < 1 or > 65535)
            throw new FormatException("В ссылке Shadowsocks некорректный сервер или порт.");

        var profile = new ProxyProfile
        {
            Protocol = "shadowsocks", Server = endpointUri.Host, Port = endpointUri.Port,
            Method = credentials[..colon], Password = credentials[(colon + 1)..],
            Name = string.IsNullOrWhiteSpace(name) ? $"Shadowsocks · {endpointUri.Host}" : name,
            SourceLink = text, Network = "raw", Security = "none"
        };
        if (!string.IsNullOrWhiteSpace(query))
        {
            var options = ParseQuery("?" + query);
            profile.RawQueryParameters = new Dictionary<string, string>(options, StringComparer.OrdinalIgnoreCase);
            if (options.TryGetValue("plugin", out var plugin) && !string.IsNullOrWhiteSpace(plugin))
                throw new NotSupportedException("Shadowsocks SIP002 plugin-параметры пока не поддерживаются.");
        }
        return profile;
    }

    public static ProxyProfile ParseVmess(string text)
    {
        var payload = text["vmess://".Length..].Trim();
        var decoded = TryDecodeBase64(payload) ?? throw new FormatException("Не удалось декодировать ссылку VMess.");
        using var document = JsonDocument.Parse(decoded);
        var root = document.RootElement;
        var profile = new ProxyProfile
        {
            Protocol = "vmess",
            Server = ReadString(root, "add"),
            Port = ReadInt(root, "port"),
            UserId = ReadString(root, "id"),
            AlterId = ReadInt(root, "aid"),
            Method = ReadString(root, "scy", "auto"),
            Encryption = ReadString(root, "encryption", ReadString(root, "scy", "auto")),
            Network = NormalizeNetwork(ReadString(root, "net", "raw")),
            Security = ReadString(root, "tls", "").Equals("tls", StringComparison.OrdinalIgnoreCase) ? "tls" : "none",
            Sni = ReadString(root, "sni"),
            Fingerprint = ReadString(root, "fp", "chrome"),
            Alpn = ReadStringOrArray(root, "alpn"),
            Host = ReadString(root, "host"),
            Path = ReadString(root, "path"),
            ServiceName = ReadString(root, "serviceName"),
            Mode = ReadString(root, "mode"),
            PacketEncoding = ReadString(root, "packetEncoding"),
            HeaderType = ReadString(root, "headerType"),
            Name = ReadString(root, "ps", "VMess"),
            SourceLink = text,
            RawProtocolDetails = decoded,
            RawQueryParameters = root.EnumerateObject().ToDictionary(x => x.Name, x => x.Value.ToString(), StringComparer.OrdinalIgnoreCase)
        };
        if (string.IsNullOrWhiteSpace(profile.Server) || profile.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(profile.UserId))
            throw new FormatException("В ссылке VMess не хватает адреса, порта или UUID.");
        return profile;
    }

    public static IReadOnlyList<ProxyProfile> ParseSubscription(string content, string sourceUrl = "")
    {
        var text = content.Trim().TrimStart('\uFEFF');
        if (string.IsNullOrWhiteSpace(text)) return [];

        // A subscription may be Base64-encoded UTF-8. Only use the decoded text if it resembles links/JSON.
        var decoded = TryDecodeBase64(text);
        if (!string.IsNullOrWhiteSpace(decoded) && (decoded.Contains("://", StringComparison.Ordinal) || decoded.TrimStart().StartsWith('{') || decoded.TrimStart().StartsWith('[')))
            text = decoded;

        var results = new List<ProxyProfile>();
        var trimmed = text.Trim();
        if (trimmed.StartsWith('{') && trimmed.Contains("\"outbounds\"", StringComparison.OrdinalIgnoreCase))
        {
            results.Add(new ProxyProfile
            {
                Name = "Импортированный JSON",
                Protocol = "json",
                RawJson = trimmed,
                SourceLink = sourceUrl,
                SubscriptionUrl = sourceUrl
            });
            return results;
        }

        foreach (var line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!line.Contains("://", StringComparison.Ordinal)) continue;
            try
            {
                var profile = ParseLink(line);
                profile.SubscriptionUrl = sourceUrl;
                results.Add(profile);
            }
            catch (NotSupportedException) { /* Keep unsupported schemes out of the active list until their engine is implemented. */ }
            catch (FormatException) { /* Ignore malformed rows but continue parsing the subscription. */ }
        }
        return results;
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var pair = item.Split('=', 2);
            var key = Uri.UnescapeDataString(pair[0].Replace('+', ' '));
            var value = pair.Length > 1 ? Uri.UnescapeDataString(pair[1].Replace('+', ' ')) : "";
            result[key] = value;
        }
        return result;
    }

    private static string Get(Dictionary<string, string> data, string key, string fallback) =>
        data.TryGetValue(key, out var value) ? value : fallback;

    private static string DecodeFragment(string fragment) =>
        string.IsNullOrWhiteSpace(fragment) ? "" : Uri.UnescapeDataString(fragment.TrimStart('#').Replace('+', ' '));

    private static string NormalizeNetwork(string network) => network.ToLowerInvariant() switch
    {
        "tcp" => "raw",
        "http" => "xhttp",
        "ws" => "ws",
        "websocket" => "ws",
        "grpc" => "grpc",
        "xhttp" => "xhttp",
        "httpupgrade" => "httpupgrade",
        "kcp" or "mkcp" => "kcp",
        _ => string.IsNullOrWhiteSpace(network) ? "raw" : network.ToLowerInvariant()
    };

    private static string? TryDecodeBase64(string value)
    {
        try
        {
            var normalized = value.Trim().Replace('-', '+').Replace('_', '/');
            normalized = normalized.PadRight(normalized.Length + (4 - normalized.Length % 4) % 4, '=');
            return Encoding.UTF8.GetString(Convert.FromBase64String(normalized)).Trim('\0', '\r', '\n', ' ');
        }
        catch { return null; }
    }

    private static string ReadString(JsonElement element, string property, string fallback = "")
    {
        if (!element.TryGetProperty(property, out var value)) return fallback;
        return value.ValueKind == JsonValueKind.String ? value.GetString() ?? fallback : value.ToString();
    }

    private static string ReadStringOrArray(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value)) return "";
        return value.ValueKind == JsonValueKind.Array
            ? string.Join(", ", value.EnumerateArray().Select(x => x.ToString()))
            : value.ToString();
    }

    private static int ReadInt(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value)) return 0;
        return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number)
            ? number
            : int.TryParse(value.ToString(), out var parsed) ? parsed : 0;
    }
}
