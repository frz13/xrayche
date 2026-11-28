using System.Text.RegularExpressions;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace XrayHub.Models;

public sealed class ProxyProfile : INotifyPropertyChanged
{
    private string _pingDisplay = string.Empty;
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "Новый профиль";
    public string Protocol { get; set; } = "";
    public string Server { get; set; } = "";
    public int Port { get; set; }
    public string UserId { get; set; } = "";
    public string Password { get; set; } = "";
    public string Method { get; set; } = "";
    // Parsed metadata required by ProfileParser and the server information panel.
    public string Encryption { get; set; } = "";
    public string Alpn { get; set; } = "";
    public string Mode { get; set; } = "";
    public string PacketEncoding { get; set; } = "";
    public string HeaderType { get; set; } = "";
    public string AllowInsecure { get; set; } = "";
    public Dictionary<string, string> RawQueryParameters { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public string RawProtocolDetails { get; set; } = "";
    public int AlterId { get; set; }
    public string Network { get; set; } = "raw";
    public string Security { get; set; } = "none";
    public string Sni { get; set; } = "";
    public string Fingerprint { get; set; } = "chrome";
    public string PublicKey { get; set; } = "";
    public string ShortId { get; set; } = "";
    public string Flow { get; set; } = "";
    public string Host { get; set; } = "";
    public string Path { get; set; } = "";
    public string ServiceName { get; set; } = "";
    public string RawJson { get; set; } = "";
    public string SourceLink { get; set; } = "";
    public string SubscriptionUrl { get; set; } = "";
    /// <summary>Subscription name from the provider (profile-title header), if it was sent.</summary>
    public string SubscriptionTitle { get; set; } = "";

    /// <summary>Group caption in the profile list: provider title, otherwise the subscription host.</summary>
    [JsonIgnore]
    public string SubscriptionGroup
    {
        get
        {
            if (string.IsNullOrWhiteSpace(SubscriptionUrl)) return "Отдельные конфигурации";
            if (!string.IsNullOrWhiteSpace(SubscriptionTitle)) return SubscriptionTitle.Trim();
            if (!Uri.TryCreate(SubscriptionUrl, UriKind.Absolute, out var uri)) return SubscriptionUrl;
            var tail = SubscriptionUrl.TrimEnd('/');
            tail = tail.Length > 4 ? tail[^4..] : tail;
            return $"{uri.Host} · …{tail}";
        }
    }
    public DateTimeOffset? UpdatedAt { get; set; }

    /// <summary>Last measured ICMP Echo latency, or an unavailable marker when no reply is received.</summary>
    [JsonIgnore]
    public string PingDisplay
    {
        get => _pingDisplay;
        set
        {
            if (_pingDisplay == value) return;
            _pingDisplay = value;
            OnPropertyChanged();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private static readonly Regex PrefixRegex = new(
        @"^\s*(?:\[([A-Za-z]{2})\]|([A-Za-z]{2})(?=$|[\s_|·:/\-]))",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex LeadingFlagRegex = new(
        @"^\s*(?:[\uD83C][\uDDE6-\uDDFF]){2}\s*",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex TrailingCountryCodeRegex = new(
        @"(?:[\s_|·:/\-]+|\[)([A-Za-z]{2})\]?\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly (string Code, string[] Names)[] CountryNames =
    [
        ("DE", ["Germany", "Deutschland", "Германия", "ФРГ"]),
        ("US", ["USA", "United States", "United States of America", "США", "Америка"]),
        ("GB", ["UK", "United Kingdom", "Great Britain", "Britain", "Англия", "Великобритания", "Британия"]),
        ("NL", ["Netherlands", "Holland", "Нидерланды", "Голландия"]),
        ("FI", ["Finland", "Финляндия"]), ("FR", ["France", "Франция"]),
        ("SE", ["Sweden", "Швеция"]), ("PL", ["Poland", "Польша"]),
        ("RU", ["Russia", "Russian Federation", "Россия"]), ("UA", ["Ukraine", "Украина"]),
        ("JP", ["Japan", "Япония"]), ("SG", ["Singapore", "Сингапур"]),
        ("TR", ["Turkey", "Türkiye", "Турция"]), ("CA", ["Canada", "Канада"]),
        ("CH", ["Switzerland", "Швейцария"]), ("AT", ["Austria", "Австрия"]),
        ("IT", ["Italy", "Италия"]), ("ES", ["Spain", "Испания"]),
        ("RO", ["Romania", "Румыния"]), ("LV", ["Latvia", "Латвия"]),
        ("EE", ["Estonia", "Эстония"]), ("LT", ["Lithuania", "Литва"]),
        ("CZ", ["Czechia", "Czech Republic", "Чехия"]), ("SK", ["Slovakia", "Словакия"]),
        ("NO", ["Norway", "Норвегия"]), ("DK", ["Denmark", "Дания"]),
        ("BE", ["Belgium", "Бельгия"]), ("LU", ["Luxembourg", "Люксембург"]),
        ("PT", ["Portugal", "Португалия"]), ("IE", ["Ireland", "Ирландия"]),
        ("BR", ["Brazil", "Бразилия"]), ("AU", ["Australia", "Австралия"]),
        ("HK", ["Hong Kong", "Гонконг"]), ("TW", ["Taiwan", "Тайвань"]),
        ("KR", ["South Korea", "Korea", "Южная Корея"]), ("AE", ["UAE", "United Arab Emirates", "ОАЭ"]),
        ("IL", ["Israel", "Израиль"]), ("IN", ["India", "Индия"]),
        ("ID", ["Indonesia", "Индонезия"]), ("TH", ["Thailand", "Таиланд"]),
        ("VN", ["Vietnam", "Вьетнам"]), ("KZ", ["Kazakhstan", "Казахстан"]),
        ("GE", ["Georgia", "Грузия"]), ("MD", ["Moldova", "Молдова"]),
        ("BG", ["Bulgaria", "Болгария"]), ("RS", ["Serbia", "Сербия"]),
        ("GR", ["Greece", "Греция"]), ("IS", ["Iceland", "Исландия"]),
        ("AR", ["Argentina", "Аргентина"]), ("MX", ["Mexico", "Мексика"])
    ];

    public string CountryCode
    {
        get
        {
            var value = Name ?? string.Empty;
            var regionalFlag = Regex.Match(value, @"^\s*([\uD83C][\uDDE6-\uDDFF])([\uD83C][\uDDE6-\uDDFF])");
            if (regionalFlag.Success)
            {
                var first = char.ConvertToUtf32(regionalFlag.Groups[1].Value, 0) - 0x1F1E6 + 'A';
                var second = char.ConvertToUtf32(regionalFlag.Groups[2].Value, 0) - 0x1F1E6 + 'A';
                var code = new string(new[] { (char)first, (char)second });
                return code == "UK" ? "GB" : code;
            }

            var prefix = PrefixRegex.Match(value);
            if (prefix.Success)
            {
                var code = (prefix.Groups[1].Success ? prefix.Groups[1].Value : prefix.Groups[2].Value).ToUpperInvariant();
                return code == "UK" ? "GB" : code;
            }

            var suffix = TrailingCountryCodeRegex.Match(value);
            if (suffix.Success)
            {
                var code = suffix.Groups[1].Value.ToUpperInvariant();
                if (BundledFlagCodes.Contains(code) || code == "UK") return code == "UK" ? "GB" : code;
            }

            foreach (var item in CountryNames)
            foreach (var countryName in item.Names)
            {
                if (Regex.IsMatch(value, @"^\s*" + Regex.Escape(countryName) + @"(?=$|[\s_|·:/\-])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    return item.Code;
                if (Regex.IsMatch(value, @"(?:[,\s_|·:/\-])" + Regex.Escape(countryName) + @"\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    return item.Code;
            }

            return string.Empty;
        }
    }

    // Flag images are used instead of Unicode regional-indicator glyphs: Windows font fallback
    // often renders those as two letters (DE/US) rather than a flag.
    private static readonly HashSet<string> BundledFlagCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        "DE", "US", "GB", "NL", "FI", "FR", "SE", "PL", "RU", "UA", "JP", "SG", "TR", "CA",
        "CH", "AT", "IT", "ES", "RO", "LV", "EE", "LT", "CZ", "SK", "NO", "DK", "BE", "LU",
        "PT", "IE", "BR", "AU", "HK", "TW", "KR", "AE", "IL", "IN", "ID", "TH", "VN", "KZ",
        "GE", "MD", "BG", "RS", "GR", "IS", "AR", "MX"
    };

    public string? CountryFlagImageUrl
    {
        get
        {
            if (CountryCode.Length != 2) return null;
            var code = CountryCode.ToLowerInvariant();
            // Common server locations are bundled, so their flags work offline and do not
            // depend on the browser/proxy being able to reach a flag-image CDN.
            return BundledFlagCodes.Contains(CountryCode)
                ? $"pack://application:,,,/Assets/Flags/{code}.png"
                : $"https://flagcdn.com/w40/{code}.png";
        }
    }

    public string DisplayName
    {
        get
        {
            var value = string.IsNullOrWhiteSpace(Name) ? Server : Name.Trim();
            value = LeadingFlagRegex.Replace(value, string.Empty, 1).Trim();
            var prefix = PrefixRegex.Match(value);
            if (prefix.Success)
                value = value[prefix.Length..].Trim(' ', '|', '-', '_', '·', ':', '/');
            else
            {
                var country = CountryNames.SelectMany(x => x.Names.Select(n => (x.Code, Name: n)))
                    .FirstOrDefault(x => value.StartsWith(x.Name, StringComparison.OrdinalIgnoreCase));
                if (country.Name is not null)
                    value = value[country.Name.Length..].Trim(' ', '|', '-', '_', '·', ':', '/');
            }

            var trailingCode = TrailingCountryCodeRegex.Match(value);
            if (trailingCode.Success && (BundledFlagCodes.Contains(trailingCode.Groups[1].Value) || trailingCode.Groups[1].Value.Equals("UK", StringComparison.OrdinalIgnoreCase)))
                value = value[..trailingCode.Index].Trim(' ', '|', '-', '_', '·', ':', '/');

            foreach (var item in CountryNames)
            foreach (var countryName in item.Names)
            {
                var suffix = Regex.Match(value, @"(?:[,\s_|·:/\-])" + Regex.Escape(countryName) + @"\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (suffix.Success)
                {
                    value = value[..suffix.Index].Trim(' ', '|', '-', '_', '·', ':', '/');
                    break;
                }
            }
            return string.IsNullOrWhiteSpace(value) ? Server : value;
        }
    }

    public string Subtitle => !string.IsNullOrWhiteSpace(Server)
        ? $"{Protocol.ToUpperInvariant()} · {Server}:{Port}"
        : "JSON-конфигурация";

    public string ProtocolDisplay => Protocol.ToLowerInvariant() switch
    {
        "vless" => "VLESS",
        "vmess" => "VMess",
        "trojan" => "Trojan",
        "ss" or "shadowsocks" => "Shadowsocks",
        "json" => "JSON",
        _ => Protocol.ToUpperInvariant()
    };

    public override string ToString() => DisplayName;
}
