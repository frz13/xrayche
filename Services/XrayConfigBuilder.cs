using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using XrayHub.Models;

namespace XrayHub.Services;

public static class XrayConfigBuilder
{
    public static JsonObject Build(ProxyProfile profile, AppSettings settings, bool tunnelMode)
    {
        if (!string.IsNullOrWhiteSpace(profile.RawJson))
        {
            var imported = NormalizeImportedJson(profile.RawJson, settings, tunnelMode);
            ApplyApplicationSettings(imported, settings, tunnelMode);
            return imported;
        }

        var outbound = BuildProxyOutbound(profile);
        var inbounds = new JsonArray
        {
            new JsonObject
            {
                ["tag"] = "socks-in", ["listen"] = "127.0.0.1", ["port"] = settings.SocksPort,
                ["protocol"] = "socks",
                ["settings"] = BuildSocksSettings(settings),
                ["sniffing"] = BuildSniffing()
            },
            new JsonObject
            {
                ["tag"] = "http-in", ["listen"] = "127.0.0.1", ["port"] = settings.HttpPort,
                ["protocol"] = "http", ["settings"] = new JsonObject(),
                ["sniffing"] = BuildSniffing()
            }
        };

        if (tunnelMode)
        {
            inbounds.Add(new JsonObject
            {
                ["tag"] = "tun-in",
                ["protocol"] = "tun",
                // TUN traffic arrives as bare IPs; sniffing recovers the domain so custom domain rules (e.g. YouTube) can match.
                ["sniffing"] = BuildSniffing(),
                ["settings"] = new JsonObject
                {
                    ["name"] = "XrayHub",
                    ["desc"] = "XrayHub Tunnel",
                    ["mtu"] = settings.TunMtu,
                    ["gateway"] = new JsonArray(settings.TunAddress),
                    ["dns"] = BuildDnsServers(settings),
                    ["autoSystemRoutingTable"] = new JsonArray("0.0.0.0/0", "::/0"),
                    ["autoOutboundsInterface"] = "auto",
                    // WFP leak filters are configurable in the Traffic Rules page.
                    ["autoSystemWfpBlockLeak"] = settings.ProtectDnsLeaks
                        ? new JsonArray("dns", "misconfigtun") : new JsonArray()
                }
            });
        }

        var outbounds = new JsonArray
        {
            outbound,
            new JsonObject { ["tag"] = "direct", ["protocol"] = "freedom", ["settings"] = new JsonObject() },
            new JsonObject { ["tag"] = "blocked", ["protocol"] = "blackhole", ["settings"] = new JsonObject() },
            new JsonObject { ["tag"] = "dns-out", ["protocol"] = "dns", ["settings"] = new JsonObject() }
        };

        var rules = new JsonArray();
        if (tunnelMode)
        {
            rules.Add(new JsonObject
            {
                ["type"] = "field", ["inboundTag"] = new JsonArray("tun-in"), ["port"] = "53", ["outboundTag"] = "dns-out"
            });
            if (settings.DisableQuic)
            {
                // Diagnostic compatibility option: reject QUIC so browsers retry over TCP/TLS.
                rules.Add(new JsonObject
                {
                    ["type"] = "field", ["network"] = "udp", ["port"] = "443", ["outboundTag"] = "blocked"
                });
            }
            if (settings.BypassPrivateNetworks)
            {
                rules.Add(new JsonObject
                {
                    ["type"] = "field", ["ip"] = new JsonArray("geoip:private"), ["outboundTag"] = "direct"
                });
            }
        }

        var config = new JsonObject
        {
            ["log"] = new JsonObject { ["loglevel"] = "warning" },
            ["dns"] = new JsonObject
            {
                ["servers"] = BuildDnsServers(settings),
                ["queryStrategy"] = "UseIP",
                ["serveStale"] = true,
                ["serveExpiredTTL"] = 300,
                ["enableParallelQuery"] = true
            },
            ["inbounds"] = inbounds,
            ["outbounds"] = outbounds,
            ["routing"] = new JsonObject
            {
                ["domainStrategy"] = "IPIfNonMatch",
                ["rules"] = rules
            }
        };
        ApplyApplicationSettings(config, settings, tunnelMode);
        return config;
    }

    private static JsonObject BuildSniffing() => new()
    {
        ["enabled"] = true,
        ["destOverride"] = new JsonArray("http", "tls", "quic"),
        // routeOnly: only used for routing decisions, the real destination is not rewritten.
        ["routeOnly"] = true
    };

    private static JsonObject BuildSocksSettings(AppSettings settings)
    {
        var socks = new JsonObject { ["auth"] = settings.SocksAuthentication ? "password" : "noauth", ["udp"] = true, ["ip"] = "127.0.0.1" };
        if (settings.SocksAuthentication)
        {
            socks["accounts"] = new JsonArray(new JsonObject
            {
                ["user"] = settings.SocksUsername,
                ["pass"] = settings.SocksPassword
            });
        }
        return socks;
    }

    private static void ApplyCoreOutboundSettings(JsonObject outbound, AppSettings settings)
    {
        outbound["mux"] = new JsonObject
        {
            ["enabled"] = settings.MuxEnabled,
            ["concurrency"] = settings.MuxTcpConcurrency > 128 ? 128 : settings.MuxTcpConcurrency,
            ["xudpConcurrency"] = settings.MuxXudpConcurrency,
            ["xudpProxyUDP443"] = settings.MuxQuicHandling is "allow" or "skip" ? settings.MuxQuicHandling : "reject"
        };

        if (!settings.FragmentationEnabled) return;
        if (outbound["streamSettings"] is not JsonObject streamSettings)
        {
            streamSettings = new JsonObject();
            outbound["streamSettings"] = streamSettings;
        }
        if (streamSettings["finalmask"] is not JsonObject finalmask)
        {
            finalmask = new JsonObject();
            streamSettings["finalmask"] = finalmask;
        }
        if (finalmask["tcp"] is not JsonArray tcpMasks)
        {
            tcpMasks = new JsonArray();
            finalmask["tcp"] = tcpMasks;
        }
        for (var i = tcpMasks.Count - 1; i >= 0; i--)
        {
            if (tcpMasks[i] is JsonObject existing && string.Equals(existing["type"]?.GetValue<string>(), "fragment", StringComparison.OrdinalIgnoreCase))
                tcpMasks.RemoveAt(i);
        }
        var packets = settings.FragmentationPackets switch
        {
            "1-2" => "1-2",
            "1-3" => "1-3",
            "1-5" => "1-5",
            _ => "tlshello"
        };
        tcpMasks.Add(new JsonObject
        {
            ["type"] = "fragment",
            ["settings"] = new JsonObject
            {
                ["packets"] = packets,
                ["lengths"] = new JsonArray("100-200"),
                ["delays"] = new JsonArray("10-20"),
                ["maxSplit"] = "3-6"
            }
        });
    }

    private static JsonArray BuildDnsServers(AppSettings settings)
    {
        var value = (settings.DnsServers ?? string.Empty).Trim();
        if (!IPAddress.TryParse(value, out _)) value = "8.8.8.8";
        return new JsonArray(value);
    }

    private static void ApplyApplicationSettings(JsonObject config, AppSettings settings, bool tunnelMode)
    {
        if (config["dns"] is not JsonObject dns)
        {
            dns = new JsonObject();
            config["dns"] = dns;
        }
        dns["servers"] = BuildDnsServers(settings);
        dns["queryStrategy"] ??= "UseIP";
        dns["serveStale"] ??= true;
        dns["serveExpiredTTL"] ??= 300;
        dns["enableParallelQuery"] ??= true;

        if (tunnelMode && config["inbounds"] is JsonArray inbounds)
        {
            var tun = inbounds.OfType<JsonObject>().FirstOrDefault(x =>
                string.Equals(x["protocol"]?.GetValue<string>(), "tun", StringComparison.OrdinalIgnoreCase));
            if (tun?["settings"] is JsonObject tunSettings)
            {
                var leaks = new JsonArray();
                if (settings.ProtectDnsLeaks)
                {
                    leaks.Add("dns");
                    leaks.Add("misconfigtun");
                }
                tunSettings["autoSystemWfpBlockLeak"] = leaks;
            }
        }

        if (config["outbounds"] is not JsonArray outbounds)
            throw new FormatException("В конфигурации не найден массив outbounds.");

        var direct = outbounds.OfType<JsonObject>().FirstOrDefault(x => x["tag"]?.GetValue<string>() == "direct");
        if (direct is null)
        {
            direct = new JsonObject { ["tag"] = "direct", ["protocol"] = "freedom", ["settings"] = new JsonObject() };
            outbounds.Add(direct);
        }
        var blocked = outbounds.OfType<JsonObject>().FirstOrDefault(x => x["tag"]?.GetValue<string>() == "blocked");
        if (blocked is null)
        {
            blocked = new JsonObject { ["tag"] = "blocked", ["protocol"] = "blackhole", ["settings"] = new JsonObject() };
            outbounds.Add(blocked);
        }

        // Pick a real proxy outbound by protocol, not merely the first tag. Imported
        // profiles often use custom names for direct/blackhole outbounds.
        var proxyOutbound = outbounds.OfType<JsonObject>().FirstOrDefault(outbound =>
        {
            var tag = outbound["tag"]?.GetValue<string>();
            var protocol = outbound["protocol"]?.GetValue<string>();
            return !string.IsNullOrWhiteSpace(tag)
                && !string.Equals(tag, "direct", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(tag, "blocked", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(tag, "dns-out", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(protocol, "freedom", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(protocol, "blackhole", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(protocol, "dns", StringComparison.OrdinalIgnoreCase);
        });
        var defaultProxyTag = proxyOutbound?["tag"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(defaultProxyTag))
            throw new FormatException("В конфигурации нет основного proxy-outbound.");

        // Apply app-level outbound transport controls to the profile's primary proxy.
        ApplyCoreOutboundSettings(proxyOutbound!, settings);

        if (config["routing"] is not JsonObject routing)
        {
            routing = new JsonObject { ["domainStrategy"] = "IPIfNonMatch", ["rules"] = new JsonArray() };
            config["routing"] = routing;
        }
        if (routing["rules"] is not JsonArray existingRules)
        {
            existingRules = new JsonArray();
            routing["rules"] = existingRules;
        }

        var newRules = new List<JsonObject>();

        // DNS and QUIC safeguards must remain ahead of user routes.
        if (tunnelMode && config["inbounds"] is JsonArray currentInbounds)
        {
            var tunTag = currentInbounds.OfType<JsonObject>()
                .FirstOrDefault(x => string.Equals(x["protocol"]?.GetValue<string>(), "tun", StringComparison.OrdinalIgnoreCase))?["tag"]?.GetValue<string>() ?? "tun-in";
            if (!existingRules.Any(x => x is JsonObject rule && rule["outboundTag"]?.GetValue<string>() == "dns-out" &&
                rule["port"]?.ToString() == "53"))
                newRules.Add(new JsonObject
                {
                    ["type"] = "field", ["inboundTag"] = new JsonArray(tunTag), ["port"] = "53", ["outboundTag"] = "dns-out"
                });
        }

        if (tunnelMode && settings.DisableQuic && !existingRules.Any(x => x is JsonObject rule &&
            rule["network"]?.ToString() == "udp" && rule["port"]?.ToString() == "443"))
            newRules.Add(new JsonObject
            {
                ["type"] = "field", ["network"] = "udp", ["port"] = "443", ["outboundTag"] = "blocked"
            });

        foreach (var rule in settings.RoutingRules ?? [])
        {
            var domains = SplitRuleValues(rule.Domain);
            if (domains.Count == 0) continue;

            var domainArray = new JsonArray();
            foreach (var domain in domains) domainArray.Add(NormalizeDomainRule(domain));
            var selectors = new JsonObject
            {
                ["type"] = "field",
                ["domain"] = domainArray,
                ["outboundTag"] = rule.Action?.ToLowerInvariant() switch
                {
                    "direct" or "напрямую" => "direct",
                    "block" or "blocked" or "блокировать" => "blocked",
                    _ => defaultProxyTag
                }
            };
            newRules.Add(selectors);
        }

        if (settings.BypassPrivateNetworks && !existingRules.Any(x => x is JsonObject rule &&
            rule["ip"] is JsonArray ips && ips.Any(ip => ip?.ToString() == "geoip:private") &&
            rule["outboundTag"]?.ToString() == "direct"))
            newRules.Add(new JsonObject
            {
                ["type"] = "field", ["ip"] = new JsonArray("geoip:private"), ["outboundTag"] = "direct"
            });

        // Custom routes belong before a profile's rules, while its existing rules are preserved.
        var rebuilt = new JsonArray();
        foreach (var rule in newRules) rebuilt.Add(rule);
        foreach (var rule in existingRules) rebuilt.Add(rule?.DeepClone());

        // A simple catch-all from an imported template must not override XrayHub's selected default route.
        for (var i = rebuilt.Count - 1; i >= 0; i--)
        {
            if (rebuilt[i] is not JsonObject rule) continue;
            var hasTarget = !string.IsNullOrWhiteSpace(rule["outboundTag"]?.ToString())
                || !string.IsNullOrWhiteSpace(rule["balancerTag"]?.ToString());
            if (!hasTarget) continue;
            var hasSpecificMatch = new[] { "domain", "ip", "port", "inboundTag", "protocol", "source" }
                .Any(key => rule.ContainsKey(key));
            if (!hasSpecificMatch && (rule["network"] is null || rule["network"]?.ToString() is "tcp,udp" or "tcp, udp"))
                rebuilt.RemoveAt(i);
        }

        var defaultTag = settings.DefaultRoute?.ToLowerInvariant() switch
        {
            "direct" => "direct",
            "block" or "blocked" => "blocked",
            _ => defaultProxyTag
        };
        // Always emit an explicit fallback route. This avoids depending on outbound
        // order in imported JSON and makes the selected default action deterministic.
        rebuilt.Add(new JsonObject { ["type"] = "field", ["network"] = "tcp,udp", ["outboundTag"] = defaultTag });

        routing["rules"] = rebuilt;
    }

    private static List<string> SplitRuleValues(string? value) => (value ?? string.Empty)
        .Split(new[] { ';', ',', '\r', '\n' }, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    private static string NormalizeDomainRule(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Contains(':')) return trimmed;
        return "domain:" + trimmed;
    }

    private static JsonObject NormalizeImportedJson(string rawJson, AppSettings settings, bool tunnelMode)
    {
        var node = JsonNode.Parse(rawJson) as JsonObject ?? throw new FormatException("JSON должен содержать объект конфигурации Xray.");
        if (node["outbounds"] is not JsonArray outbounds || outbounds.Count == 0)
            throw new FormatException("В JSON не найден непустой массив outbounds.");

        if (node["inbounds"] is not JsonArray inbounds)
        {
            inbounds = new JsonArray();
            node["inbounds"] = inbounds;
        }
        if (!inbounds.Any(x => x is JsonObject o && o["tag"]?.GetValue<string>() == "http-in"))
            inbounds.Add(new JsonObject
            {
                ["tag"] = "http-in", ["listen"] = "127.0.0.1", ["port"] = settings.HttpPort,
                ["protocol"] = "http", ["settings"] = new JsonObject()
            });
        if (!inbounds.Any(x => x is JsonObject o && o["tag"]?.GetValue<string>() == "socks-in"))
            inbounds.Add(new JsonObject
            {
                ["tag"] = "socks-in", ["listen"] = "127.0.0.1", ["port"] = settings.SocksPort,
                ["protocol"] = "socks", ["settings"] = BuildSocksSettings(settings)
            });
        var xrayHubSocks = inbounds.OfType<JsonObject>().FirstOrDefault(o => o["tag"]?.GetValue<string>() == "socks-in");
        if (xrayHubSocks is not null)
        {
            xrayHubSocks["port"] = settings.SocksPort;
            xrayHubSocks["listen"] = "127.0.0.1";
            xrayHubSocks["settings"] = BuildSocksSettings(settings);
        }

        if (tunnelMode)
        {
            var tun = inbounds.OfType<JsonObject>().FirstOrDefault(x => x["protocol"]?.GetValue<string>() == "tun");
            if (tun is null)
            {
                tun = new JsonObject { ["tag"] = "tun-in", ["protocol"] = "tun", ["settings"] = new JsonObject() };
                inbounds.Add(tun);
            }
            if (string.IsNullOrWhiteSpace(tun["tag"]?.GetValue<string>())) tun["tag"] = "tun-in";
            // Imported profiles may already define a TUN inbound without sniffing.
            // Without sniffing, domain-based XrayHub rules cannot match TUN packets by hostname.
            tun["sniffing"] = BuildSniffing();
            var tunTag = tun["tag"]!.GetValue<string>();
            if (tun["settings"] is not JsonObject tunSettings)
            {
                tunSettings = new JsonObject();
                tun["settings"] = tunSettings;
            }
            tunSettings["name"] ??= "XrayHub";
            tunSettings["desc"] ??= "XrayHub Tunnel";
            tunSettings["mtu"] ??= settings.TunMtu;
            tunSettings["gateway"] = new JsonArray(settings.TunAddress);
            tunSettings["mtu"] = settings.TunMtu;
            tunSettings["dns"] = BuildDnsServers(settings);
            tunSettings["autoSystemRoutingTable"] ??= new JsonArray("0.0.0.0/0", "::/0");
            tunSettings["autoOutboundsInterface"] ??= "auto";
            if (tunSettings["autoSystemWfpBlockLeak"] is not JsonArray leakRules)
            {
                leakRules = new JsonArray();
                tunSettings["autoSystemWfpBlockLeak"] = leakRules;
            }
            leakRules.Clear();
            if (settings.ProtectDnsLeaks)
            {
                leakRules.Add("dns");
                leakRules.Add("misconfigtun");
            }

            if (node["dns"] is not JsonObject)
            {
                node["dns"] = new JsonObject
                {
                    // Use the single DNS address selected in XrayHub (8.8.8.8 by default).
                    ["servers"] = BuildDnsServers(settings),
                    ["queryStrategy"] = "UseIP", ["serveStale"] = true, ["serveExpiredTTL"] = 300,
                    ["enableParallelQuery"] = true
                };
            }
            if (!outbounds.Any(x => x is JsonObject o && o["tag"]?.GetValue<string>() == "dns-out"))
                outbounds.Add(new JsonObject { ["tag"] = "dns-out", ["protocol"] = "dns", ["settings"] = new JsonObject() });
            if (settings.DisableQuic && !outbounds.Any(x => x is JsonObject o && o["tag"]?.GetValue<string>() == "blocked"))
                outbounds.Add(new JsonObject { ["tag"] = "blocked", ["protocol"] = "blackhole", ["settings"] = new JsonObject() });

            if (node["routing"] is not JsonObject routing)
            {
                routing = new JsonObject();
                node["routing"] = routing;
            }
            if (routing["rules"] is not JsonArray rules)
            {
                rules = new JsonArray();
                routing["rules"] = rules;
            }
            if (!rules.Any(x => x is JsonObject o && o["outboundTag"]?.GetValue<string>() == "dns-out" &&
                                   o["port"]?.ToString() == "53" &&
                                   o["inboundTag"] is JsonArray tags && tags.Any(t => t?.GetValue<string>() == tunTag)))
                rules.Insert(0, new JsonObject
                {
                    ["type"] = "field", ["inboundTag"] = new JsonArray(tunTag), ["port"] = "53", ["outboundTag"] = "dns-out"
                });
            if (settings.DisableQuic && !rules.Any(x => x is JsonObject o && o["network"]?.GetValue<string>() == "udp" && o["port"]?.ToString() == "443"))
                rules.Insert(0, new JsonObject
                {
                    ["type"] = "field", ["network"] = "udp", ["port"] = "443", ["outboundTag"] = "blocked"
                });
        }

        // Preserve an imported full config, while adding the XrayHub local-control inbounds and TUN safety defaults.
        return node;
    }

    private static JsonObject BuildProxyOutbound(ProxyProfile p)
    {
        JsonObject settings;
        switch (p.Protocol.ToLowerInvariant())
        {
            case "vless":
                settings = new JsonObject
                {
                    ["vnext"] = new JsonArray(new JsonObject
                    {
                        ["address"] = p.Server, ["port"] = p.Port,
                        ["users"] = new JsonArray(new JsonObject
                        {
                            ["id"] = p.UserId, ["encryption"] = "none", ["flow"] = p.Flow
                        })
                    })
                };
                break;
            case "vmess":
                settings = new JsonObject
                {
                    ["vnext"] = new JsonArray(new JsonObject
                    {
                        ["address"] = p.Server, ["port"] = p.Port,
                        ["users"] = new JsonArray(new JsonObject
                        {
                            ["id"] = p.UserId, ["alterId"] = p.AlterId, ["security"] = string.IsNullOrWhiteSpace(p.Method) ? "auto" : p.Method
                        })
                    })
                };
                break;
            case "trojan":
                settings = new JsonObject
                {
                    ["servers"] = new JsonArray(new JsonObject { ["address"] = p.Server, ["port"] = p.Port, ["password"] = p.Password })
                };
                break;
            case "ss":
            case "shadowsocks":
                settings = new JsonObject
                {
                    ["servers"] = new JsonArray(new JsonObject { ["address"] = p.Server, ["port"] = p.Port, ["method"] = p.Method, ["password"] = p.Password })
                };
                break;
            default:
                throw new NotSupportedException($"Протокол {p.Protocol} ещё не поддерживается генератором конфигурации.");
        }

        var outbound = new JsonObject { ["tag"] = "proxy", ["protocol"] = p.Protocol == "ss" ? "shadowsocks" : p.Protocol, ["settings"] = settings };
        if (!string.IsNullOrWhiteSpace(p.Network) || !string.IsNullOrWhiteSpace(p.Security))
            outbound["streamSettings"] = BuildStreamSettings(p);
        return outbound;
    }

    private static JsonObject BuildStreamSettings(ProxyProfile p)
    {
        var network = string.IsNullOrWhiteSpace(p.Network) ? "raw" : p.Network;
        var stream = new JsonObject { ["network"] = network, ["security"] = p.Security };
        switch (network)
        {
            case "ws":
                var ws = new JsonObject { ["path"] = string.IsNullOrWhiteSpace(p.Path) ? "/" : p.Path };
                if (!string.IsNullOrWhiteSpace(p.Host)) ws["headers"] = new JsonObject { ["Host"] = p.Host };
                stream["wsSettings"] = ws;
                break;
            case "grpc":
                var grpc = new JsonObject
                {
                    ["serviceName"] = p.ServiceName,
                    // Subscription links carry mode=multi / mode=gun; it must match the server, otherwise the handshake succeeds but no data flows.
                    ["multiMode"] = string.Equals(p.Mode, "multi", StringComparison.OrdinalIgnoreCase)
                };
                if (p.RawQueryParameters.TryGetValue("authority", out var grpcAuthority) && !string.IsNullOrWhiteSpace(grpcAuthority))
                    grpc["authority"] = grpcAuthority;
                stream["grpcSettings"] = grpc;
                break;
            case "xhttp":
                var xhttp = new JsonObject { ["path"] = string.IsNullOrWhiteSpace(p.Path) ? "/" : p.Path, ["host"] = p.Host };
                if (!string.IsNullOrWhiteSpace(p.Mode)) xhttp["mode"] = p.Mode;
                stream["xhttpSettings"] = xhttp;
                break;
            case "httpupgrade":
                var upgrade = new JsonObject { ["path"] = string.IsNullOrWhiteSpace(p.Path) ? "/" : p.Path };
                if (!string.IsNullOrWhiteSpace(p.Host)) upgrade["host"] = p.Host;
                stream["httpupgradeSettings"] = upgrade;
                break;
            case "kcp":
                stream["kcpSettings"] = new JsonObject { ["header"] = new JsonObject { ["type"] = "none" } };
                break;
        }

        if (p.Security == "tls")
        {
            var insecure = p.AllowInsecure is "1" or "true" or "True" or "TRUE";
            var tls = new JsonObject { ["allowInsecure"] = insecure, ["fingerprint"] = p.Fingerprint };
            // Without sni= Xray would use the server address as SNI; links that rely on host= (CDN / fronted servers) need it as SNI.
            if (!string.IsNullOrWhiteSpace(p.Sni)) tls["serverName"] = p.Sni;
            else if (!string.IsNullOrWhiteSpace(p.Host)) tls["serverName"] = p.Host;
            if (!string.IsNullOrWhiteSpace(p.Alpn))
            {
                var alpn = new JsonArray();
                foreach (var item in p.Alpn.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)) alpn.Add(item);
                if (alpn.Count > 0) tls["alpn"] = alpn;
            }
            stream["tlsSettings"] = tls;
        }
        else if (p.Security == "reality")
        {
            stream["realitySettings"] = new JsonObject
            {
                ["serverName"] = p.Sni,
                ["fingerprint"] = p.Fingerprint,
                ["publicKey"] = p.PublicKey,
                ["shortId"] = p.ShortId,
                ["spiderX"] = p.RawQueryParameters.TryGetValue("spx", out var spx) && !string.IsNullOrWhiteSpace(spx) ? spx : ""
            };
        }
        return stream;
    }
}
