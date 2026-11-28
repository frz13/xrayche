using System.Text.Json;
using XrayHub.Models;

namespace XrayHub.Services;

public sealed class ProfileStore
{
    private readonly string _directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "XrayHub");
    private string ProfilesFile => Path.Combine(_directory, "profiles.json");
    private string SettingsFile => Path.Combine(_directory, "settings.json");
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        // WindowLeft/WindowTop default to NaN until the window position is saved.
        NumberHandling = System.Text.Json.Serialization.JsonNumberHandling.AllowNamedFloatingPointLiterals
    };

    public ProfileStore() => Directory.CreateDirectory(_directory);

    public List<ProxyProfile> LoadProfiles()
    {
        if (!File.Exists(ProfilesFile)) return [];
        try { return JsonSerializer.Deserialize<List<ProxyProfile>>(File.ReadAllText(ProfilesFile), JsonOptions) ?? []; }
        catch { return []; }
    }

    public void SaveProfiles(IEnumerable<ProxyProfile> profiles) =>
        File.WriteAllText(ProfilesFile, JsonSerializer.Serialize(profiles, JsonOptions));

    public AppSettings LoadSettings()
    {
        if (!File.Exists(SettingsFile)) return new AppSettings();
        try { return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsFile), JsonOptions) ?? new AppSettings(); }
        catch { return new AppSettings(); }
    }

    public void SaveSettings(AppSettings settings) =>
        File.WriteAllText(SettingsFile, JsonSerializer.Serialize(settings, JsonOptions));

    public string RuntimeDirectory
    {
        get
        {
            var path = Path.Combine(_directory, "runtime");
            Directory.CreateDirectory(path);
            return path;
        }
    }
}
