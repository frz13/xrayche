using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace XrayHub.Models;

/// <summary>Per-application route: traffic of the given executable goes through the selected outbound.</summary>
public sealed class AppRoutingRule : INotifyPropertyChanged
{
    private string _action = "proxy";

    /// <summary>Human readable name (file description or file name).</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Full path to the executable chosen by the user.</summary>
    public string Path { get; set; } = string.Empty;

    public string Action
    {
        get => _action;
        set
        {
            if (_action == value) return;
            _action = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(ActionLabel));
        }
    }

    /// <summary>Executable file name used for Xray process matching, for example chrome.exe.</summary>
    [JsonIgnore]
    public string ProcessName => System.IO.Path.GetFileName(Path ?? string.Empty);

    [JsonIgnore]
    public string ActionLabel => Action switch
    {
        "direct" => "Напрямую",
        "block" or "blocked" => "Блокировать",
        _ => "Прокси"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
