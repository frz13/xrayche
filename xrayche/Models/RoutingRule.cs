using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace XrayHub.Models;

/// <summary>A user-defined Xray field routing rule.</summary>
public sealed class RoutingRule : INotifyPropertyChanged
{
    private string _action = "proxy";

    public string Domain { get; set; } = string.Empty;
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
