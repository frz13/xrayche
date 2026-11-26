using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using XrayHub.Models;

namespace XrayHub;

// Per-application routing: the "Маршрутизация приложений" section of the Routing page.
public partial class MainWindow
{
    private readonly ObservableCollection<AppRoutingRule> _appRoutingRules = [];
    private bool _appRoutingWired;

    private void InitializeAppRouting()
    {
        foreach (var rule in _appRoutingRules) rule.PropertyChanged -= AppRule_PropertyChanged;
        _appRoutingRules.Clear();
        foreach (var rule in _settings.AppRoutingRules ?? [])
        {
            if (string.IsNullOrWhiteSpace(rule.Path)) continue; // never keep empty app rules
            rule.PropertyChanged += AppRule_PropertyChanged;
            _appRoutingRules.Add(rule);
        }

        AppRoutingGrid.ItemsSource = _appRoutingRules;
        if (!_appRoutingWired)
        {
            _appRoutingWired = true;
            _appRoutingRules.CollectionChanged += (_, _) =>
            {
                UpdateAppRoutingEmptyState();
                ScheduleSettingsAutosave();
            };
        }
        UpdateAppRoutingEmptyState();
        SetRoutingSubTab("domains", animate: false);
    }

    private void AppRule_PropertyChanged(object? sender, PropertyChangedEventArgs e) => ScheduleSettingsAutosave();

    private void UpdateAppRoutingEmptyState()
    {
        if (AppRoutingEmptyText is null) return;
        AppRoutingEmptyText.Visibility = _appRoutingRules.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Copies the app rules from the UI list to settings (called before settings are written).</summary>
    private void SyncAppRoutingRulesToSettings()
    {
        _settings.AppRoutingRules = _appRoutingRules
            .Where(rule => !string.IsNullOrWhiteSpace(rule.Path) && rule.Action is "proxy" or "direct" or "block" or "blocked")
            .ToList();
    }

    private void RoutingSubTab_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string tag }) SetRoutingSubTab(tag);
    }

    private void SetRoutingSubTab(string tag, bool animate = true)
    {
        if (RoutingDomainsPanel is null || RoutingAppsPanel is null) return;
        var apps = string.Equals(tag, "apps", StringComparison.Ordinal);
        RoutingDomainsPanel.Visibility = apps ? Visibility.Collapsed : Visibility.Visible;
        RoutingAppsPanel.Visibility = apps ? Visibility.Visible : Visibility.Collapsed;
        MarkSubTab(RoutingSubDomainsButton, !apps);
        MarkSubTab(RoutingSubAppsButton, apps);
        if (animate) PlayEntrance(apps ? RoutingAppsPanel : RoutingDomainsPanel, 10, 220);
    }

    private static void MarkSubTab(Button button, bool active)
    {
        if (active)
        {
            button.SetResourceReference(Control.BackgroundProperty, "Accent");
            button.SetResourceReference(Control.BorderBrushProperty, "Accent");
            button.Foreground = Brushes.White;
        }
        else
        {
            button.ClearValue(Control.BackgroundProperty);
            button.ClearValue(Control.BorderBrushProperty);
            button.ClearValue(Control.ForegroundProperty);
        }
    }

    private void AddAppRouting_Click(object sender, RoutedEventArgs e)
    {
        var picker = new AppPickerWindow(L) { Owner = this };
        if (picker.ShowDialog() != true) return;

        var added = 0;
        foreach (var app in picker.SelectedApps)
        {
            if (_appRoutingRules.Any(rule => string.Equals(rule.Path, app.FilePath, StringComparison.OrdinalIgnoreCase)))
                continue;
            var rule = new AppRoutingRule { Name = app.Title, Path = app.FilePath, Action = "proxy" };
            rule.PropertyChanged += AppRule_PropertyChanged;
            _appRoutingRules.Add(rule);
            added++;
        }

        if (added > 0)
        {
            AddLog($"Маршрутизация приложений: добавлено {added}.");
            AppRoutingGrid.ScrollIntoView(_appRoutingRules[^1]);
        }
    }

    private void RemoveAppRouting_Click(object sender, RoutedEventArgs e)
    {
        var selected = AppRoutingGrid.SelectedItems.OfType<AppRoutingRule>().ToList();
        foreach (var rule in selected)
        {
            rule.PropertyChanged -= AppRule_PropertyChanged;
            _appRoutingRules.Remove(rule);
        }
    }
}
