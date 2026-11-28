using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

namespace XrayHub;

/// <summary>An application the user can add to per-app routing.</summary>
public sealed class AppCandidate
{
    public string Title { get; init; } = string.Empty;
    public string ProcessName { get; init; } = string.Empty;
    public string FilePath { get; init; } = string.Empty;
    public bool HasWindow { get; set; }
}

/// <summary>
/// Picker with a searchable list of running applications and a button that opens
/// Explorer to choose an executable manually.
/// </summary>
public sealed class AppPickerWindow : Window
{
    private readonly Func<string, string> _t;
    private readonly TextBox _search = new();
    private readonly ListBox _list = new();
    private readonly TextBlock _status = new();
    private readonly Button _addButton = new();
    private readonly Dictionary<string, ImageSource?> _icons = new(StringComparer.OrdinalIgnoreCase);
    private List<AppCandidate> _all = [];

    public List<AppCandidate> SelectedApps { get; } = [];

    public AppPickerWindow(Func<string, string> translate)
    {
        _t = translate;
        Title = _t("Добавить приложение");
        Width = 580;
        Height = 620;
        MinWidth = 460;
        MinHeight = 440;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        SetResourceReference(BackgroundProperty, "Bg");
        SetResourceReference(ForegroundProperty, "TextMain");

        var root = new Grid { Margin = new Thickness(16) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var header = new TextBlock
        {
            Text = _t("Выбери запущенные приложения из списка или укажи файл приложения вручную."),
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap
        };
        header.SetResourceReference(TextBlock.ForegroundProperty, "TextMuted");
        Grid.SetRow(header, 0);
        root.Children.Add(header);

        _search.Margin = new Thickness(0, 12, 0, 10);
        _search.ToolTip = _t("Поиск по названию или пути");
        _search.TextChanged += (_, _) => RefreshList();
        Grid.SetRow(_search, 1);
        root.Children.Add(_search);

        _list.SelectionMode = SelectionMode.Extended;
        _list.HorizontalContentAlignment = HorizontalAlignment.Stretch;
        _list.BorderThickness = new Thickness(1);
        _list.SetValue(ScrollViewer.HorizontalScrollBarVisibilityProperty, ScrollBarVisibility.Disabled);
        _list.SetResourceReference(BackgroundProperty, "InputBg");
        _list.SetResourceReference(BorderBrushProperty, "Line");
        _list.SetResourceReference(ForegroundProperty, "TextMain");
        _list.SelectionChanged += (_, _) => _addButton.IsEnabled = _list.SelectedItems.Count > 0;
        _list.MouseDoubleClick += (_, _) => ConfirmSelection();
        Grid.SetRow(_list, 2);
        root.Children.Add(_list);

        _status.Margin = new Thickness(0, 8, 0, 0);
        _status.FontSize = 11;
        _status.SetResourceReference(TextBlock.ForegroundProperty, "TextMuted");
        Grid.SetRow(_status, 3);
        root.Children.Add(_status);

        var buttons = new Grid { Margin = new Thickness(0, 12, 0, 0) };
        buttons.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        buttons.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var browse = new Button { Content = _t("Выбрать файл…"), Padding = new Thickness(12, 8, 12, 8), HorizontalAlignment = HorizontalAlignment.Left };
        browse.Click += Browse_Click;
        buttons.Children.Add(browse);

        var right = new StackPanel { Orientation = Orientation.Horizontal };
        Grid.SetColumn(right, 1);
        var cancel = new Button { Content = _t("Отмена"), Padding = new Thickness(14, 8, 14, 8), Margin = new Thickness(0, 0, 8, 0), IsCancel = true };
        _addButton.Content = _t("Добавить выбранные");
        _addButton.Padding = new Thickness(14, 8, 14, 8);
        _addButton.IsEnabled = false;
        _addButton.IsDefault = true;
        _addButton.SetResourceReference(BackgroundProperty, "Accent");
        _addButton.SetResourceReference(BorderBrushProperty, "Accent");
        _addButton.Foreground = Brushes.White;
        _addButton.Click += (_, _) => ConfirmSelection();
        right.Children.Add(cancel);
        right.Children.Add(_addButton);
        buttons.Children.Add(right);
        Grid.SetRow(buttons, 4);
        root.Children.Add(buttons);

        Content = root;
        Loaded += async (_, _) => await LoadRunningAppsAsync();
    }

    private async Task LoadRunningAppsAsync()
    {
        _status.Text = _t("Загрузка списка приложений…");
        try { _all = await Task.Run(EnumerateRunningApps); }
        catch { _all = []; }
        RefreshList();
        _search.Focus();
    }

    private void RefreshList()
    {
        var query = _search.Text.Trim();
        _list.Items.Clear();
        foreach (var app in _all)
        {
            if (query.Length > 0 &&
                !app.Title.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !app.ProcessName.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !app.FilePath.Contains(query, StringComparison.OrdinalIgnoreCase))
                continue;
            _list.Items.Add(BuildItem(app));
        }
        _status.Text = _list.Items.Count == 0
            ? _t("Ничего не найдено. Можно выбрать файл вручную.")
            : $"{_t("Запущенных приложений")}: {_list.Items.Count}";
    }

    private ListBoxItem BuildItem(AppCandidate app)
    {
        var grid = new Grid { Margin = new Thickness(2, 3, 2, 3) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        grid.Children.Add(new System.Windows.Controls.Image
        {
            Width = 24,
            Height = 24,
            Margin = new Thickness(0, 0, 10, 0),
            VerticalAlignment = VerticalAlignment.Center,
            Source = GetIcon(app.FilePath)
        });

        var stack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(stack, 1);
        stack.Children.Add(new TextBlock
        {
            Text = string.Equals(app.Title, app.ProcessName, StringComparison.OrdinalIgnoreCase)
                ? app.ProcessName
                : $"{app.Title}  ·  {app.ProcessName}",
            FontWeight = FontWeights.SemiBold,
            FontSize = 12,
            TextTrimming = TextTrimming.CharacterEllipsis
        });
        var path = new TextBlock
        {
            Text = app.FilePath,
            FontSize = 10,
            Margin = new Thickness(0, 2, 0, 0),
            TextTrimming = TextTrimming.CharacterEllipsis,
            ToolTip = app.FilePath
        };
        path.SetResourceReference(TextBlock.ForegroundProperty, "TextMuted");
        stack.Children.Add(path);
        grid.Children.Add(stack);

        return new ListBoxItem { Content = grid, Tag = app };
    }

    private ImageSource? GetIcon(string path)
    {
        if (_icons.TryGetValue(path, out var cached)) return cached;
        ImageSource? result = null;
        try
        {
            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (icon is not null)
            {
                var source = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                source.Freeze();
                result = source;
            }
        }
        catch { /* No icon is not a reason to hide the application. */ }
        _icons[path] = result;
        return result;
    }

    private void ConfirmSelection()
    {
        if (_list.SelectedItems.Count == 0) return;
        SelectedApps.Clear();
        foreach (var item in _list.SelectedItems.OfType<ListBoxItem>())
            if (item.Tag is AppCandidate app) SelectedApps.Add(app);
        if (SelectedApps.Count == 0) return;
        DialogResult = true;
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = _t("Выбери приложение"),
            Filter = $"{_t("Приложения")} (*.exe)|*.exe|{_t("Все файлы")} (*.*)|*.*",
            Multiselect = true,
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != true) return;

        SelectedApps.Clear();
        foreach (var file in dialog.FileNames)
            SelectedApps.Add(FromFile(file, hasWindow: false));
        if (SelectedApps.Count > 0) DialogResult = true;
    }

    private static AppCandidate FromFile(string path, bool hasWindow)
    {
        var fileName = System.IO.Path.GetFileName(path);
        var title = string.Empty;
        try { title = FileVersionInfo.GetVersionInfo(path).FileDescription?.Trim() ?? string.Empty; }
        catch { }
        if (string.IsNullOrWhiteSpace(title)) title = System.IO.Path.GetFileNameWithoutExtension(path);
        return new AppCandidate { Title = title, ProcessName = fileName, FilePath = path, HasWindow = hasWindow };
    }

    private static List<AppCandidate> EnumerateRunningApps()
    {
        var selfPath = Environment.ProcessPath ?? string.Empty;
        var byPath = new Dictionary<string, AppCandidate>(StringComparer.OrdinalIgnoreCase);

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                string? path;
                try { path = process.MainModule?.FileName; }
                catch { continue; } // System or protected process: its path cannot be read.
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) continue;
                if (string.Equals(path, selfPath, StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(System.IO.Path.GetFileName(path), "xray.exe", StringComparison.OrdinalIgnoreCase)) continue;

                var hasWindow = false;
                try { hasWindow = process.MainWindowHandle != IntPtr.Zero; } catch { }

                if (byPath.TryGetValue(path, out var existing))
                {
                    if (hasWindow) existing.HasWindow = true;
                    continue;
                }
                byPath[path] = FromFile(path, hasWindow);
            }
            catch { }
            finally { process.Dispose(); }
        }

        return byPath.Values
            .OrderByDescending(app => app.HasWindow)
            .ThenBy(app => app.Title, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }
}
