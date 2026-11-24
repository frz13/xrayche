using System.Globalization;
using System.Windows.Controls;
using System.Windows.Data;

namespace XrayHub;

/// <summary>
/// WPF computes a ScrollBar thumb purely from viewport/extent and does not honor
/// Thumb.MinHeight, so long lists in short windows produced a ~10 px thumb.
/// This converter enlarges the ViewportSize given to Track just enough that the
/// thumb is never shorter than the requested minimum. Scroll values are unchanged.
/// values: ViewportSize, Maximum, Minimum, ActualHeight, ActualWidth, Orientation.
/// parameter: minimum thumb length in DIPs.
/// </summary>
public sealed class ScrollThumbViewportConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        var viewport = Read(values, 0);
        var maximum = Read(values, 1);
        var minimum = Read(values, 2);
        var height = Read(values, 3);
        var width = Read(values, 4);
        var vertical = values.Length > 5 && values[5] is Orientation o && o == Orientation.Vertical;

        var minThumb = 24.0;
        if (parameter is string text &&
            double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed))
            minThumb = parsed;

        var track = vertical ? height : width;
        var range = Math.Max(0.0, maximum - minimum);

        if (viewport < 0) viewport = 0;
        if (range <= 0 || track <= minThumb + 1) return viewport;

        // thumb = track * vp / (range + vp) >= minThumb  =>  vp >= range * minThumb / (track - minThumb)
        var needed = range * minThumb / (track - minThumb);
        return Math.Max(viewport, needed);
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();

    private static double Read(object[] values, int index) =>
        index < values.Length && values[index] is double d && !double.IsNaN(d) && !double.IsInfinity(d) ? d : 0.0;
}
