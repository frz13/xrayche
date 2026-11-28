using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace XrayHub;

// Light UI animations. All of them are skipped when Windows has animations turned off.
public partial class MainWindow
{
    private static bool AnimationsEnabled => SystemParameters.ClientAreaAnimation;

    /// <summary>Fade (and optional slide) of an element that has just appeared. Base values are restored afterwards.</summary>
    private static void PlayEntrance(FrameworkElement? element, double fromY = 10, int milliseconds = 220)
    {
        if (element is null || !AnimationsEnabled) return;
        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };

        element.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(milliseconds))
        {
            EasingFunction = ease,
            FillBehavior = FillBehavior.Stop
        });

        if (Math.Abs(fromY) < 0.01) return;
        TranslateTransform? translate = element.RenderTransform as TranslateTransform;
        if (translate is null || translate.IsFrozen)
        {
            // Do not replace a transform the element already uses for something else.
            if (element.RenderTransform is not null && !ReferenceEquals(element.RenderTransform, Transform.Identity)) return;
            translate = new TranslateTransform();
            element.RenderTransform = translate;
        }
        translate.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(fromY, 0, TimeSpan.FromMilliseconds(milliseconds))
        {
            EasingFunction = ease,
            FillBehavior = FillBehavior.Stop
        });
    }

    /// <summary>Plays the entrance animation every time the element becomes visible.</summary>
    private static void AttachEntrance(FrameworkElement? element, double fromY = 0, int milliseconds = 200)
    {
        if (element is null) return;
        element.IsVisibleChanged += (_, e) =>
        {
            if (e.NewValue is true) PlayEntrance(element, fromY, milliseconds);
        };
    }

    /// <summary>Soft breathing of the status dot while a connection is active.</summary>
    private void SetConnectionPulse(bool active)
    {
        if (ConnectionDot is null) return;
        if (!active || !AnimationsEnabled)
        {
            ConnectionDot.BeginAnimation(UIElement.OpacityProperty, null);
            return;
        }
        ConnectionDot.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(1.0, 0.3, TimeSpan.FromMilliseconds(950))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        });
    }

    private void InitializeAnimations()
    {
        AttachEntrance(InlineNoticeHost, -8, 220);
        AttachEntrance(ProfileDetailsOverlay, 0, 180);
        AttachEntrance(ProxyConflictOverlay, 0, 180);
        AttachEntrance(ConnectionDetailsOverlay, 0, 180);
        // Rows fade in when they are created (fade only: no layout shifts while a cell is being edited).
        RoutingRulesGrid.LoadingRow += (_, e) => PlayEntrance(e.Row, 0, 240);
        AppRoutingGrid.LoadingRow += (_, e) => PlayEntrance(e.Row, 0, 240);
    }
}
