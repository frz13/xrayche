using System.Threading;
using System.Windows;

namespace XrayHub;

public partial class App : Application
{
    private const string MutexName = @"Local\XrayHub.SingleInstance.v1";
    private const string ActivationEventName = @"Local\XrayHub.Activate.v1";

    private Mutex? _instanceMutex;
    private EventWaitHandle? _activationEvent;
    private RegisteredWaitHandle? _activationRegistration;
    private bool _ownsMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Create/open the activation event before checking the mutex. This avoids a
        // startup race where a second launch arrives before the first has created it.
        _activationEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ActivationEventName);
        _instanceMutex = new Mutex(false, MutexName);
        try
        {
            _ownsMutex = _instanceMutex.WaitOne(0);
        }
        catch (AbandonedMutexException)
        {
            // The previous instance crashed; this process now owns the abandoned mutex.
            _ownsMutex = true;
        }

        if (!_ownsMutex)
        {
            try { _activationEvent.Set(); } catch { }
            base.OnStartup(e);
            Shutdown();
            return;
        }

        base.OnStartup(e);
        var window = new MainWindow();
        MainWindow = window;
        window.Show();

        _activationRegistration = ThreadPool.RegisterWaitForSingleObject(
            _activationEvent,
            (_, _) =>
            {
                try
                {
                    if (Current?.MainWindow is MainWindow mainWindow)
                        mainWindow.Dispatcher.BeginInvoke(new Action(mainWindow.ActivateFromSecondInstance));
                }
                catch { }
            },
            null,
            Timeout.Infinite,
            executeOnlyOnce: false);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _activationRegistration?.Unregister(null);
        _activationEvent?.Dispose();
        if (_ownsMutex)
        {
            try { _instanceMutex?.ReleaseMutex(); } catch { }
        }
        _instanceMutex?.Dispose();
        base.OnExit(e);
    }
}
