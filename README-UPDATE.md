# XrayHub 0.3.7 — interface and proxy-conflict update

This update contains application files only. It does **not** include or replace `.github/workflows/build-windows.yml`.

## Changes

- Notification titles and messages are translated between Russian and English, including connection, import, subscription, ping, routing, settings, and external-proxy conflict notices. A notice that is already visible is re-rendered when the UI language changes.
- The custom routing domain editor now uses the XrayHub dark input surface and accent outline instead of the default white WPF TextBox surface.
- The Configurations list now handles the mouse wheel itself when its list can scroll; the surrounding page receives the wheel only when the list is at its limit.
- Scrollbars are hidden application-wide while mouse-wheel and keyboard scrolling remain available.
- The main window has no Windows title-bar caption or window icon; the in-app logo and executable/tray icon are retained.
- The About page contains `created by: frz`; `frz` changes to blue on hover and opens `https://github.com/frz13`.
- Event-driven Windows WinINET proxy-conflict detection remains included. It compares the configured proxy against XrayHub's own local proxy, checks direct access versus system-proxy access before creating a warning, and does not run a continuous internet monitor.
- A confirmed unresolved conflict is persisted under `%APPDATA%\XrayHub\proxy-conflict-state.json`, rechecked at the next start, and shown again if it still exists. The Fix action backs up the current Windows proxy state and rolls it back if internet access is not restored.

## Apply

Upload the files from this archive to the root of your GitHub repository, preserving folder structure and replacing the existing files. Do not upload an `.github` folder and do not modify the working workflow.

Files in this update:

- `App.xaml`
- `MainWindow.xaml`
- `MainWindow.xaml.cs`
- `Models/ProxyProfile.cs`
- `Models/ProxyConflictState.cs`
- `Models/WindowsProxySnapshot.cs`
- `Services/ProxyConflictStateStore.cs`
- `Services/WindowsProxyChangeWatcher.cs`
- `Services/WindowsProxyManager.cs`

The project was checked for XML well-formedness, duplicate translation keys, XAML event-handler references, and scrollbar visibility settings. A Windows WPF compilation was not available in this environment; GitHub Actions must validate the final build.
