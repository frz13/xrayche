# XrayHub 0.3.6 — detection and repair of conflicting Windows proxy

This update adds event-driven detection of a third-party Windows user proxy and a persistent in-app repair prompt.

## Files to replace/add

Replace:
- `MainWindow.xaml`
- `MainWindow.xaml.cs`
- `Services/WindowsProxyManager.cs`
- `XrayHub.csproj`

Add:
- `Services/WindowsProxyChangeWatcher.cs`
- `Services/ProxyConflictStateStore.cs`
- `Models/WindowsProxySnapshot.cs`
- `Models/ProxyConflictState.cs`

Do not replace or upload `.github/workflows/build-windows.yml` for this update.

## How detection works

- XrayHub waits for a Windows registry change notification on the current-user WinINET `Internet Settings` key. It does not run a periodic internet ping.
- After a proxy setting changes, it checks whether the configured proxy is different from XrayHub's own `127.0.0.1:<HTTP port>` proxy.
- It then performs one short, event-triggered comparison: direct HTTPS access versus access using the Windows system proxy.
- The prompt is shown only if direct access succeeds while the Windows proxy route fails.
- PAC and auto-detect (WPAD) settings are treated as potential external proxy settings and are subjected to the same connectivity check.

## Persistent prompt

A confirmed, unresolved event is saved to:

`%APPDATA%\XrayHub\proxy-conflict-state.json`

Closing or crashing XrayHub does not clear it. On the next launch, the previously confirmed prompt is restored. It remains until the user chooses **Fix** or **Leave as is**. If Windows settings changed after detection, the repair action rechecks them before making any changes.

## Repair safety

- Before disabling the conflict, XrayHub saves the current proxy registry values to a rollback file.
- It disables the current-user proxy enable flag, PAC URL and auto-detect setting. It preserves the proxy server text and bypass list.
- It verifies internet access again using the Windows system-proxy route.
- If access is not restored, it restores the captured registry values and keeps the unresolved warning pending.
- If access is restored, the repair is committed so disconnecting XrayHub later will not re-enable the conflicting proxy that was just repaired.
- An interrupted repair is rolled back on the next application startup.

Scope: this update checks the current user's Windows Internet Settings (WinINET) proxy/PAC/WPAD configuration. It does not currently inspect machine-wide WinHTTP proxy, browser-specific extensions, or per-application proxy settings.

## Build

Upload these files to the repository root using the folder structure above. Then commit the changes. GitHub Actions should build using the workflow already present in your repository.

The XAML structure, duplicate element names, and event-handler references were statically checked. A Windows/.NET compilation was not available in this environment; verify the actual build through GitHub Actions before replacing your current working package.
