# XrayHub 0.3.3 — update

This is an application-source update only. It intentionally does **not** include `.github` or any GitHub Actions workflow file. Keep the existing `build-windows.yml` unchanged.

## Replace these files in the repository

- `App.xaml`
- `MainWindow.xaml`
- `MainWindow.xaml.cs`
- `XrayHub.csproj`
- `GlobalUsings.cs`
- `Models/AppSettings.cs`
- `Assets/XrayHub.png`
- `Assets/XrayHub.ico`

Upload them from the repository root, preserving the folders, then commit the changes. The existing Actions workflow should start on the commit.

## Changes

- DNS is directly editable; first-run/default DNS is `8.8.8.8`; the `8.8.8.8` button restores the default. Older blank/system/auto/Cloudflare-default settings are migrated once; other custom resolver values are preserved.
- SOCKS5 authentication is enabled for a fresh install. If credentials are missing, a random username and 24-character password are generated once and saved. Clicking the masked password field reveals it; clicking again hides it. The generator creates a new credential pair.
- The light theme now uses replaceable dynamic WPF resources throughout the main controls, data grids, menus, and popups.
- The Components card was removed from About.
- The existing XrayHub mark was preserved pixel-for-pixel; only the outer square corners of the PNG and ICO background were made transparent/rounded. The X glyph itself was not altered.
- The tray icon uses the executable's embedded icon. The app places an icon in the notification area while running; minimizing or closing the window hides it to the tray. Left-click/double-click or the Open menu restores it. Use the tray menu's Exit command to stop Xray and really quit.
- WinForms is enabled only for the native Windows tray icon. Implicit usings were made explicit to avoid WPF/WinForms namespace collisions.

## Notes

- No workflow file is included in this archive.
- When the window is hidden to the tray, the Xray connection remains active. Exit from the tray menu restores the system proxy and stops Xray.
- Settings are saved through the existing Save settings button; DNS and SOCKS credentials are also migrated/saved once on first launch after this update.
