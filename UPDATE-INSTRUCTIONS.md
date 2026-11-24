# XrayHub 0.3.5 — update instructions

This archive contains the application update only. It intentionally does not include `.github/`, workflows, build scripts, or a copy of Xray Core.

## Apply the update

1. Extract the ZIP.
2. In the existing `frz13/xrayhubtest` repository, upload the extracted files while preserving their folder structure and overwrite matching files.
3. Do not delete or replace `.github/workflows/build-windows.yml`.
4. Commit the changes. The existing GitHub Actions workflow should run automatically.
5. Download the new `XrayHub-Windows-x64` artifact after the workflow completes successfully.

## Changes in 0.3.5

- Added named-mutex single-instance protection. A second launch signals the existing app to restore its window instead of creating another process/tray icon.
- Improved language switching by walking both logical and visual WPF trees, including inactive tab pages.
- Localized connection-mode descriptions and dynamic connect/disconnect button captions.
- The tray uses the application's rounded multi-resolution icon and displays a small blue lightning mark while connected.
- The connected status (`Connected >`) opens an in-app connection details panel with public egress IP, IP version, network range (when RDAP provides it), country, region, city, timezone, postal code, coordinates, ISP, ASN, and estimated geolocation accuracy.

## Notes

- Geolocation is approximate IP-based information. Postal codes, coordinates, and network ranges may be unavailable or less precise depending on the provider's data.
- The connection details lookup goes through the active local Xray SOCKS5 inbound, so it reports the selected route's public egress rather than the user's direct ISP address.
- This environment cannot run a Windows WPF build. Confirm compilation and runtime behaviour in GitHub Actions on the Windows runner.
