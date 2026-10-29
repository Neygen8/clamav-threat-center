# ClamAV live protection for macOS

This project combines ClamAV scanning, live file monitoring, a quarantine and VirusTotal second opinions in a macOS menu-bar control panel.

## Protection

- `clamd` keeps the signature database in memory for scanning.
- The live monitor watches new and changed files on the Desktop and in Downloads. External drives are scanned when explicitly selected.
- Events are combined and scans run sequentially to limit system load. Existing files are not automatically requeued after a service restart; a limited recovery scan handles an interrupted event stream.
- Archives and disk images, including `.dmg`, `.iso`, `.zip`, `.jar`, `.7z` and `.rar`, are excluded from live scanning. Use the Finder quick action for an on-demand scan. Gatekeeper and VirusTotal hash checks continue separately.
- Detected threats are moved to a user-only quarantine and can be inspected or restored in the Threat Center.
- The bundled schedule updates signatures every six hours and scans Desktop and Downloads daily at 19:00.
- The VirusTotal service watches Downloads and reports to the same panel. It checks SHA-256 hashes first; file contents are uploaded only with explicit approval or when automatic quarantine analysis is enabled in the user's configuration.

The application is installed in `~/Applications` and appears in the menu bar. Closing the interface leaves the separate background services running. The Finder quick action currently appears as **ClamAV ile Tara**.

> Live monitoring scans files after they are written. It does not replace an Endpoint Security execution blocker and cannot guarantee that every file is stopped before it is opened.

## Complementary security tools

The panel also displays the status of macOS Gatekeeper and XProtect, Santa, BlockBlock, RansomWhere? and LuLu. These tools are separate products and must be installed and configured independently. The included `config/Santa-Standalone.mobileconfig` uses Santa's Monitor mode. The verified installer hashes and signature records are in `config/verified-installers.txt`.

## Installation and management

Install ClamAV with Homebrew and download its signature database first. Then run:

```sh
./install.sh install
./install.sh status
./install.sh scan-now
./install.sh update-now
./install.sh uninstall
```

Uninstall removes the project's running jobs and Finder quick action but retains quarantine, settings and logs. After a successful migration, the former `VirusTotal İzleyici.app` and its LaunchAgent are moved into a dated, user-only migration backup. The existing VirusTotal API key remains at `~/.config/vt-download-watcher/.env`.

## Settings and logs

Under `~/Library/Application Support/ClamAV-Automation/`:

- `scan-paths`: scheduled scan paths
- `realtime-paths`: live monitoring paths
- `Quarantine/`: quarantined files
- `realtime-status.json`, `virustotal-status.json`: service status
- `scan-progress.json`: scan progress and estimated time remaining
- `virustotal-quarantine-state.json`: quarantine VirusTotal state
- `coordination/quarantine.lock`: shared quarantine coordination lock

Logs and event records are stored under `~/Library/Logs/ClamAV-Automation/`. VirusTotal privacy and upload settings are stored in `~/.config/vt-download-watcher/config.json`.

Path files accept one absolute path or `$HOME`-relative path per line. Restart the live service after changing its paths. Sensitive files are kept with user-only permissions.

Long scans build a manifest of accessible files and deduplicate APFS firmlinks by device and inode. When scanning `/`, the read-only `/System` and mounted drives under `/Volumes` are skipped; select external drives separately. Development directories and user caches are excluded by default.
