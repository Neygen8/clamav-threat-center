# ClamAV Threat Center for macOS

ClamAV Threat Center brings ClamAV scans, file monitoring, quarantine, and optional VirusTotal checks together in a macOS menu-bar app.

## What it does

- Scans new and changed files in the configured monitoring folders, normally Desktop and Downloads. Scans are queued and processed sequentially to limit resource use.
- Runs on-demand scans from the control panel or Finder's **Quick Actions → Scan with ClamAV** menu. External drives can be selected for an on-demand scan.
- Shows scan progress, estimated time remaining, recent events, and quarantine records in one control panel.
- Moves detected threats to a user-only quarantine. The app scans a quarantined file again before allowing it to be restored.
- Uses `clamd` to keep the signature database in memory and processes file scans with one configured engine thread.
- Checks Downloads with VirusTotal when an API key is configured. Checks use a file's SHA-256 hash first. Uploading file contents is optional; automatic uploads are disabled by default.
- Displays the status of Gatekeeper, XProtect, Santa, BlockBlock, RansomWhere?, and LuLu when available. These are separate products and require their own installation and configuration.

Real-time monitoring reacts after a file is written. It is not an execution blocker and cannot guarantee that every threat is stopped before opening. Archives and disk images such as `.dmg`, `.iso`, `.zip`, `.jar`, `.7z`, and `.rar` are excluded from real-time scanning; use an on-demand scan to inspect them. ClamAV scans are also subject to the size and time limits in `config/clamd.conf`.

## Requirements

- macOS 13 or later.
- [Homebrew](https://brew.sh/) and ClamAV, including `clamd`, `clamdscan`, and a downloaded signature database.
- Python 3.10 or later for the VirusTotal service.
- A VirusTotal API key for VirusTotal checks. ClamAV scanning works without one.
- Appropriate macOS privacy permissions for the folders you want to monitor or scan.

The included `config/Santa-Standalone.mobileconfig` configures Santa's Monitor mode. Installer verification records are in `config/verified-installers.txt`.

## Install

Install ClamAV and download its signature database before running the project installer. From the repository directory, run:

```sh
./install.sh install
```

The installer builds the app in `~/Applications`, installs background services and the Finder quick action, and starts the services. **It also starts a signature update immediately and schedules another update every six hours**, plus a daily scan at 19:00. Review these settings before installation if you manage updates yourself. The app appears in the menu bar; closing its window does not stop the background services.

After installation, inspect the services with:

```sh
./install.sh status
```

Use these commands separately as needed:

```sh
./install.sh scan-now    # Scan configured folders now
./install.sh update-now  # Update ClamAV signatures now
./install.sh uninstall   # Remove this project's jobs and Finder quick action
```

Uninstall retains settings, quarantine, and logs. After a successful migration, the former standalone VirusTotal watcher and its LaunchAgent are moved to a dated, user-only backup.

## VirusTotal and privacy

The VirusTotal watcher reads `VIRUSTOTAL_API_KEY` from `~/.config/vt-download-watcher/.env`. Keep the key private. Settings are stored in `~/.config/vt-download-watcher/config.json`.

A hash lookup sends the file's SHA-256 hash to VirusTotal. A file upload sends its contents to a third party; only upload files you are permitted to share. `auto_upload_unknown` and `auto_upload_quarantine` are false by default. Enabling these settings or explicitly requesting an upload can send file contents for analysis. VirusTotal responses and API availability depend on the service and your account's limits.

## Settings and logs

Files under `~/Library/Application Support/ClamAV-Automation/` include:

- `scan-paths`: paths for scheduled scans.
- `realtime-paths`: paths for real-time monitoring.
- `Quarantine/`: quarantined files and metadata.
- `realtime-status.json` and `virustotal-status.json`: service status.
- `scan-progress.json`: progress and estimated time remaining.
- `virustotal-quarantine-state.json`: VirusTotal quarantine analysis state.
- `coordination/quarantine.lock`: shared quarantine coordination lock.

Path files accept one absolute path or `$HOME`-relative path per line. Restart the real-time service after changing its paths. Logs and event records are stored under `~/Library/Logs/ClamAV-Automation/`; sensitive project files use user-only permissions.

Long scans first build a manifest of accessible files and deduplicate APFS firmlinks by device and inode. When scanning `/`, the read-only `/System` and mounted drives under `/Volumes` are skipped; select external drives separately. Development directories and user caches are excluded by default.
