# Corso Shield macOS 2.3 — development build

Continues the original SwiftUI/ClamAV project. Requires macOS 13+, an Apple Silicon or Intel Mac for the universal release binary, and Homebrew ClamAV. No telemetry or cloud dashboard is enabled. This is supplemental scanning, not a replacement for Apple's protections or a production endpoint security product.

## Install and run

1. Install ClamAV using your existing Homebrew installation: `brew install clamav`.
2. Copy `dist/Corso Shield.app` to a permanent location, preferably `/Applications`. If replacing the previous build, first disable its schedules. The new Enable background service action also removes the old update/scan launch agents.
3. Open the app. This local development build is ad-hoc signed, not Developer ID signed or notarized. If macOS blocks it, review the source/build locally; do not disable Gatekeeper globally.
4. Click **Permission setup…**. In System Settings → Privacy & Security → Full Disk Access, add the installed Corso Shield.app and enable it. macOS requires explicit consent; Corso cannot grant this automatically. Restart the service after changing permission. Depending on macOS attribution, the engine may also need approval; inspect scan logs for denied paths. Do not grant your terminal broad access just to hide permission failures. This build cannot prove system-wide FDA coverage. Replacing/moving an ad-hoc signed build can require reapproval.
5. Click **Update signatures**, then **Quick scan** to verify the engine works. Review warnings and skipped files, not only the exit status.
6. Click **Enable background service**. It starts immediately and at subsequent sign-ins. Close the window if desired; the separate launch agent continues. **Stop background service** unloads it. Nothing installs or runs as root.

To build from source on Apple Silicon or Intel with Apple command-line tools:

```sh
bash scripts/build.sh
bash scripts/test-safety.sh
bash scripts/test-core.sh
```

The build uses the host architecture. `swift test` additionally requires an Xcode installation with XCTest. The build downloads the checksum-pinned official Sparkle framework. ClamAV signature updates require network access. No service is enabled by building or running tests.

## Implemented behavior

- SwiftUI manual quick/custom scans, reports, manual signature updates and reviewed quarantine.
- Quiet per-user launch agent, single service instance, background process priority and low-priority I/O. Scans/updates serialize across the GUI and service; a busy operation returns an error and service retries later.
- Daily rolling 24-hour signature updates and Downloads/Desktop scans, immediately when first enabled. Successful timestamps persist. Missed work runs after sign-in/wake; failures retry no more often than hourly. No scheduled work runs while signed out or shut down. Daily scan time is not user-configurable in this version.
- Downloads polling every 60 seconds with two unchanged size/mtime observations before scanning. At most 20 files per batch and 5,000 enumerated entries per poll. Hidden files, packages and known partial-download suffixes are excluded. New and modified regular files are considered; initial files are also scanned. Memory cache resets at restart. This can miss actively changing files or files executed/deleted between polls. Entry caps can starve deeper entries; custom scans cover those separately.
- Automatic mode is enable-and-leave-running scheduling/monitoring; advanced mode is manual target selection and review. Neither automatically removes threats. No desktop notifications yet: inspect reports and logs regularly.
- Quarantine checks SHA-256, regular-file type, user-home boundary, symlinks and hard links; payloads have execution/read permissions removed. Restore checks the digest and refuses overwrites, linked parents, invalid IDs and destinations outside home. Restore creates owner-only non-executable files and retains the inert quarantine copy. Use the quarantine folder UUID in the restore field only after confirming a false positive.
- App data: `~/Library/Application Support/Corso Shield`. Reports/scan logs retain newest 100 each while the service runs. Quarantine is never auto-purged. Logs include local paths; protect them when sharing.

Limits: files over 100 MB and archive expanded data over 400 MB can be skipped. A zero engine exit is not proof every byte was inspected. ClamAV startup reloads databases for each batch: idle work is bounded, but scan CPU/RAM is not hard-capped or benchmarked. Signature updates use FreshClam's validation. App updates use signed GitHub Releases with installation confirmation while the frontend is open. ClamAV engine upgrades remain manual. Same-user malware can tamper with a user-owned scanner or its quarantine; no tamper resistance or race-proof privileged file broker is claimed. Restore does not make infected content safe. Quarantine is restricted to user files, not system remediation.

## Uninstall

Click Stop background service first, quit the app, then remove the application. The service plist is `~/Library/LaunchAgents/local.corso.shield.background.plist`. If the UI is unavailable, run `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/local.corso.shield.background.plist`, then remove that plist. Keep application support data until you have reviewed quarantined files; deleting it destroys those recovery copies.

## Rootkit and reverse-shell indicators (2.1)

Click **Security indicators** to run an on-demand check. The background service also runs it at startup and every 15 minutes between scan/update jobs; long scans can delay it. Findings and coverage notes are saved locally in `security-indicators.json` under application support. This is a latest snapshot, overwritten each check; it is not a persistent incident history. No process termination, network blocking or automated rootkit removal occurs.

Reverse-shell checks correlate visible established TCP socket owners (`lsof`) with shell process IDs (`ps`) and look for command-line patterns such as network redirection, socket-to-process wiring, and network tools executing shells. A shell owning a TCP socket is a review signal, not a confirmed reverse shell. Developer tooling and quoted examples can trigger patterns. Obfuscated, encrypted, UDP-only, short-lived and child-process-mediated shells can be missed. Process names/arguments can be spoofed; PID reuse between snapshots is possible. No SSH sessions are flagged merely for using SSH.

Rootkit indicators check SIP status and verify up to 16 installed third-party `.kext` bundles in `/Library/Extensions` with Apple's `codesign`. Disabled/custom SIP or failed signature verification is evidence to investigate, not proof of infection. Installed bundles are not necessarily loaded. Valid signatures and enabled SIP do not prove absence of rootkits. There is no kernel-memory, hidden-process, firmware, boot-integrity or complete loaded-extension inspection. Do not disable SIP to enable these checks. See [Apple's kernel security overview](https://support.apple.com/guide/security/sec8e454101b/web).

Probes have eight-second individual timeouts and four-MB read caps; the output-file threshold is sampled, so a probe may briefly exceed it. Up to 16 extension checks can lengthen a pass. No elevation is requested: process/socket visibility is restricted by the current account, and Full Disk Access does not grant kernel visibility. Coverage failures appear explicitly. Raw process arguments are used for matching but are not included in the saved snapshot. Probe output is briefly stored in owner-only temporary files and removed on normal completion; a crash can leave `Logs/probe-*.tmp` containing sensitive arguments. Do not share raw probe files.

CLI: run the installed app's `Contents/MacOS/CorsoShield --security-check`. Exit 0 means no indicators observed within stated coverage, 1 means findings to review, and 2 means the overall check could not be saved/run. Individual probe failures are recorded in coverage even if the exit is 0. Read coverage notes every time. Results are local and do not constitute incident diagnosis.

## Not implemented

Behavioral ransomware detection/blocking or recovery, USB insertion monitoring, network intrusion monitoring, execution-time interception, Windows custom service and family dashboard. A runnable Windows PowerShell companion beta is in [Windows/README.md](Windows/README.md). See ARCHITECTURE.md for the concrete design and release gates. No unavailable assistant messages from the prior conversation were reconstructed or treated as implemented features.

## Reference documentation

- Apple: https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox
- ClamAV: https://docs.clamav.net/manual/Usage/Scanning.html
- FreshClam: https://docs.clamav.net/manual/Usage/Configuration.html

## Signed GitHub app updates (2.2)

Use **Check for app updates…** or leave the frontend open for daily checks. Download/install uses signed GitHub release assets and requires confirmation. See [UPDATES.md](UPDATES.md) for trust, service restart behavior, and publishing instructions. The background scan service alone does not check for app updates.

## Reviewed removal and settings recovery (2.3)

Select a saved ClamAV report and use **Remove detected files to quarantine…**. This removes detected regular user files from their original locations, rechecks each digest, logs partial failures, and retains restore copies. Virus, Trojan and spyware signatures use the same scanner/remediation path; detection category alone does not authorize deleting arbitrary files. Scan again afterward. This is containment/removal of detected files, not disinfection of documents, automatic removal of running processes or complete persistence/rootkit cleanup. System files and heuristic-only process findings are not automatically removed.

Use **Settings recovery…** to save a trusted baseline of DNS and the HTTP proxy for one exact network service (for example Wi-Fi). Save it only after independently verifying the configuration is trusted. Baselines are authenticated using a device-local Keychain key and tied to the same Mac. Restore requires a preview, refuses changed settings, saves a pre-change snapshot, applies only the covered settings, and verifies the result. On failure it attempts rollback and reports rollback failures. These operations may require administrator rights and can interrupt connectivity. No privileges are bypassed. Read-only parsing/authentication tests passed; live network writes have not been executed on your Mac.

This version does not capture credentials or automatically recover arbitrary system preferences, firewall/VPN/browser settings, HTTPS/SOCKS/PAC proxy values, system files, encrypted files or deleted documents. Existing settings cannot be reconstructed if no trusted baseline exists. Keychain access and actual authorized network recovery require desktop acceptance testing. Same-user malware can invoke the app/account APIs, so the baseline is not tamper-proof against a fully compromised login session.

## Windows companion beta 0.1

See [Windows/README.md](Windows/README.md) for a runnable Windows PowerShell/Windows Forms application, Defender virus/Trojan/spyware remediation, trusted settings baselines, recovery previews and installation steps. Defender supplies real-time protection and its existing scheduler. The Windows beta does not implement the planned custom background service, signed MSI, signed app updater or family dashboard. No Windows machine has been installed or remediated by this task.
