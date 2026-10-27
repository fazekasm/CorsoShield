# Next platform architecture and retained requirements

Status: macOS app plus Windows companion beta. Planned components below are explicitly labeled.

## Windows companion build

The Windows PowerShell/Windows Forms companion in Windows/ now implements Defender health, scans/signature updates, reviewed remediation, daily Defender scan configuration and same-user DPAPI settings baselines/recovery. A .NET worker service and unprivileged tray/settings client remain future architecture. Keep Microsoft Defender active. Do not register Corso as the primary Windows Security Center antivirus, disable Defender, change exclusions, or force passive mode. Microsoft's documented coexistence behavior varies with Windows and Defender enrollment; verify Defender remains active in the Windows acceptance matrix. Reference: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility

Components: Windows service adapter for lifecycle/scheduling; Defender health adapter reads protection/signature/scan state; optional ClamAV second-opinion adapter runs only on demand or during idle schedules; directory watcher feeds a bounded debounced queue and rescans on overflow; quarantine broker owns ACL-restricted storage and authorizes each request. Named-pipe IPC validates the caller SID. No arbitrary command execution or file deletion endpoint. Default per-user scope; elevation only for a separately reviewed installer/broker. Defender owns real-time protection and ransomware enforcement.

Shared conceptual contracts: Engine.scan(targets, budget) → report {schemaVersion, start/end, scope, engineVersion, signatureVersion, completeness, detections, errors}; Update.check/run → signature status; Scheduler due/completed/retry; Quarantine.review/move/list/restore; Health.snapshot. Keep OS paths and IDs inside adapters. Versioned health JSON example is in contracts/health.schema.json. Next build should implement the service and tray projects, not attempt to compile the SwiftUI app on Windows.

Windows release tests: Windows 11 standard/admin accounts, Defender remains active before/after install, offline signatures, watcher overflow, sleep/resume, service restart, bounded queue, signed MSI uninstall, quarantine ACL/path/race attacks, restore refusal, and CPU/memory measurements on a low-spec PC. Windows PowerShell parser and mocked remediation/recovery tests run in CI; live Defender remediation and GUI acceptance on Windows 11 remain required.

## Family health dashboard: opt-in plan

Each adult device owner explicitly pairs their own device with a short-lived code, sees what is shared, and can revoke locally immediately. No silent family enrollment. Sharing defaults off and remains off in this build. Read-only health includes pseudonymous device ID, platform/app version, last contact, protection health, signature age, last scan completeness and unresolved detection count. Never upload filenames, file content, browsing/network histories or quarantine payloads by default. Family members see only explicitly shared devices. No remote scan/delete/restore shell.

Use per-device credentials in Keychain/Windows credential storage, authenticated TLS, scoped membership authorization on every read, token rotation and revocation, audit records and rate limits. Retain latest status plus 30 days of events, allow export/deletion, display stale/offline distinctly from healthy, and delete membership data on unpair. Implement/test server tenant isolation, revoked/offline clients, consent and deletion before shipping. No dashboard/server or data transmission exists yet.

## macOS further work and release gates

- FDA onboarding: stable Developer ID signed/notarized app and helper identity, service permission tests on supported OS versions; explicit coverage diagnostics. Current settings link is guidance, not an automated grant/check.
- Ransomware: investigate Apple Endpoint Security entitlement and a signed extension for behavioral event analysis; opt-in canary directory, rate heuristics, false-positive fixtures, no automatic process killing until validated. Backups/restore are separate requirements; no guaranteed ransomware rollback.
- USB: opt-in mount event observer with visible exclusions and bounded scan queue; do not automatically execute or quarantine mounted-system files. Test removable media and ejection during scan.
- Network: opt-in local connection metadata with retention controls; a Network Extension requires entitlements, explicit consent and separate review. No TLS interception or packet-content uploads by default.
- Signed application updates: Sparkle and GitHub Releases are implemented in 2.2 with a Keychain-held Ed25519 key, signed feed and archive, and user-confirmed installation. Developer ID signing, notarization and silent installation remain release work. HTTPS signed manifest, version monotonicity, payload verification, atomic install, rollback and key-rotation tests. Windows equivalent: signed installer with pinned publisher verification. FreshClam signature updates are already implemented; they do not update the app/engine.
- Resource policy: measure battery/CPU/RAM, pause on battery/thermal pressure, persistent bounded watcher queue, incremental engine session/clamd when memory budget permits, cancellation/timeouts and guaranteed progress beyond monitor caps.
- Quarantine hardening: descriptor-relative no-follow operations and privileged broker where appropriate, crash-consistent transaction journals and race/failure injection. Current user-owned storage is for reviewed local operations, not hostile same-user containment.
- Testing: signed install/FDA, launchd login/wake/reboot, real download debounce, cap/overflow, update interruption, stale signatures, resource load, log rotation and notarized update tamper tests remain manual/release work.
