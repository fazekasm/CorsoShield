# Installation permissions and per-version readiness

This version front-loads the permissions the operating system permits the owner to grant. It does not claim that an installer can permanently authorize all future file, network or administrator operations.

## macOS

1. Install the app at a permanent Applications location. `bash scripts/install-macos.sh '/path/to/Corso Shield.app'` verifies its bundle identity/signature, stages a per-user install, preserves the old app as a backup, and opens the installed app. It refuses linked paths and asks the owner to quit a foreground Corso process rather than killing a scan. The old background agent is stopped and must be re-enabled after setup.
2. The app automatically opens Permission setup when review/checks are missing. The owner opens Full Disk Access, adds/enables the installed app, returns and checks access. Corso never writes to TCC or resets privacy databases.
3. Checks cover the installed location, ClamAV/FreshClam, private app storage and opening available protected sample files. No protected-file content is read or stored. Sample access can be unavailable or denied; it is not a supported system-wide FDA entitlement query and does not prove child-engine or background access. The owner's confirmation is recorded as a review, not as an OS grant.
4. Settings recovery Keychain preparation is selected by default. Saving the review checks/creates the device-local baseline key; the owner may need to approve the Keychain prompt. They can opt out to configure scanning only. Network-recovery administrator authorization remains an operation-time requirement; installer approval cannot make it permanent.
5. Enable background scans only after the exact app build/location has a saved review and required dependencies/storage pass. A denied or unavailable sample blocks this step unless the owner explicitly accepts limited/unverified scan scope. The app never relabels limited scope as full system protection. Manual scans still report their actual access/errors.
6. The review is bound to the executable's SHA-256 and installed path. A new executable/location requires a new review. The background service and its enable command enforce the check, including after automatic application replacement. The updater may leave a resume marker until the owner completes the new setup. If permissions are revoked later, access failures are reported; review setup again.

Ad-hoc signed development builds may require FDA and Keychain reapproval after replacement. Stable Developer ID signing/notarization is still a release prerequisite for a polished permission experience. No Apple developer identity is provisioned in this project. Camera, microphone, contacts, Accessibility and automation permissions are not requested for antivirus functionality.

## Windows companion beta 0.2

1. Review/verify/unblock the specific downloaded scripts as appropriate for your policy. Run `Install-CorsoShield.ps1` from Windows PowerShell as administrator. `-WhatIf` previews without changing files, shortcuts or permissions.
2. The installer copies the allowlisted app files into Program Files, verifies copy hashes, and protects the directory: SYSTEM/Administrators full control; Users read/execute. It creates a Start Menu shortcut. It refuses linked destinations and an existing install until the owner has preserved/closed it for an explicit upgrade. It does not change execution policy, disable Defender or tamper protection, create exclusions or open firewall ports.
3. The installed launcher requests ordinary UAC elevation for each new session. It refuses automatic elevation from a portable/user-writable location, and refuses a different administrator identity so it cannot silently read/repair the wrong user's proxy settings or DPAPI baselines. Installation elevation is not treated as a permanent app privilege.
4. Each UI launch automatically checks Windows 11 support, elevation for this session, required Defender/firewall commands, Defender active mode and private storage. The Permission setup button rechecks. Protected backend actions also check their own prerequisites. Policy, tamper protection, per-file ACLs and network restrictions can still block an action and remain reported as errors.
5. Standard users who cannot approve same-user elevation may open `Start-CorsoShield.ps1` directly for available read-only health/review actions; administrator operations remain blocked. Do not provide another account's credentials and assume baselines will belong to the original user's profile.

This is a script installer, not a signed MSI/service broker. There is no persistent administrator-token caching, UAC bypass or new Windows background service. A future signed broker could reduce repeated prompts for a narrowly defined action set but is not implemented here.

## Verification

Local Mac tests validate readiness refusal for missing installs/dependencies/current-version receipts and denied samples, plus explicit limited-scope acceptance. Windows CI covers readiness decisions, installer ACL construction, alternate-user rejection, installer WhatIf, PowerShell parsing and hidden GUI initialization. Actual OS grant dialogs, privileged installation, revocation, reboot and per-version FDA/Keychain/UAC behavior require device acceptance testing. Test fixtures do not grant permissions or modify host security settings.

References:
- https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works
