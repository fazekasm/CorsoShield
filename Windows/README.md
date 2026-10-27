# Corso Shield Windows companion beta 0.2

This is the first runnable Windows companion, not a finished parity build of the Mac app. It is a native Windows PowerShell 5.1/Windows Forms interface over Microsoft Defender. No extra runtime, browser login, telemetry, custom antivirus driver or always-running Corso service is installed. Requires supported Windows 11 with Defender active. Windows 10 and third-party antivirus/passive-mode configurations have not been validated.

## Launch

1. Download/extract the Windows companion package from the project. Review the source and verify the published package checksum. These scripts are not Authenticode signed.
2. Windows may block downloaded scripts. After verifying the package, right-click each `.ps1`/`.psm1` file → Properties → Unblock, or use `Unblock-File -LiteralPath 'THE_EXACT_VERIFIED_FILE'` for these files. Do not turn off execution policy system-wide and do not bypass corporate policy.
3. For installation, run `& './Install-CorsoShield.ps1'` from Windows PowerShell as administrator after reviewing/verifying the package. It installs into Program Files with protected file permissions and creates a Start Menu shortcut. The installed launcher requests UAC per session and checks prerequisites on startup. It refuses elevation under a different Windows identity; no permanent administrator grant is assumed.
4. For direct portable/read-only use, right-click **Windows PowerShell** → **Run as administrator** as your normal Windows user, change to the extracted folder, and run `& '.\Start-CorsoShield.ps1'`. Administrator rights are needed for Defender scans/remediation and firewall/protection recovery. Standard-user health/read-only operations may still work.
4. **Health** shows whether Defender is active. **Update signatures**, **Quick scan**, and **Full scan** use Defender's existing engine. Defender can automatically remediate during a scan according to its current policy; Corso does not override that policy.
5. **Review threats** shows detections. **Remediate ALL active threats** displays a confirmation and refuses a stale threat list. Microsoft's `Remove-MpThreat` operates on all active detections; Corso does not offer a misleading per-file selection. Afterward inspect Windows Security Protection history and rescan. A successful request is not proof of complete removal.
6. Open **Windows Security / quarantine** to review remediation history or restore a verified false positive. Corso never directly manipulates Defender's protected quarantine files. System/rootkit infections may need an offline scan, supported recovery media or reinstall; this beta does not automatically reboot or run offline recovery.

The `.cmd` launcher uses the installed elevation-aware launcher. It refuses automatic elevation before a protected Program Files install. Directly opening `Start-CorsoShield.ps1` remains available for read-only/explicitly reviewed portable use. Run only reviewed files from a trusted location. No script runs as SYSTEM, no root directory scan is installed by launch, and the companion does not register itself as the Windows primary antivirus or disable Defender, tamper protection, or exclusions.

## Settings recovery

- Save a **trusted baseline** only on a machine/configuration you independently believe are clean. It is a snapshot you trust, not something Corso proves is clean. Capture is refused if any covered Defender protection is disabled or any firewall profile is off.
- Covered values: real-time, behavior, downloaded-file (IOAV) and script scanning enablement; enabled state of Domain/Private/Public firewall profiles; current-user Windows Internet Settings `ProxyEnable`, `ProxyServer` and `AutoConfigURL`.
- Baselines are authenticated/encrypted with Windows DPAPI for the same computer and signed-in Windows user. Do not transfer one from mom's computer to another PC or run the app as a different administrator identity. Baselines and reports live under `%LOCALAPPDATA%\Corso Shield`. Same-user malware is outside the baseline trust boundary.
- Paste the saved baseline ID and click **Preview recovery**. Review every change, then **Restore reviewed settings**. Stale previews are refused, a pre-change backup is saved, and settings are read back before success is reported. Failed recovery attempts proxy rollback; it never re-disables protection to reproduce an insecure pre-change state. Backups containing insecure values cannot be loaded as trusted recovery baselines. Review logs and Windows Security after a partial failure. Proxy changes can interrupt network access; restart affected apps if their cached settings persist.
- Tamper protection, Windows policy or your organization can block changes. Corso reports failure; it does not bypass those controls. It does not restore arbitrary registry trees, DNS, browser-specific preferences, VPN profiles, firewall rules, exclusions, user files, system files, apps or passwords. No Windows System Restore point is created.
- **Set Defender daily quick scan** changes Defender's existing schedule after confirmation. Previous scheduling values are recorded in the local audit. Windows controls signature updates, real-time protection and power/idle behavior. There is no separate Corso scheduler or download watcher in this beta.

## CLI examples

Run from Windows PowerShell as administrator where required:

```powershell
Import-Module .\CorsoShield.psm1
Get-CorsoHealth
Invoke-CorsoScan -Kind QuickScan
$threats = @(Get-CorsoThreats)
$threats | Format-List
# Review ALL active threats before confirming this request:
Remove-CorsoThreats -ExpectedActiveHash (Get-CorsoActiveHash $threats)
$id = Save-CorsoBaseline -Confirm
$plan = Get-CorsoRecoveryPlan $id
$plan | ConvertTo-Json -Depth 8
Restore-CorsoSettings -BaselineId $id -ExpectedCurrentHash $plan.CurrentHash -WhatIf
# Repeat without -WhatIf only after reviewing and confirming.
```

Removal and recovery support `-WhatIf`/`-Confirm`. No automatic Windows app updater is implemented: obtain reviewed updates manually from this GitHub project. Real-time prevention and ongoing detection remain Defender's responsibility, including while this window is closed. Windows family dashboard, ransomware-specific rollback, custom rootkit/reverse-shell probes, tray service, signed MSI and signed automatic app updating are still future work.

## Tests and limits

`powershell.exe -NoProfile -File .\Tests\Run-Tests.ps1` parses the scripts with Windows PowerShell 5.1, initializes the Windows Forms UI without showing it, and runs isolated tests with all Defender/firewall/proxy mutation adapters mocked. It tests DPAPI authentication, recovery planning, backups, read-back, stale/tampered/weak baseline refusal, failure handling, and remediation/WhatIf guards. It never launches a live threat or changes host security settings. GitHub's Windows runner runs this suite. Actual Windows 11 GUI, UAC, live Defender removal, domain policies and restart behavior require device acceptance testing; no mom's-PC installation has been performed.

Microsoft references:
- https://learn.microsoft.com/en-us/powershell/module/defender/remove-mpthreat
- https://learn.microsoft.com/en-us/powershell/module/defender/start-mpscan
- https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility

Permission setup is checked at every launch and by protected actions. See the repository PERMISSIONS.md for the exact grant/verification boundary; install approval cannot suppress future UAC, policy or tamper-protection decisions.
