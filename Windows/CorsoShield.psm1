# Windows PowerShell 5.1; no third-party modules or changes to Defender's provider registration.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:CorsoRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Corso Shield'
$script:ProtectionKeys = @('DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableIOAVProtection','DisableScriptScanning')
$script:SettingKeys = $script:ProtectionKeys + @('FirewallDomain','FirewallPrivate','FirewallPublic','ProxyEnable','ProxyServer','AutoConfigURL')
function Initialize-Corso {
    [void][IO.Directory]::CreateDirectory($script:CorsoRoot)
    foreach ($name in @('Baselines','Reports')) { [void][IO.Directory]::CreateDirectory((Join-Path $script:CorsoRoot $name)) }
}
function Assert-CorsoWindows {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'This companion requires Windows 11 and Windows PowerShell 5.1.' }
}
function Assert-CorsoAdmin {
    Assert-CorsoWindows
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open Windows PowerShell as administrator to run this action. Corso does not bypass UAC or tamper protection.' }
}
function Get-CorsoIdentity {
    $machine = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    return "$machine/$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
}
function Get-CorsoHash([string]$Text) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
}
function Write-CorsoAudit([string]$Action, $Result) {
    Initialize-Corso
    $record = [ordered]@{ Schema=1; At=[DateTime]::UtcNow.ToString('o'); Action=$Action; Result=$Result }
    $name = 'action-' + [Guid]::NewGuid().ToString() + '.json'
    [IO.File]::WriteAllText((Join-Path (Join-Path $script:CorsoRoot 'Reports') $name), ($record | ConvertTo-Json -Depth 12))
    Get-ChildItem (Join-Path $script:CorsoRoot 'Reports') -Filter 'action-*.json' | Sort-Object LastWriteTime -Descending | Select-Object -Skip 100 | Remove-Item -Force
}
function Get-CorsoHealth {
    Assert-CorsoWindows
    $status = Get-MpComputerStatus
    return [pscustomobject]@{ Platform='Windows'; AntimalwareEnabled=$status.AMServiceEnabled; AntivirusEnabled=$status.AntivirusEnabled; DefenderMode=$status.AMRunningMode; RealTimeProtection=$status.RealTimeProtectionEnabled; SignaturesUpdated=$status.AntivirusSignatureLastUpdated; LastQuickScan=$status.QuickScanEndTime; LastFullScan=$status.FullScanEndTime; TamperProtected=$status.IsTamperProtected; Note='Defender owns real-time protection, download scanning, remediation and quarantine. Corso does not replace its provider.' }
}
function Assert-CorsoDefenderActive {
    $status = Get-MpComputerStatus
    if (-not $status.AMServiceEnabled -or -not $status.AntivirusEnabled -or $status.AMRunningMode -ne 'Normal') { throw 'Defender is unavailable, passive or not the active antivirus. Corso will not disable another antivirus or force Defender into a different mode.' }
}
function Read-CorsoDefenderThreats { Get-MpThreat }
function Get-CorsoThreats {
    Assert-CorsoWindows
    return @(Read-CorsoDefenderThreats | Select-Object ThreatID,ThreatName,SeverityID,CategoryID,IsActive,DidThreatExecute,Resources)
}
function Get-CorsoActiveHash($Threats) {
    if ($null -eq $Threats) { return Get-CorsoHash '' }
    $ids = @($Threats | Where-Object { $null -ne $_ -and $_.IsActive } | ForEach-Object { ([string]$_.ThreatID) + ':' + (@($_.Resources | Sort-Object) -join '|') } | Sort-Object -Unique)
    return Get-CorsoHash ($ids -join ',')
}
function Invoke-CorsoScan {
    [CmdletBinding()]
    param([ValidateSet('QuickScan','FullScan')][string]$Kind='QuickScan')
    Assert-CorsoAdmin; Assert-CorsoDefenderActive
    # Defender can remediate during scanning according to its existing policy.
    Start-MpScan -ScanType $Kind
    $result = [pscustomobject]@{ Requested=$Kind; CompletedAt=[DateTime]::UtcNow.ToString('o'); Threats=@(Get-CorsoThreats); Note='Review Windows Security Protection history. No claim that every threat was removed.' }
    Write-CorsoAudit 'Scan' $result; return $result
}
function Update-CorsoSignatures {
    Assert-CorsoAdmin; Assert-CorsoDefenderActive
    Update-MpSignature
    $health = Get-CorsoHealth; Write-CorsoAudit 'SignatureUpdate' $health; return $health
}
function Remove-CorsoThreats {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param([Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedActiveHash)
    Assert-CorsoAdmin; Assert-CorsoDefenderActive
    $before = @(Get-CorsoThreats)
    if ((Get-CorsoActiveHash $before) -ne $ExpectedActiveHash) { throw 'The active threat list changed since review. Refresh and review again.' }
    if (@($before | Where-Object IsActive).Count -eq 0) { return 'No active Defender threats are currently reported.' }
    if ($PSCmdlet.ShouldProcess('ALL active Defender threats on this computer','Run Microsoft Defender remediation (quarantine/removal per Defender policy)')) {
        # Remove-MpThreat has no supported per-ID selection: do not pretend otherwise.
        Remove-MpThreat
        $after = @(Get-CorsoThreats)
        $result = [pscustomobject]@{ Before=$before; After=$after; StillActive=@($after | Where-Object IsActive).Count; Note='The remediation request completed. Review Protection history and rescan; running malware/persistence may remain.' }
        Write-CorsoAudit 'DefenderRemediation' $result; return $result
    }
}
function Get-CorsoSettings {
    Assert-CorsoWindows
    $p = Get-MpPreference
    $values = [ordered]@{}
    foreach ($key in $script:ProtectionKeys) { $values[$key] = [bool]$p.$key }
    foreach ($name in @('Domain','Private','Public')) { $values['Firewall'+$name] = [bool](Get-NetFirewallProfile -Name $name).Enabled }
    $path = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $values.ProxyEnable = [int][Microsoft.Win32.Registry]::GetValue($path,'ProxyEnable',0)
    $values.ProxyServer = [Microsoft.Win32.Registry]::GetValue($path,'ProxyServer',$null)
    $values.AutoConfigURL = [Microsoft.Win32.Registry]::GetValue($path,'AutoConfigURL',$null)
    return [pscustomobject]$values
}
function Assert-CorsoSettings($Settings) {
    $names = @($Settings.PSObject.Properties.Name)
    if ($names.Count -ne $script:SettingKeys.Count -or @($names | Where-Object { $_ -notin $script:SettingKeys }).Count -gt 0) { throw 'Baseline contains missing or unsupported settings.' }
    foreach ($key in $script:ProtectionKeys) {
        if ($Settings.$key -isnot [bool] -or $Settings.$key) { throw "Recovery cannot disable Defender protection: $key" }
    }
    foreach ($key in @('FirewallDomain','FirewallPrivate','FirewallPublic')) {
        if ($Settings.$key -isnot [bool] -or -not $Settings.$key) { throw 'A trusted baseline must keep every firewall profile enabled.' }
    }
    if ($Settings.ProxyEnable -notin @(0,1)) { throw 'Invalid proxy state' }
    foreach ($key in @('ProxyServer','AutoConfigURL')) {
        if ($null -ne $Settings.$key -and ($Settings.$key -isnot [string] -or $Settings.$key.Length -gt 2048 -or $Settings.$key.Contains("`n") -or $Settings.$key.Contains('@'))) { throw 'Unsupported proxy setting; credentials are not stored.' }
    }
    if ($Settings.ProxyEnable -eq 1 -and [string]::IsNullOrWhiteSpace($Settings.ProxyServer)) { throw 'Enabled proxy requires a server' }
    if (-not [string]::IsNullOrEmpty($Settings.AutoConfigURL)) {
        $uri = $null
        if (-not [Uri]::TryCreate($Settings.AutoConfigURL,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -notin @('http','https') -or $uri.UserInfo) { throw 'Only HTTP(S) PAC URLs without credentials are supported' }
    }
}
function Get-CorsoSettingsHash($Settings) {
    $ordered = [ordered]@{}
    foreach ($key in $script:SettingKeys) { $ordered[$key] = $Settings.$key }
    return Get-CorsoHash ($ordered | ConvertTo-Json -Compress)
}
function Save-CorsoSnapshot($Settings, [string]$Purpose) {
    Initialize-Corso
    Add-Type -AssemblyName System.Security
    $id = [Guid]::NewGuid().ToString()
    $snapshot = [ordered]@{ Schema=1; Id=$id; Created=[DateTime]::UtcNow.ToString('o'); Identity=(Get-CorsoIdentity); Purpose=$Purpose; Settings=$Settings }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($snapshot | ConvertTo-Json -Depth 8 -Compress))
    $protected = [Security.Cryptography.ProtectedData]::Protect($bytes,[Text.Encoding]::UTF8.GetBytes('CorsoSettingsV1'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.File]::WriteAllBytes((Join-Path (Join-Path $script:CorsoRoot 'Baselines') ($id+'.bin')), $protected)
    return $id
}
function Save-CorsoBaseline {
    [CmdletBinding(SupportsShouldProcess=$true)]param()
    $settings = Get-CorsoSettings
    Assert-CorsoSettings $settings
    if ($PSCmdlet.ShouldProcess('Current network/protection settings','Save a baseline you independently believe is trusted')) { return Save-CorsoSnapshot $settings 'TrustedBaseline' }
}
function Read-CorsoBaseline([string]$Id) {
    $uuid = [Guid]::Empty
    if (-not [Guid]::TryParseExact($Id,'D',[ref]$uuid)) { throw 'Invalid baseline ID' }
    Add-Type -AssemblyName System.Security
    $bytes = [IO.File]::ReadAllBytes((Join-Path (Join-Path $script:CorsoRoot 'Baselines') ($uuid.ToString()+'.bin')))
    $clear = [Security.Cryptography.ProtectedData]::Unprotect($bytes,[Text.Encoding]::UTF8.GetBytes('CorsoSettingsV1'),[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $snapshot = [Text.Encoding]::UTF8.GetString($clear) | ConvertFrom-Json
    if ($snapshot.Schema -ne 1 -or $snapshot.Identity -ne (Get-CorsoIdentity)) { throw 'Baseline is for another computer/user or schema' }
    Assert-CorsoSettings $snapshot.Settings
    return $snapshot
}
function Get-CorsoRecoveryPlan([string]$BaselineId) {
    $baseline = Read-CorsoBaseline $BaselineId
    $current = Get-CorsoSettings
    $changes = @()
    foreach ($key in $script:SettingKeys) {
        if (($current.$key | ConvertTo-Json -Compress) -cne ($baseline.Settings.$key | ConvertTo-Json -Compress)) { $changes += [pscustomobject]@{ Setting=$key; Before=$current.$key; After=$baseline.Settings.$key } }
    }
    return [pscustomobject]@{ BaselineId=$BaselineId; Saved=$baseline.Created; CurrentHash=(Get-CorsoSettingsHash $current); Changes=$changes; Note='Only allowlisted Defender flags, firewall enabled states and current-user HTTP/PAC proxy values are covered. Baseline is not proof of a clean machine.' }
}
function Set-CorsoSetting([string]$Name, $Value) {
    if ($Name -in $script:ProtectionKeys) {
        if ($Value -ne $false) { throw 'Refusing to disable protection' }
        $preferences = @{}; $preferences[$Name] = $false
        Set-MpPreference @preferences
    } elseif ($Name -in @('FirewallDomain','FirewallPrivate','FirewallPublic')) {
        if ($Value -ne $true) { throw 'Refusing to disable firewall' }
        Set-NetFirewallProfile -Name $Name.Substring(8) -Enabled True
    } elseif ($Name -in @('ProxyEnable','ProxyServer','AutoConfigURL')) {
        $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        if ($null -eq $Value) { Remove-ItemProperty -LiteralPath $path -Name $Name -ErrorAction SilentlyContinue }
        elseif ($Name -eq 'ProxyEnable') { New-ItemProperty -LiteralPath $path -Name $Name -Value ([int]$Value) -PropertyType DWord -Force | Out-Null }
        else { New-ItemProperty -LiteralPath $path -Name $Name -Value ([string]$Value) -PropertyType String -Force | Out-Null }
    } else { throw 'Setting is not allowlisted' }
}
function Restore-CorsoSettings {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param([Parameter(Mandatory)][string]$BaselineId, [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedCurrentHash)
    Assert-CorsoAdmin
    $plan = Get-CorsoRecoveryPlan $BaselineId
    if ($plan.CurrentHash -ne $ExpectedCurrentHash) { throw 'Settings changed since preview; review again.' }
    if (-not $PSCmdlet.ShouldProcess('The reviewed settings on this computer','Apply baseline with backup and read-back verification')) { return }
    $before = Get-CorsoSettings
    if ((Get-CorsoSettingsHash $before) -ne $ExpectedCurrentHash) { throw 'Settings changed before backup; review again.' }
    $backup = Save-CorsoSnapshot $before 'PreRecoveryBackup'
    $applied = @()
    try {
        foreach ($change in $plan.Changes) { $applied += $change; Set-CorsoSetting $change.Setting $change.After }
        $after = Get-CorsoRecoveryPlan $BaselineId
        if ($after.Changes.Count -gt 0) { throw 'Read-back mismatch. Policy or tamper protection may have blocked recovery.' }
        $result = [pscustomobject]@{ Verified=$true; BackupId=$backup; Applied=$plan.Changes }
        Write-CorsoAudit 'SettingsRecovery' $result; return $result
    } catch {
        $problem = $_.Exception.Message
        $rollbackErrors = @()
        # Do not re-disable security during rollback. Revert proxy changes only.
        foreach ($change in $applied | Where-Object Setting -In @('ProxyEnable','ProxyServer','AutoConfigURL')) {
            try { Set-CorsoSetting $change.Setting $change.Before } catch { $rollbackErrors += $_.Exception.Message }
        }
        Write-CorsoAudit 'SettingsRecoveryFailed' @{ Error=$problem; BackupId=$backup; RollbackErrors=$rollbackErrors; Note='Protection re-enabling is not rolled back to an insecure state.' }
        throw "Recovery incomplete: $problem Backup: $backup. Proxy rollback errors: $($rollbackErrors -join '; '). Review Windows Security/network settings."
    }
}
function Set-CorsoDailyScan {
    [CmdletBinding(SupportsShouldProcess=$true)]param([ValidateRange(0,23)][int]$Hour=18)
    Assert-CorsoAdmin; Assert-CorsoDefenderActive
    if ($PSCmdlet.ShouldProcess('Microsoft Defender existing scan scheduler',"Schedule a daily quick scan at ${Hour}:15")) {
        $p = Get-MpPreference
        $backup = @{ Day=$p.ScanScheduleDay; Time=$p.ScanScheduleTime; Parameters=$p.ScanParameters }
        Write-CorsoAudit 'PreScheduleChange' $backup
        Set-MpPreference -ScanScheduleDay 0 -ScanScheduleTime ([datetime]::Today.AddHours($Hour).AddMinutes(15)) -ScanParameters 1
        $after = Get-MpPreference
        if ([int]$after.ScanScheduleDay -ne 0 -or [int]$after.ScanParameters -ne 1 -or $after.ScanScheduleTime.Hour -ne $Hour -or $after.ScanScheduleTime.Minute -ne 15) { throw 'Schedule read-back mismatch; your organization or Windows policy may control it.' }
        return 'Defender daily quick-scan schedule verified. Windows manages signature updates and power/idle conditions.'
    }
}
function Open-CorsoProtectionHistory { Start-Process 'windowsdefender://threat/' }
function Open-CorsoData { Initialize-Corso; Start-Process explorer.exe -ArgumentList $script:CorsoRoot }
Export-ModuleMember -Function Get-CorsoHealth,Get-CorsoThreats,Get-CorsoActiveHash,Invoke-CorsoScan,Update-CorsoSignatures,Remove-CorsoThreats,Save-CorsoBaseline,Get-CorsoRecoveryPlan,Restore-CorsoSettings,Set-CorsoDailyScan,Open-CorsoProtectionHistory,Open-CorsoData
