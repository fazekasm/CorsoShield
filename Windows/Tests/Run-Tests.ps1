# Dependency-free tests. All system mutation adapters are mocked inside the imported module.
# Real Windows Defender, firewall and proxy settings are NEVER written by these tests.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent
$errors=@()
Get-ChildItem $root -Recurse -Include *.ps1,*.psm1 | ForEach-Object {
    $tokens=$null; $parseErrors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$parseErrors)
    $errors+=@($parseErrors)
}
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
Import-Module (Join-Path $root 'CorsoShield.psm1') -Force
$module=Get-Module CorsoShield
$storage=Join-Path ([IO.Path]::GetTempPath()) ('Corso-tests-'+[Guid]::NewGuid())
function Assert($Value,[string]$Message) { if (-not $Value) { throw "ASSERT: $Message" } }
function Assert-Throws([scriptblock]$Work,[string]$Message) { $threw=$false; try { & $Work } catch { $threw=$true }; Assert $threw $Message }
try {
    & $module {
        param($Storage)
        $script:CorsoRoot=$Storage
        $script:settings=[pscustomobject][ordered]@{DisableRealtimeMonitoring=$false; DisableBehaviorMonitoring=$false; DisableIOAVProtection=$false; DisableScriptScanning=$false; FirewallDomain=$true; FirewallPrivate=$true; FirewallPublic=$true; ProxyEnable=0; ProxyServer=$null; AutoConfigURL=$null}
        $script:threats=@([pscustomobject]@{ThreatID=10;ThreatName='Harmless mocked detection';IsActive=$true;Resources=@('file:_C:\fixture.txt')})
        $script:removals=0; $script:writes=0; $script:failProxy=$false
        function script:Assert-CorsoAdmin {}
        function script:Assert-CorsoDefenderActive {}
        function script:Get-CorsoIdentity { 'mock-device/mock-user' }
        function script:Get-CorsoSettings { return $script:settings.PSObject.Copy() }
        function script:Get-CorsoThreats { return $script:threats }
        function script:Remove-MpThreat { $script:removals++; $script:threats=@() }
        function script:Set-CorsoSetting([string]$Name,$Value) {
            $script:writes++
            if ($script:failProxy -and $Name -eq 'ProxyEnable') { throw 'Mocked proxy write failure' }
            $script:settings.$Name=$Value
        }
    } $storage
    $id=Save-CorsoBaseline -Confirm:$false
    Assert ([Guid]::Parse($id) -ne [Guid]::Empty) 'trusted baseline ID'
    Assert-Throws { Get-CorsoRecoveryPlan '../escape' } 'path traversal must fail'
    $plan=Get-CorsoRecoveryPlan $id
    Assert ($plan.Changes.Count -eq 0) 'unchanged baseline'
    & $module { $script:settings.ProxyEnable=1; $script:settings.ProxyServer='example.invalid:8080'; $script:settings.DisableRealtimeMonitoring=$true }
    $plan=Get-CorsoRecoveryPlan $id
    Assert ($plan.Changes.Count -eq 3) 'proxy + protection drift'
    Restore-CorsoSettings -BaselineId $id -ExpectedCurrentHash $plan.CurrentHash -WhatIf
    Assert ((& $module {$script:writes}) -eq 0) 'WhatIf must not write settings'
    Assert-Throws { Restore-CorsoSettings -BaselineId $id -ExpectedCurrentHash ('0'*64) -Confirm:$false } 'stale preview rejection'
    $result=Restore-CorsoSettings -BaselineId $id -ExpectedCurrentHash $plan.CurrentHash -Confirm:$false
    Assert $result.Verified 'verified recovery'
    Assert ((Get-CorsoRecoveryPlan $id).Changes.Count -eq 0) 'read-back match'
    Assert (Test-Path (Join-Path (Join-Path $storage 'Baselines') ($result.BackupId+'.bin'))) 'pre-change backup exists'
    & $module { $script:settings.FirewallPrivate=$false }
    Assert-Throws { Save-CorsoBaseline -Confirm:$false } 'weak firewall baseline refused'
    & $module { $script:settings.FirewallPrivate=$true; $script:settings.DisableScriptScanning=$true }
    Assert-Throws { Save-CorsoBaseline -Confirm:$false } 'disabled protection baseline refused'
    & $module { $script:settings.DisableScriptScanning=$false; $script:settings.ProxyEnable=1; $script:failProxy=$true }
    $plan=Get-CorsoRecoveryPlan $id
    Assert-Throws { Restore-CorsoSettings -BaselineId $id -ExpectedCurrentHash $plan.CurrentHash -Confirm:$false } 'write failure must not report success'
    & $module { $script:failProxy=$false; $script:settings.ProxyEnable=0 }
    # DPAPI authentication rejects tampered baseline bytes.
    $file=Join-Path (Join-Path $storage 'Baselines') ($id+'.bin')
    $bytes=[IO.File]::ReadAllBytes($file); $original=$bytes.Clone(); $bytes[32]=$bytes[32] -bxor 1; [IO.File]::WriteAllBytes($file,$bytes)
    Assert-Throws { Get-CorsoRecoveryPlan $id } 'tampered baseline must fail'
    [IO.File]::WriteAllBytes($file,$original)
    $hash=Get-CorsoActiveHash (Get-CorsoThreats)
    Remove-CorsoThreats -ExpectedActiveHash $hash -WhatIf
    Assert ((& $module {$script:removals}) -eq 0) 'WhatIf must not remediate'
    Assert-Throws { Remove-CorsoThreats -ExpectedActiveHash ('0'*64) -Confirm:$false } 'changed detections refused'
    Remove-CorsoThreats -ExpectedActiveHash $hash -Confirm:$false | Out-Null
    Assert ((& $module {$script:removals}) -eq 1) 'Defender remediation adapter called exactly once'
    Assert (@(Get-CorsoThreats).Count -eq 0) 'mocked remediation result'
    Write-Output 'PASS: PowerShell 5.1 syntax, DPAPI baseline integrity, recovery plan, backup/read-back, stale/tampered/weak baseline refusal, failure handling, remediation and WhatIf guards. No host security settings changed.'
} finally { Remove-Module CorsoShield; if (Test-Path $storage) { Remove-Item -LiteralPath $storage -Recurse -Force } }
