[CmdletBinding()]
param(
    [ValidateSet('Requirements','Health','Threats','QuickScan','FullScan','Update','Remediate','SaveBaseline','PreviewRecovery','Restore','Daily')][string]$Action='Health',
    [string]$BaselineId='', [string]$ExpectedHash='', [int]$Hour=18
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'CorsoShield.psm1') -Force
switch ($Action) {
    Requirements { Get-CorsoRequirements }
    Health { Get-CorsoHealth }
    Threats { $threats=@(Get-CorsoThreats); [pscustomobject]@{Threats=$threats; ActiveHash=(Get-CorsoActiveHash $threats)} }
    QuickScan { Invoke-CorsoScan -Kind QuickScan }
    FullScan { Invoke-CorsoScan -Kind FullScan }
    Update { Update-CorsoSignatures }
    Remediate { Remove-CorsoThreats -ExpectedActiveHash $ExpectedHash -Confirm:$false }
    SaveBaseline { [pscustomobject]@{BaselineId=(Save-CorsoBaseline -Confirm:$false)} }
    PreviewRecovery { Get-CorsoRecoveryPlan $BaselineId }
    Restore { Restore-CorsoSettings -BaselineId $BaselineId -ExpectedCurrentHash $ExpectedHash -Confirm:$false }
    Daily { Set-CorsoDailyScan -Hour $Hour -Confirm:$false }
}
