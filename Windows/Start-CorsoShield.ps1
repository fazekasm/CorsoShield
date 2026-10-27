# Native Windows PowerShell GUI. Does not elevate itself or change execution policy.
#requires -Version 5.1
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$script:workerPath=Join-Path $PSScriptRoot 'Invoke-CorsoAction.ps1'
$script:job=$null; $script:action=''; $script:activeHash=''; $script:previewHash=''; $script:previewId=''
$form=New-Object Windows.Forms.Form
$form.Text='Corso Shield for Windows - companion beta 0.1'; $form.Width=1000; $form.Height=780; $form.MinimumSize=New-Object Drawing.Size(900,700)
$layout=New-Object Windows.Forms.TableLayoutPanel
$layout.Dock='Fill'; $layout.ColumnCount=1; $layout.RowCount=7
$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',62)))
$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',55)))
$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',50)))
$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',50)))
$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',50)))
$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',100)))
$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',48)))
$form.Controls.Add($layout)
$title=New-Object Windows.Forms.Label
$title.Dock='Fill'; $title.Padding=New-Object Windows.Forms.Padding(10)
$title.Text='Corso Shield supplements Microsoft Defender. Defender keeps control of real-time protection, download scanning and quarantine. This is a development companion; no custom Windows service or silent app updater is installed.'
$layout.Controls.Add($title,0,0)
$tools=New-Object Windows.Forms.FlowLayoutPanel; $tools.Dock='Fill'; $layout.Controls.Add($tools,0,1)
$review=New-Object Windows.Forms.FlowLayoutPanel; $review.Dock='Fill'; $layout.Controls.Add($review,0,2)
$baselineRow=New-Object Windows.Forms.FlowLayoutPanel; $baselineRow.Dock='Fill'; $layout.Controls.Add($baselineRow,0,3)
$scheduleRow=New-Object Windows.Forms.FlowLayoutPanel; $scheduleRow.Dock='Fill'; $layout.Controls.Add($scheduleRow,0,4)
$label=New-Object Windows.Forms.Label; $label.Text='Baseline ID:'; $label.AutoSize=$true; $baselineRow.Controls.Add($label)
$baseline=New-Object Windows.Forms.TextBox; $baseline.Width=285; $baselineRow.Controls.Add($baseline)
$hour=New-Object Windows.Forms.NumericUpDown; $hour.Minimum=0; $hour.Maximum=23; $hour.Value=18; $hour.Width=50
$scheduleRow.Controls.Add($hour)
$output=New-Object Windows.Forms.TextBox; $output.Multiline=$true; $output.ReadOnly=$true; $output.ScrollBars='Both'; $output.WordWrap=$true; $output.Dock='Fill'; $output.Font=New-Object Drawing.Font('Consolas',10)
$output.Text='Run health and review threats first. Administrator rights are required for scans/remediation and machine protection settings. Use Windows Security Protection history to review quarantine and restore false positives. No removal or settings restore occurs simply by opening this window.'
$layout.Controls.Add($output,0,5)
$status=New-Object Windows.Forms.Label; $status.Dock='Fill'; $status.Padding=New-Object Windows.Forms.Padding(8); $status.Text='Ready. Windows manages ongoing protection when this window is closed.'
$layout.Controls.Add($status,0,6)
$script:buttons=@()
function Start-CorsoJob([string]$Action,[string]$Id='',[string]$Hash='') {
    if ($null -ne $script:job) { return }
    foreach ($button in $script:buttons) { $button.Enabled=$false }
    $script:action=$Action; $script:previewId=$Id; $status.Text="Working: $Action. Wait for completion before closing."
    $script:job=Start-Job -ArgumentList $script:workerPath,$Action,$Id,$Hash,([int]$hour.Value) -ScriptBlock {
        param($Path,$Action,$Id,$Hash,$Hour)
        $ErrorActionPreference='Stop'
        & $Path -Action $Action -BaselineId $Id -ExpectedHash $Hash -Hour $Hour
    }
}
function Add-CorsoButton($Parent,[string]$Text,[scriptblock]$Handler) {
    $button=New-Object Windows.Forms.Button; $button.Text=$Text; $button.AutoSize=$true; $button.Height=32
    $button.Add_Click($Handler); $Parent.Controls.Add($button); $script:buttons+=$button
}
Add-CorsoButton $tools 'Health' { Start-CorsoJob 'Health' }
Add-CorsoButton $tools 'Review threats' { Start-CorsoJob 'Threats' }
Add-CorsoButton $tools 'Update signatures' { Start-CorsoJob 'Update' }
Add-CorsoButton $tools 'Quick scan' { Start-CorsoJob 'QuickScan' }
Add-CorsoButton $tools 'Full scan' { Start-CorsoJob 'FullScan' }
Add-CorsoButton $review 'Remediate ALL active threats...' {
    if (-not $script:activeHash) { [void][Windows.Forms.MessageBox]::Show('Review threats first.'); return }
    $answer=[Windows.Forms.MessageBox]::Show('Microsoft Defender will remediate ALL currently active detections using its existing policy. This can quarantine or remove files. False positives are possible. Review the displayed threat list first. Continue?','Confirm remediation','YesNo','Warning')
    if ($answer -eq 'Yes') { Start-CorsoJob 'Remediate' '' $script:activeHash; $script:activeHash='' }
}
Add-CorsoButton $review 'Windows Security / quarantine' { Start-Process 'windowsdefender://threat/' }
Add-CorsoButton $review 'Reports and baselines' { Import-Module (Join-Path $PSScriptRoot 'CorsoShield.psm1'); Open-CorsoData }
Add-CorsoButton $baselineRow 'Save trusted baseline...' {
    if ([Windows.Forms.MessageBox]::Show('Only save from a computer and configuration you independently believe are clean. Protection must be enabled. A snapshot is not proof the computer is malware-free. Save this baseline?','Trust settings','YesNo','Warning') -eq 'Yes') { Start-CorsoJob 'SaveBaseline' }
}
Add-CorsoButton $baselineRow 'Preview recovery' { Start-CorsoJob 'PreviewRecovery' $baseline.Text }
Add-CorsoButton $scheduleRow 'Restore reviewed settings...' {
    if (-not $script:previewHash -or $script:previewId -ne $baseline.Text) { [void][Windows.Forms.MessageBox]::Show('Preview this baseline first.'); return }
    if ([Windows.Forms.MessageBox]::Show('Apply only the displayed settings changes? Corso saves a pre-change backup, verifies results and never disables Defender or firewall protection. Proxy changes may interrupt network access. Policy/tamper protection may block changes.','Confirm recovery','YesNo','Warning') -eq 'Yes') { Start-CorsoJob 'Restore' $baseline.Text $script:previewHash; $script:previewHash='' }
}
Add-CorsoButton $scheduleRow 'Set Defender daily quick scan...' {
    if ([Windows.Forms.MessageBox]::Show("Change Defender's existing schedule to a daily quick scan at $($hour.Value):15? Previous scheduling values are recorded in the local audit log. Windows manages signature updates and idle/power conditions.",'Confirm schedule','YesNo','Question') -eq 'Yes') { Start-CorsoJob 'Daily' }
}
$timer=New-Object Windows.Forms.Timer; $timer.Interval=500
$timer.Add_Tick({
    if ($null -eq $script:job -or $script:job.State -in @('Running','NotStarted')) { return }
    try {
        $result=Receive-Job $script:job -ErrorAction Stop
        $output.Text=($result | ConvertTo-Json -Depth 12)
        if ($script:action -eq 'Threats') { $script:activeHash=$result.ActiveHash }
        if ($script:action -eq 'SaveBaseline') { $baseline.Text=$result.BaselineId }
        if ($script:action -eq 'PreviewRecovery') { $script:previewHash=$result.CurrentHash }
        $status.Text='Action completed. Read the result and Windows Security history; completion is not proof of a clean system.'
    } catch { $output.Text=$_.Exception.Message; $status.Text='Action failed or was blocked. No success is asserted.' }
    finally { Remove-Job $script:job -Force; $script:job=$null; foreach ($button in $script:buttons) { $button.Enabled=$true } }
})
$form.Add_FormClosing({ param($sender,$event) if ($null -ne $script:job) { $event.Cancel=$true; [void][Windows.Forms.MessageBox]::Show('An operation is still running. Wait for it to finish before closing. If Defender remains busy, inspect Windows Security. Closing Corso is not a reliable way to cancel a system scan.') } })
$timer.Start(); [void]$form.ShowDialog(); $timer.Dispose(); $form.Dispose()
