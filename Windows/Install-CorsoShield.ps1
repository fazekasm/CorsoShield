# Explicit administrator installer into Program Files; no UAC/Defender/policy bypass.
#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]param()
$ErrorActionPreference='Stop'
$files=@('CorsoShield.psm1','Invoke-CorsoAction.ps1','Start-CorsoShield.ps1','Launch-CorsoShield.ps1','Install-Helpers.ps1','README.md')
foreach ($name in $files) { if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $name) -PathType Leaf)) { throw "Incomplete package: $name" } }
$destination=Join-Path $env:ProgramFiles 'Corso Shield'
if (-not $PSCmdlet.ShouldProcess($destination,'Install reviewed companion and create an administrator-prompting Start Menu shortcut')) { return }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this reviewed installer from Windows PowerShell as administrator. Installation approval does not grant administrator rights to all future app sessions.'
}
if ([IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') -eq [IO.Path]::GetFullPath($destination).TrimEnd('\')) { throw 'Extract the installer to a separate folder before installing/upgrading.' }
if (Test-Path -LiteralPath $destination) {
    $item=Get-Item -LiteralPath $destination -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'A linked install directory is refused.' }
    throw 'An installation already exists. Close Corso, preserve its folder as a backup, and rerun this installer. Baselines in LocalAppData are not removed.'
}
[void][IO.Directory]::CreateDirectory($destination)
# Protect scripts used by elevated launches against standard-user modification.
. (Join-Path $PSScriptRoot 'Install-Helpers.ps1')
$acl=New-CorsoInstallAcl
Set-Acl -LiteralPath $destination -AclObject $acl
foreach ($name in $files) {
    $source=Join-Path $PSScriptRoot $name
    if ((Get-Item -LiteralPath $source -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked package files are refused.' }
    $target=Join-Path $destination $name
    Copy-Item -LiteralPath $source -Destination $target
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash) { throw "Copy verification failed: $name" }
}
$receipt=[ordered]@{ Version='0.2'; InstalledAt=[DateTime]::UtcNow.ToString('o'); InstallationUsedAdminToken=$true; FutureLaunchRequiresUAC=$true; DefenderTamperProtectionBypassed=$false; ProtectionReady=$false }
$receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'installation.json') -Encoding UTF8
$shell=New-Object -ComObject WScript.Shell
$shortcut=$shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Corso Shield.lnk'))
$shortcut.TargetPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$shortcut.Arguments='-NoProfile -STA -File "'+(Join-Path $destination 'Launch-CorsoShield.ps1')+'"'
$shortcut.WorkingDirectory=$destination; $shortcut.Description='Corso Shield - explicit UAC approval, Defender readiness check'; $shortcut.Save()
Write-Output 'Installed. Open Corso Shield from Start and approve UAC for that session. The first-run prerequisites check reports elevation, Defender mode/modules, private storage and supported Windows version. Installation itself does not declare protection ready or grant permanent administrator rights. No execution policy or tamper-protection setting was changed.'
