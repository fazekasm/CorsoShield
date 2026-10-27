# Launches this installed companion with an explicit, ordinary UAC prompt.
# It never caches credentials or disables UAC. Over-the-shoulder account changes are refused.
#requires -Version 5.1
[CmdletBinding()]param([ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid='')
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$sid=$identity.User.Value
. (Join-Path $PSScriptRoot 'Install-Helpers.ps1')
Test-CorsoLaunchIdentity $ExpectedUserSid $sid
$admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $protectedPath=Join-Path $env:ProgramFiles 'Corso Shield'
    if (-not [string]::Equals([IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\'),[IO.Path]::GetFullPath($protectedPath).TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)) { throw 'Run the reviewed Install-CorsoShield.ps1 first. Corso refuses automatic elevation of scripts from a portable/user-writable folder.' }
    if ((Get-Item -LiteralPath $PSScriptRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'A linked installed directory is refused.' }

    $hostExe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments='-NoProfile -STA -File "'+$PSCommandPath+'" -ExpectedUserSid '+$sid
    try { $process=Start-Process -FilePath $hostExe -Verb RunAs -ArgumentList $arguments -PassThru -Wait; if ($process.ExitCode -ne 0) { throw 'The elevated companion exited with an error. Permissions were not recorded as granted.' } }
    catch { throw ('Administrator approval was denied or unavailable. No permission bypass was attempted. '+$_.Exception.Message) }
    return
}
& (Join-Path $PSScriptRoot 'Start-CorsoShield.ps1')
