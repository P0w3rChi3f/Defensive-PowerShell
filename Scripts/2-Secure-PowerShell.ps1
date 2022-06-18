# https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
# Working with PowerShellv2
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

#######################################################################################
# Transcript logging
Set-Location C:\DefensivePowershell\Logs
Start-Transcript .\ps7transcript.txt
Get-Service
Stop-Transcript
.\ps7transcript.txt

test-path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\
New-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\
Set-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\ -Name EnableTranscripting -Type DWord -Value 1
Set-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\ -Name OutputDirectory -Value "C:\DefensivePowershell\transcripts\"

#######################################################################################
# Scriptblock Logging
# Check the registry key
Get-childItem HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\

# Check for PowerShell logs
# Check to see if you are already logging
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational  | Where-Object {($_.id -eq 4104)} | Select-Object -First 1 -ExpandProperty message 

Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Group-Object id | out-file ".\Logs\CurrentLog#.txt"

# Create Scriptblock logging Registry key
New-Item HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\ -Force
Set-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\ -name EnableScriptBlockLogging -Value 1

# Check the registry Key
Get-Item HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\

# Restart shell
Exit
Enter-PSSession -session $remoteSession 

# Opening PowerShell Creates Event ID 40961,40962,53504
# Remote PowerShell Creates Event ID  53504 (PowerShell Named Pipe IPC)

#######################################################################################
# Module Logging

# Enable module logging per module
Install-Module SqlServer
Import-Module SqlServer
(Get-Module SqlServer).LogPipelineExecutionDetails = $true

# Check module logging registry key

Test-Path HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging

# Enable module logging for all modules
New-Item HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging
Set-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging -name EnableModuleLogging -Type DWord -Value 1

New-Item HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Force 
Set-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -Value *


# check module logging
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Where-Object {$_.id -eq 4103} 

#######################################################################################
# Firewall logging
Local Security Policy -> Windows Defender Firewall and Advanced Security 
%systemroot%\system32\logfiles\firewall\pfirewall.log

# Check to see if logging is enabled
Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogFileName
Get-Content $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log

foreach ($fwProfile in (Get-NetFirewallProfile)) {set-NetFirewallProfile -Name $fwProfile.Name -LogAllowed True -LogBlocked True -LogIgnored True}

#######################################################################################
# Firewall Rules

Get-NetFirewallRule | Select-Object -First 1
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $false} | Select-Object Name, Profile, Direction, Action
Get-NetFirewallRule -Name *SpoolSvc* | Select-Object Name, Enabled, Profile, Direction, Action, Description | Format-Table -AutoSize -Wrap

Set-NetFirewallRule -Name FPS-SpoolSvc-In-TCP -Enabled True
Disable-NetFirewallRule -Name FPS-SpoolSvc-In-TCP



########################################################################################
# Starter Functions to enable PowerShell Logging
########################################################################################

# 1. Check to see if scriptblock logging already been enabled.
Get-ChildItem HKLM:\SOFTWARE\Policies\Microsoft\Windows | Select-Object PSChildName

# Enable Script Block Logging
function Enable-PSScriptBlockLogging
{
    $basePath = 'HKLM:\Software\Policies\Microsoft\Windows' +
      '\PowerShell\ScriptBlockLogging'

    if(-not (Test-Path $basePath))
    {
        $null = New-Item $basePath -Force
    }

    Set-ItemProperty $basePath -Name EnableScriptBlockLogging -Value "1"
}

# check to see if the registry was created
Get-ChildItem HKLM:\SOFTWARE\Policies\Microsoft\Windows | Select-Object PSChildName

# Check to see if there is a new logging provider
Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue | Where-Object {$_.name -like "*Powershell*"} | Select-Object Name

# Enable Module Logging for all
function Enable-ModuleLogging
{
    $basePath = 'HKLM:\Software\Policies\Microsoft\Windows' +
      '\PowerShell\ModuleLogging'

    if(-not (Test-Path $basePath))
    {
        $null = New-Item $basePath -Force
    }

    Set-ItemProperty $basePath -Name EnableModuleLogging -Value "1"
    Set-ItemProperty $basePath -Name Modulename -Value "*=*"
}

# Enable Module Logging for individual
#(Get-Module <Module-Name>).LogPipelineExecutionDetails = $true
