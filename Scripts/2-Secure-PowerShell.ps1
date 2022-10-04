#######################################################################################
# Disable PowerShell v2
#######################################################################################

# https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
# Working with PowerShellv2
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 | select DisplayName, Online
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

#######################################################################################
# Transcript logging
#######################################################################################
Set-Location C:\DefensivePowershell\transcripts
Start-Transcript .\ps7transcript.txt -Append
Get-Service
Stop-Transcript
get-content .\ps7transcript.txt

test-path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\
New-Item HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\ -Force
Set-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\ -Name EnableTranscripting -Type DWord -Value 1
Set-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\ -Name OutputDirectory -Value "C:\DefensivePowershell\transcripts\"

#######################################################################################
# Scriptblock Logging
#######################################################################################

# Check the registry key
Get-childItem HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell

# Check for PowerShell logs
# Check to see if you are already logging
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational  | Where-Object {($_.id -eq 4104)} | Select-Object -first 1 -ExpandProperty message 

New-Item -ItemType Directory -Name Logs
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Group-Object id | out-file ".\Logs\CurrentLog#.txt" -Force

# Create Scriptblock logging Registry key
New-Item HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\ -Force
Set-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\ -name EnableScriptBlockLogging -Value 1

# Check the registry Key
Get-Item HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\

# Restart shell
Exit
Enter-PSSession -session $remoteSession
Enter-PSSession -Session $pwsh7Remoting 

# Opening PowerShell Creates Event ID 40961,40962,53504
# Remote PowerShell Creates Event ID  53504 (PowerShell Named Pipe IPC)

#######################################################################################
# Module Logging
#######################################################################################

# Enable module logging per module
Install-Module SqlServer
Import-Module WindowsUpdate
(Get-Module WindowsUpdate).LogPipelineExecutionDetails = $true

# Check module logging registry key

Test-Path HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging

# Enable module logging for all modules
New-Item HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging
Set-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging -name EnableModuleLogging -Type DWord -Value 1

New-Item HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Force 
Set-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -Value *


# check module logging
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | Where-Object {$_.id -eq 4103} | Select-Object -First 1 -ExpandProperty message

#######################################################################################
# Firewall logging
#######################################################################################

Local Security Policy -> Windows Defender Firewall and Advanced Security 
%systemroot%\system32\logfiles\firewall\pfirewall.log

test-path $env:SystemRoot\system32\logfiles\firewall\pfirewall.log

# Check to see if logging is enabled
Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogFileName
Get-Content $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log -First 4

# Enable firewall connection log
foreach ($fwProfile in (Get-NetFirewallProfile)) {set-NetFirewallProfile -Name $fwProfile.Name -LogAllowed False -LogBlocked False -LogIgnored False}


# Joshua Write Technique
Get-Content $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log | ForEach-Object {$Columns = $_ -split ' '; $Columns[1]; $Columns[2]}

Get-Content $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log | ForEach-Object {$Columns = $_ -split ' '; Write-Host -NoNewline $Columns[1]; write-host -nonewline " " ; Write-Host $Columns[2]}

Get-Content $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log | ForEach-Object {$Columns = $_ -split ' '; $Columns[1,2,3]}

Get-Content $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log | ForEach-Object {$Columns = $_ -split ' '; write-host $Columns[1] $Columns[2] $Columns[3] }

@(Get-Content $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log) -like "*SEND*" | measure



# Create an object
$Connection = @()

(Get-Content $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log).split('`n') | Select-Object -Skip 4 | ForEach-Object {$record = [PSCustomObject]@{
  Date = $_.split(' ')[0]
  Time = $_.split(' ')[1]
  action = $_.split(' ')[2]
  protocol = $_.split(' ')[3]
  src_ip = $_.split(' ')[4]
  dst_ip = $_.split(' ')[5]
  src_port = $_.split(' ')[6] 
  dst_port = $_.split(' ')[7]
  size = $_.split(' ')[8] 
  tcpflags = $_.split(' ')[9] 
  tcpsyn = $_.split(' ')[10] 
  tcpack = $_.split(' ')[11]
  tcpwin = $_.split(' ')[12] 
  icmptype = $_.split(' ')[13] 
  icmpcode = $_.split(' ')[14] 
  info = $_.split(' ')[15] 
  path = $_.split(' ')[16] 
  pid = $_.split(' ')[17]
    } 
    $Connection += $Record
  }


#######################################################################################
# Firewall Rules
#######################################################################################

Get-NetFirewallRule | Select-Object -First 1
Get-NetFirewallRule | Where-Object {($_.Enabled -eq $true) -and ($_.Profile -eq "Domain")} | Select-Object Name, Profile, Direction, Action
Get-NetFirewallRule -Name *SpoolSvc* | Select-Object Name, Enabled, Profile, Direction, Action, Description | Format-Table -AutoSize -Wrap

Set-NetFirewallRule -Name FPS-SpoolSvc-In-TCP -Enabled True
Disable-NetFirewallRule -Name FPS-SpoolSvc-In-TCP
Get-NetFirewallRule -Name FPS-SpoolSvc-In-TCP | Select-Object Name, Enabled



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
