# https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
# Working with PowerShellv2
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

# Enable Logging

# Check to see if you are already logging
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational

Opening PowerShell Creates Event ID 40961,40962,53504
Remote PowerShell Creates Event ID  53504 (PowerShell Named Pipe IPC)

# 1. Check to see if it has already been enabled.
Get-ChildItem HKLM:\SOFTWARE\Policies\Microsoft\Windows | select PSChildName

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
Get-ChildItem HKLM:\SOFTWARE\Policies\Microsoft\Windows | select PSChildName

# Check to see if there is a new logging provider
Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue | Where-Object {$_.name -like "*Powershell*"} | select Name

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
