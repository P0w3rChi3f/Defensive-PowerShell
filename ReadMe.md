# Defensive PowerShell Workshop  

Rest my vmnet8 for PowerShell Remoting
`Get-NetAdapter * | Where-Object {$_.name -like "*vmnet8*"} | disable-NetAdapter`
Disable RDP  
`Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' -Name fDenyTSConnections -value 1`
Clear logs in pwsh7
`Import-Module Microsoft.PowerShell.Management -UseWindowsPowerShell Get-EventLog -LogName * | % { Clear-EventLog -LogName $_.log }`

1. Setup and Overview - (60 min)
    * Expectations
        * May not be best tool for the job
        * Adding tools to the toolbox
        * Living off the land
    * PowerShell Versions
    * PowerShell Terminals
    * PowerShell Remoting
2. Secure - (120 min)
    * Disable PowerShellv2
        * `Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2`
        * `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`
        * `Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`
    * Enable PowerShell Logging and transcriptions
        * `Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue | Where-Object {$_.name -like "*Powershell*"} | select Name`
        * `Get-WinEvent -ProviderName Microsoft-Windows-PowerShell`
        * `HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging → EnableModuleLogging = 1`
        * `HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames → * = *`
        * `HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging → EnableScriptBlockLogging = 1`
    * secedit [/configure | /analyze | /import | /export | /validate | /generaterollback]
        * https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/administer-security-policy-settings#bkmk-scmtool
    * DSC (Desired State Configuration)
        * Set up Account Policy
            * Computer Configuration\Windows Settings\Account Policies\Password Policy
                * Enforce password history = 24
                * Maximum password age = 364
                * Minimum password age = 1
                * Minimum password length = 14
                * Password must meet complexity requirement = Enable
                * Relax minimum password length limits = Enabled
                    * MACHINE\System\CurrentControlSet\Control\SAM:RelaxMinimumPasswordLengthLimits
                * Store passwords using reversible encryption for all users in the domain = Disable
            * Computer Configuration\Windows Settings\Account Policies\Account Lockout Policy
                * Account lockout duration = 15
                * Account lockout threshold = 5
                * Reset lockout counter after = 15
        * Audit Policy
    * [JEA](https://github.com/P0w3rChi3f/JEA-Just-Enough-Admin)
3. Investigate/Hunt - (180 Min)
    * Get-WinEvent vs. Get-EventLog  
        * Get-WinEvent  
            * Module: Microsoft.PowerShell.Diagnostics
            * The Get-WinEvent cmdlet gets events from event logs, including classic logs, such as the System and Application logs. The cmdlet gets data from event logs that are generated by the Windows Event Log technology introduced in Windows Vista. And, events in log files generated by Event Tracing for Windows (ETW). By default, Get-WinEvent returns event information in the order of newest to oldest.
            * Get-WinEvent lists event logs and event log providers. To interrupt the command, press CTRL+C. You can get events from selected logs or from logs generated by selected event providers. And, you can combine events from multiple sources in a single command. Get-WinEvent allows you to filter events using XPath queries, structured XML queries, and hash table queries.
            * If you're not running PowerShell as an Administrator, you might see error messages that you cannot retrieve information about a log. |  
        * Get-EventLog  
            * Module: Microsoft.PowerShell.Management
            * The Get-EventLog cmdlet gets events and event logs from local and remote computers. By default, Get-EventLog gets logs from the local computer. To get logs from remote computers, use the ComputerName parameter.
            * You can use the Get-EventLog parameters and property values to search for events. The cmdlet gets events that match the specified property values.
            * PowerShell cmdlets that contain the EventLog noun work only on Windows classic event logs such as Application, System, or Security. To get logs that use the Windows Event Log technology in Windows Vista and later Windows versions, use Get-WinEvent.  
    * ***Get-EventLog uses a Win32 API that is deprecated. The results may not be accurate. Use the Get-WinEvent cmdlet instead.***
    * Converting Get-EventLog to Get-WinEvent
    * install Sysmon with Swift on Security config
        `.\sysmon.exe -accepteula -i sysmonconfig-export.xml`
    * find network share access
        eventID 5140 : A network share was accessed
        EventID 4624 : Logged in users


## Things to ADD

Decode a base64 encoded command
    `$encodedText = (([string](Get-CimInstance Win32_Process | where {$_.processID -eq '6844'} | select Commandline)).split(" ")[-1]).TrimEnd("}"); [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))`



## Overview

This workshop touches on the difference between PowerShell versions.  It will detail how to use PowerShell to secure the systems, PowerShell remoting, and set up auditing.  During this section, the specific modules discussed are PowerShell DSC (Desired State Configuration) and PowerShell JEA (Just Enough Admin).  We will use PowerShell remoting to query system logs, query the registry, search for unwanted executables, and determine the type of file and if its executable.  The rest of the day, we will use PowerShell to investigate a system and hunt for evil.
