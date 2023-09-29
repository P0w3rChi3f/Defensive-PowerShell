# Install PWSH 7
https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.2

# Event ID cheetsheet
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia


# Set the working directory to the root of Defensive PowerShell
Set-Location c:\DefensivePowershell

# Show the log differences between get-winevent and get-event log

Get-EventLog -LogName * | Select-Object Log | Measure-Object
Get-WinEvent -ListLog * | Select-Object logname | Measure-Object

# Get the logs from exported logs PowerShell v5
foreach ($log in ((get-childitem .\evtx\SingleLogs).Name)){Get-WinEvent -path .\evtx\SingleLogs\$log}
get-winevent -path .\evtx\Merge.evtx

# Get the logs from exported logs PowerShell v7
Get-WinEvent -path .\evtx\Merge.evtx

#######################################################################################
# Explore Get-WinEvent basics and store as a variable
#######################################################################################
$importLogs = foreach ($log in (get-childitem .\evtx\SingleLogs)){Get-WinEvent -path $log.FullName} #v5

$importLogs | Select-Object -First 1 
$importLogs | Select-Object -First 1 | Select-Object -ExpandProperty message | select-string -pattern "Logon ID:"

$importLogs | Where-Object {$_.id -eq 4624} | Group-Object Id
($importLogs | Where-Object {$_.id -eq 4624} | Select-Object -ExpandProperty message).split("`n") | select-string -pattern "Logon type:" 

$importLogs | Where-Object {$_.id -eq "4672"} | Select-Object TaskDisplayName
$importLogs | Where-Object {$_.TaskDisplayName -eq "Special Logon"} | select-object -ExpandProperty Message
($importLogs | Where-Object {$_.TaskDisplayName -eq "Special Logon"} | select-object -ExpandProperty Message).split("`n") | select-string "Account Name"
($importLogs | Where-Object {$_.TaskDisplayName -eq "Special Logon"} | select-object -ExpandProperty Message).split("`n") | select-string "Account Name" -Context(0,3)

#Find everything a user did while logged in.
$importLogs | Where-Object {$_.message -like "*0x567515*"}
    # What IP did samir login from?
    # What was the name of their workstation?
    ($importLogs | Where-Object {$_.message -like "*0x567515*" -and $_.id -eq 4624}| Select-Object -ExpandProperty Message).split("`n") | Select-String -Pattern "Network Information:" -Context (0,3)
    
$importLogs | Where-Object {$_.id -eq "4688"}
($importLogs | Where-Object {$_.id -eq "4688"} | Select-Object -ExpandProperty message).split("`n") | Select-String -patter "New Process ID:" -Context (0,1)

Get-WinEvent -FilterHashTable @{path='.\evtx\Merge.evtx'; ID=4688}

##############################################################################################################
$createdProcess = @()
$processLogs = (Get-WinEvent -FilterHashTable @{path='.\evtx\Merge.evtx'; ID=4688} | Select-Object -ExpandProperty message).split("`n") | Select-String -Pattern "New Process ID:" -Context (0,1)

foreach ($log in $processLogs){
    $processObject = [PSCustomObject]@{
        ProcessID = ($log.line).Split("`t")[3]
        ProcessName = $log.Context | select-object -ExpandProperty PostContext | Split-Path -Leaf
         }
    $createdProcess += $processObject
}

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
foreach ($fwProfile in (Get-NetFirewallProfile)) {set-NetFirewallProfile -Name $fwProfile.Name -LogAllowed True -LogBlocked True -LogIgnored True}


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


Get-WinEvent -FilterHashTable @{path='.\evtx\Merge.evtx'; ID=4688} | Select-Object @{name='TimeCreated';expression={(($_.TimeCreated).ToUniversalTime()).tostring("MM/dd/yyyy HH:mm:ss")}}, ID, LevelDisplayName, Message

get-winevent -FilterHashTable @{path='.\evtx\Merge.evtx'; ID=4688} | Where-Object {($_.TimeCreated -gt '2019-03-18T15:00:00') -and ($_.TimeCreated -lt '2019-03-18T17:00:00')}

get-winevent -FilterHashTable @{path='.\evtx\Merge.evtx'; ID=4688; StartTime='2019-03-18T15:00:00'; EndTime='2019-03-18T17:00:00'}

#######################################################################################
# Filter xml  (show EventID=4624 or 4625) (appears not to work on saved files)
#######################################################################################

$query = @'
<QueryList>
    <Query Id="0" Path=".\evtx\Merge.evtx">
        <Select Path="security">
            *[System[(EventID=4624)]] and
            *[EventData[Data[@Name='LogonType'] and (Data !='2')]]
        </Select>
    </Query>
</QueryList>
'@
(get-winevent -FilterXml $query | Select-Object -ExpandProperty Message).split("`n") | select-string -Pattern "Logon Type:" | Group-Object | Sort-Object Count

#######################################################################################
# Filter Xpath
#######################################################################################

$xpath = "*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType'] and (Data='3')]]"
Get-WinEvent -path .\evtx\Merge.evtx -FilterXPath $xpath

$notxpath = "*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType'] and (Data!='3')]]"
Get-WinEvent -path .\evtx\Merge.evtx -FilterXPath $notxpath | Measure-Object | select-object Count

# Baseline query
(get-winevent -FilterHashTable @{path='.\evtx\Merge.evtx'; ID=4624} | Select-Object -ExpandProperty Message).split("`n") | Select-String -Pattern "Logon Type:" | Group-Object | Sort-Object Count

<# Notes from DCI

<QueryList>
        <Query Id="0" Path="Security">
            <Select Path="Security">
                *[System[(EventID=4624)]] and 
                *[EventData[Data[@Name='IpAddress'] and (Data='172.16.12.3')]] and 
                *[EventData[Data[@Name='IpPort'] and (Data=56842 or Data=65499 or Data=65497 or Data=50726)]]
            </Select>
        </Query>
    </QueryList>

 
Get the time the log was cleared
get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4688"}

Count of event ID 4624
get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4624"} | measure

Count of event ID 4779
get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4779"} | measure
Earliest failed logon attempt
get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4625"} | select -Last 5
Get Earliest failed logon attempt Logon Type
"(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4625"} | select -Last 1 | Select-object -expand message).split("`n") | select-string -pattern "Logon Type:""
Analyzing Password reset
(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4724"} shows a password change attempt was made
(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4738"} shows a user account was changed.
(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4724"} | Select-object -expand message).split("n") | select-string -Pattern "Password Last Set:" -context 8,0
Look for Privilege escalation
(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4672"}
(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4732"}
There were no 4728 logs
Find the user that was elevated to Admin
(get-winevent -path <path\to\evtx\file> | where {$_.id -eq "4672"} | Select-object -expand message).split("n") | select-string -Pattern "Account Name:" -gets a list of users who were elevated
Get event ID not related to user accounts or groups.
``
Get file name for System integrity event ID
found other System Integrity event Id through Google
Counted how many logs there were: get-winevent -path <path\to\evtx\file> | measure = 206
Then counted how many begain with a 4: get-winevent -path <path\to\evtx\file> | where {$_.id -like "4*"} | measure = 203
then looked at what the 3 logs were that didn't begin with 4: get-winevent -path <path\to\evtx\file> | where {$_.id -notlike "4*"} = 6281 and 1102
Then looked at the 6281 logs: (get-winevent -path <path\to\evtx\file> | select -first 1 | where {$_.id -eq "6281"} | Select-object -expand message)


Note: Look for IP 172.16.12.3. There are 12 total results, but select only from the following:
get-winevent Microsoft-Windows-WinRM/Operational | select-object -expandProperty message | select-string "172.16.12.3" - NoGo
get-winevent "Microsoft-Windows Firewall with Advanced Security/Firewall" | select-object -expandProperty message | select-string "172.16.12.3" - NoGo
Foreach ($log in (get-winevent -listlog *)){get-winevent -logname $log.logname | select-object -expandproperty message | select-string "172.16.12.3"} - GO
Foreach ($log in (get-winevent -listlog *)){(get-winevent -logname $log.logname | select-object -expandproperty message).split("n") | select-string "172.16.12.3"}


Convert Log Dates to UTC

Get-WinEvent -LogName Security | Where-Object {$_.id -eq "4672"} | select @{name="MyTime"; expression={(($_.TimeCreated).ToUniversalTime()).tostring("MM/dd/yyyy HH:mm:ss")}}, ID, LevelDisplayName, Message | select -First 150
#>