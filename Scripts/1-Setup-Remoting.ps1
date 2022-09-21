# Create a Session Variable
$remoteSession = New-PSSession -ComputerName 192.168.254.133 -Credential vagrant 

# Create Directory Structor and copy over evtx files
Invoke-Command -Session $remoteSession -Command {$directories = "evtx", "transcripts", "logs"; new-item -ItemType Directory -path "c:\" -Name "DefensivePowershell" -Force; foreach ($name in $directories){new-item -ItemType Directory "c:\DefensivePowershell" -Name $name -force}}
Copy-Item ".\Files\*" -Recurse "c:\DefensivePowershell\" -ToSession $remoteSession -Force

# Enter PSSession into virtual machine
Enter-PSSession -session $remoteSession 

# Install pwsh v7 and enable psremoting
# From physical machine remote into vm
Set-Location c:\DefensivePowershell\
msiexec.exe /package PowerShell-7.2.4-win-x64.msi /quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1

Set-Location 'c:\Program Files\PowerShell\7'
.\Install-PowerShellRemoting.ps1 -PowerShellHome "C:\Program Files\PowerShell\7"

# from vm pwsh 7
Enable-PSRemoting -SkipNetworkProfileCheck

# Double Check your PSversion 
Get-PSSessionConfiguration | Select-Object Name

# From remote machine
$pwsh7Remoting = New-PSSession 192.168.254.133 -Credential vagrant -ConfigurationName PowerShell.7.2.6

Enter-PSSession -Session $pwsh7Remoting


