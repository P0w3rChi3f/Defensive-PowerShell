# Create a Session Variable
$remoteSession = New-PSSession -ComputerName vagrant-10 -Credential vagrant

# Create Directory Structor and copy over evtx files
Invoke-Command -Session $remoteSession -Command {$directories = "evtx", "transcripts", "logs"; new-item -ItemType Directory -path "c:\" -Name "DefensivePowershell" -Force; foreach ($name in $directories){new-item -ItemType Directory "c:\DefensivePowershell" -Name $name -force}}
Copy-Item ".\Files\Evtx\*" "c:\DefensivePowershell\evtx" -ToSession $remoteSession -Force

# Enter PSSession into virtual machine
Enter-PSSession -session $remoteSession 

