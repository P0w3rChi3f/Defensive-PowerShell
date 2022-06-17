# Create a Session Variable
$remoteSession = New-PSSession -ComputerName 192.168.77.187 -Credential vagrant
Invoke-Command -Session $remoteSession -Command {new-item -ItemType Directory -path "c:\" -Name "evtx" -Force}
Copy-Item .\Files\Evtx\* c:\evtx\ -ToSession $remoteSession -Force
Enter-PSSession $remoteSession


# Enter PSSession into virtual machine
Enter-PSSession 192.168.77.187 -Credential vagrant

