# Create a Session Variable
$remoteSession = New-PSSession -ComputerName 192.168.77.187 -Credential vagrant
copy .\Files\Evtx\* c:\evtx -ToSession $remoteSession -Force


# Enter PSSession into virtual machine
Enter-PSSession 192.168.77.187 -Credential vagrant

