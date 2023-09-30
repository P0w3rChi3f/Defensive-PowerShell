# Set my location on my machine
Set-Location "$env:userprofile\Documents\Projects\Presentations\Defensive-PowerShell"

# Set up PowerShell Remoting
code .\Scripts\1-Setup-Remoting.ps1
powershell_ise.exe .\Scripts\1-Setup-Remoting.ps1 #v7
ise .\Scripts\1-Setup-Remoting.ps1 #v5

# Secure PowerShell walkthrough
code .\Scripts\2-SecurePowerShell.ps1

# open Event Log PS1
code .\Scripts\3-Log-Parsing.ps1

# DSC Walk Through
code .\Scripts\4-Enable-Auditing.ps1