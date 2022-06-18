configuration Install-ClientApps {
    # One can evaluate expressions to get the node list
    # E.g: $AllNodes.Where("Role -eq Web").NodeName
    
    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName xChrome
    Import-DscResource -Module vscode
    Import-DscResource -Module vscode -Name vscodesetup
    Import-DscResource -Name vscodeextension

    node 'localhost'
    {
        # Call Resource Provider
        # E.g: WindowsFeature, File
        # Was able to find name by running "Get-WindowsCapability -Online | Where-Object {$_.Name -like "*RSAT*"}"

        WindowsCapability "Server Manager"
        {
            Ensure = "Present"
            Name = "Rsat.ServerManager.Tools~~~~0.0.1.0"
        }
        WindowsCapability "RSAT-ADDS"
        {
            Ensure = "Present"
            Name = "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            
        }
        WindowsCapability "Group Policy Management"
        {
            Ensure = "Present"
            Name = "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
        }
        MSFT_xChrome chrome
        {
            
        }
    }
}

#Create MOF
Install-ClientApps

#Execute MOF
Start-DscConfiguration -Path .\Install-ClientApps -Force -Wait -Verbose