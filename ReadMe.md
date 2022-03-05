# Defensive PowerShell Workshop  

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
    * Enable PowerShell Logging and transcriptions
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
    * JEA
3. Investigate/Hunt - (180 Min)
    * Get-WinEvent vs. Get-EventLog

## Overview

This workshop touches on the difference between PowerShell versions.  It will detail how to use PowerShell to secure the systems, PowerShell remoting, and set up auditing.  During this section, the specific modules discussed are PowerShell DSC (Desired State Configuration) and PowerShell JEA (Just Enough Admin).  We will use PowerShell remoting to query system logs, query the registry, search for unwanted executables, and determine the type of file and if its executable.  The rest of the day, we will use PowerShell to investigate a system and hunt for evil.
# Defensive-PowerShell
