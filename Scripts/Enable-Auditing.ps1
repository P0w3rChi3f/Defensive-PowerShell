Configuration CIS_Windows11_v100 {
    param (
        [string[]]$NodeName ='localhost'
        )

    Import-DscResource -ModuleName 'PSDscResources'
    Import-DscResource -ModuleName 'AuditPolicyDsc'
    Import-DscResource -ModuleName 'SecurityPolicyDsc'

    Node $NodeName {
        AccountPolicy AccountPolicies
        {
            Name                                        = 'PasswordPolicies'
            # 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history                    = 24
            # 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
            Maximum_Password_Age                        = 60
            # 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
            Minimum_Password_Age                        = 1
            # 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
            Minimum_Password_Length                     = 14
            # 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'
            # 1.1.6 (L1) Ensure 'Relax minimum password length limits' is set to 'Enabled'
 #           Relax_minimum_Password_length = 'Enabled'
            # 1.1.7 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            # 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
            Account_lockout_duration                    = 15
            # 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'
            Account_lockout_threshold                   = 5
            # 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
            Reset_account_lockout_counter_after         = 15
        }
         # 2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
         UserRightsAssignment AccessCredentialManagerasatrustedcaller {
            Policy       = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity     = ''
        }

        # 2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' (DC only)
        UserRightsAssignment Accessthiscomputerfromthenetwork {
            Policy       = 'Access_this_computer_from_the_network'
            Identity     = 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'
        }

        # 2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
        UserRightsAssignment Actaspartoftheoperatingsystem {
            Policy       = 'Act_as_part_of_the_operating_system'
            Identity     = ''
        }

        # 2.2.4 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Adjustmemoryquotasforaprocess {
            Policy       = 'Adjust_memory_quotas_for_a_process'
            Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
        }

        # 2.2.5 (L1) Ensure 'Allow log on locally' is set to 'Administrators, Users'
        UserRightsAssignment Allowlogonlocally {
            Policy       = 'Allow_log_on_locally'
            Identity     = 'Administrators, Users'
        }

        # 2.2.6 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'
        UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
            Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
            Identity     = 'Administrators, Remote Desktop Users'
        }

        # 2.2.7 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
        UserRightsAssignment Backupfilesanddirectories {
            Policy       = 'Back_up_files_and_directories'
            Identity     = 'Administrators'
        }

        # 2.2.8 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethesystemtime {
            Policy       = 'Change_the_system_time'
            Identity     = 'Administrators, LOCAL SERVICE'
        }

        # 2.2.9 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users'
        UserRightsAssignment Changethetimezone {
            Policy       = 'Change_the_time_zone'
            Identity     = 'Administrators, LOCAL SERVICE, Users'
        }

        # 2.2.10 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
        UserRightsAssignment Createapagefile {
            Policy       = 'Create_a_pagefile'
            Identity     = 'Administrators'
        }

        # 2.2.11 (L1) Ensure 'Create a token object' is set to 'No One'
        UserRightsAssignment Createatokenobject {
            Policy       = 'Create_a_token_object'
            Identity     = ''
        }

        # 2.2.12 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Createglobalobjects {
            Policy       = 'Create_global_objects'
            Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        }

        # 2.2.13 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
        UserRightsAssignment Createpermanentsharedobjects {
            Policy       = 'Create_permanent_shared_objects'
            Identity     = ''
        }

        # 2.2.14 (L1) Configure 'Create symbolic links'
        UserRightsAssignment Createsymboliclinks {
            Policy       = 'Create_symbolic_links'
            Identity     = 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
        }

        # 2.2.15 (L1) Ensure 'Debug programs' is set to 'Administrators'
        UserRightsAssignment Debugprograms {
            Policy       = 'Debug_programs'
            Identity     = 'Administrators'
        }        

        # 2.2.16 (L1) Ensure 'Deny access to this computer from the network' is set to 'Guests, Local account'
        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Guests, Local account'
        }

        # 2.2.17 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy       = 'Deny_log_on_as_a_batch_job'
            Identity     = 'Guests'
        }

        # 2.2.18 (L1) Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
        }

        # 2.2.19 (L1) Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy       = 'Deny_log_on_locally'
            Identity     = 'Guests'
        }

        # 2.2.20 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests, Local account'
        }

        # 2.2.21 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'
        UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
            Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity     = ''
        }

        # 2.2.22 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
        UserRightsAssignment Forceshutdownfromaremotesystem {
            Policy       = 'Force_shutdown_from_a_remote_system'
            Identity     = 'Administrators'
        }

        # 2.2.23 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Generatesecurityaudits {
            Policy       = 'Generate_security_audits'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
        }

        # 2.2.24 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Impersonateaclientafterauthentication {
            Policy       = 'Impersonate_a_client_after_authentication'
            Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        }

        # 2.2.25 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Windows Manager\Windows Manager Group'
        UserRightsAssignment Increaseschedulingpriority {
            Policy       = 'Increase_scheduling_priority'
            Identity     = 'Administrators, Windows Manager\Windows Manager Group'
        }

        # 2.2.26 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
        UserRightsAssignment Loadandunloaddevicedrivers {
            Policy       = 'Load_and_unload_device_drivers'
            Identity     = 'Administrators'
        }

        # 2.2.27 (L1) Ensure 'Lock pages in memory' is set to 'No One'
        UserRightsAssignment Lockpagesinmemory {
            Policy       = 'Lock_pages_in_memory'
            Identity     = ''
        }

        # 2.2.28 (L2) Ensure 'Log on as a batch job' is set to 'Administrators'
        UserRightsAssignment Logonasabatchjob {
            Policy       = 'Log_on_as_a_batch_job'
            Identity     = 'Administrators'
        }

        # 2.2.29 (L2) Configure 'Log on as a service'
        UserRightsAssignment Logonasaservice {
            Policy       = 'Log_on_as_a_service'
            Identity     = 'NT VIRTUAL MACHINE\Virtual Machines'
        }

        # 2.2.30 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators'
        UserRightsAssignment Manageauditingandsecuritylog {
            Policy       = 'Manage_auditing_and_security_log'
            Identity     = 'Administrators'
        }

        # 2.2.31 (L1) Ensure 'Modify an object label' is set to 'No One'
        UserRightsAssignment Modifyanobjectlabel {
            Policy       = 'Modify_an_object_label'
            Identity     = ''
        }

        # 2.2.32 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
        UserRightsAssignment Modifyfirmwareenvironmentvalues {
            Policy       = 'Modify_firmware_environment_values'
            Identity     = 'Administrators'
        }

        # 2.2.33 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
        UserRightsAssignment Performvolumemaintenancetasks {
            Policy       = 'Perform_volume_maintenance_tasks'
            Identity     = 'Administrators'
        }

        # 2.2.34 (L1) Ensure 'Profile single process' is set to 'Administrators'
        UserRightsAssignment Profilesingleprocess {
            Policy       = 'Profile_single_process'
            Identity     = 'Administrators'
        }

        # 2.2.35 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
        UserRightsAssignment Profilesystemperformance {
            Policy       = 'Profile_system_performance'
            Identity     = 'Administrators, NT SERVICE\WdiServiceHost'
        }

        # 2.2.36 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Replaceaprocessleveltoken {
            Policy       = 'Replace_a_process_level_token'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
        }

        # 2.2.37 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
        UserRightsAssignment Restorefilesanddirectories {
            Policy       = 'Restore_files_and_directories'
            Identity     = 'Administrators'
        }

        # 2.2.38 (L1) Ensure 'Shut down the system' is set to 'Administrators, Users'
        UserRightsAssignment Shutdownthesystem {
            Policy       = 'Shut_down_the_system'
            Identity     = 'Administrators'
        }

        # 2.2.39 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
        UserRightsAssignment Takeownershipoffilesorotherobjects {
            Policy       = 'Take_ownership_of_files_or_other_objects'
            Identity     = 'Administrators'
        }

    }
}

#Create MOF
CIS_Windows11_v100

#Execute MOF
Start-DscConfiguration -Path .\CIS_Windows11_v100
