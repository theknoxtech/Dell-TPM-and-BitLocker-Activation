<#
.SYNOPSIS

This script is used to enable Bitlocker.

.DESCRIPTION

This script is used to enable Bitlocker with TPM and Recovery Password protectors. It will also attempt to activate the TPM on Dell computers using the DellBiosProvider module.

Author: Jon Witherspoon
Last Modified: 12-30-24

.PARAMETER Name

None.

.INPUTS

None. You cannot pipe objects to this script.

.OUTPUTS

Console output of status or errors.
Log transcript.

.EXAMPLE

PS> .\Enable-Bitlocker.ps1

.LINK

None.

#>


# Global Variables
$global:LTSvc = "C:\Windows\LTSvc\packages\Enable-Blocker"
$global:EncryptVol = Get-CimInstance -Namespace 'ROOT/CIMV2/Security/MicrosoftVolumeEncryption' -Class Win32_EncryptableVolume -Filter "DriveLetter='C:'"
$global:TimeStamp = (Get-Date).ToString("MM/dd/yyyy HH:mm:ss")

# Create a log that outputs to the console and c:\Windows\Ltsvc\packages\enable-bitlocker.txt
function New-BitlockerLog 
{
    param(
        [Logs]$Type,
        [string]$Message
    )

    enum Logs 
    {
        Info
        Success
        Error
    }

    $LogPath = "$LTSvc\enable_bitlocker.txt"
    

    $console_logs = @{
        Info = "$($timestamp) : Line : $($MyInvocation.ScriptLineNumber) : $($message)"
        Success = "$($timestamp) : Line : $($MyInvocation.ScriptLineNumber) : $($message)"
        Error = "$($timestamp) : ERROR: An error occurred at Line: $($MyInvocation.ScriptLineNumber) with the following error message: `n$($Error[0])"
    }

    switch ($Type) {
        ([Logs]::Info) {$console_logs.Info | Tee-Object -FilePath $LogPath -Append ; break}
        ([Logs]::Success) {$console_logs.Success | Tee-Object -FilePath $LogPath -Append ; break }
        ([Logs]::Error) {$console_logs.Error | Tee-Object -FilePath $LogPath -Append; break} 

    }
}

function Stop-ScriptExecution {
    param (
        [switch]$ExitScript
    )
    $LogPath = "$LTSvc\enable_bitlocker.txt"
    $Failure =  "$($timestamp) : FAILURE: Script Halted at Line: $($MyInvocation.ScriptLineNumber) "

    if ($ExitScript){ 

        throw "$message`n  `n$($Failure)"  | Tee-Object -FilePath $LogPath -Append

    }
}

# Create a file based checkpoint
function New-ScriptCheckpoint 
{
    [CmdletBinding()]
    Param(
        [Parameter()]
        [string]$CheckpointName
    )

    if (-not [string]::IsNullOrEmpty($CheckpointName))
    {
        try
        {
            New-Item -Path $LTSvc -ItemType File -Name $CheckpointName
            New-MigrationLog -Type info -Message "$($CheckpointName) has been created at: $($CheckPointLocation)"
            return $true
        }
        catch
        {
            return $false
        }
    }
    else
    {
        throw "`"New-ScriptCheckpoint -ChecpointName`" must not be null!"
    }
}   

# Get file based checkpoints
function Get-ScriptCheckpointExists 
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$CheckpointName
    )

    if (-not [string]::IsNullOrEmpty($CheckpointName))
    {
        if (Get-ChildItem -Path $LTSvc -Name $CheckpointName -ErrorAction SilentlyContinue)
        {
            return $true
        }

        else
        {
            return $false
        }
    }

    else
    {
        throw "`"Get-ScriptCheckpointExists -CheckpointName`" must not be null!"
    }
}   

# Convert exception to string and match for HRESULT code and return it
<# function Get-ExceptionCode {
    param (
        [String]$errorcode
    )
    $regex = "\((0x[0-9A-Fa-f]+)\)"

    if ($errorcode.ToString() -match $regex) {

        $code = $Matches[1]
        return $code
    }
}
 #>
<# function Get-ComputerModel {
    
} #>

# Check BIOS verion
function Get-SMBiosVersion 
{
    $Bios = Get-CimInstance Win32_BIOS 
    $Version = [float]::Parse("$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)")
    return $Version
}

# Returns true if BIOS version does not meet minium requirements. Returns false otherwise.
function Get-SMBiosRequiresUpgrade 
{
    Param(
        [float]$MinimumVersion = 2.4
    )

    if ((Get-SMBiosVersion) -lt $MinimumVersion)
    {
        return $true
    }

    return $false
}

# Query TPM and return custom TPMState object <[bool]IsPresent, [bool]IsReady, [bool]IsEnabled, [function]CheckTPMReady>
function Get-TPMState
{

    $TPM = Get-Tpm

    $TPMState = New-Object psobject
    $TPMState | Add-Member NoteProperty "IsPresent" $TPM.TpmPresent
    $TPMState | Add-Member NoteProperty "IsReady" $TPM.TpmReady
    $TPMState | Add-Member NoteProperty "IsEnabled" $TPM.TpmEnabled

    $TPMState | Add-Member ScriptMethod "CheckTPMReady"{
        if ($this.IsPresent -and $this.IsReady -and $this.IsEnabled)
        {
            return $true
        }

        return $false
    }

    return $TPMState
}

# Query Bitlocker and return custom Get-BitlockerState object 
function Get-BitlockerState 
{
    $ERGBitlocker = Get-BitLockerVolume -MountPoint "C:"

    $BitlockerState = New-Object psobject
    $BitlockerState | Add-Member NoteProperty "VolumeStatus" $ERGBitlocker.VolumeStatus
    $BitlockerState | Add-Member NoteProperty "ProtectionStatus" $ERGBitlocker.ProtectionStatus
    $BitlockerState | Add-Member NoteProperty "KeyProtector" $ERGBitlocker.KeyProtector
    
    $BitlockerState | Add-Member ScriptMethod "IsTPMKeyPresent" {
        $tpm_key = ($this.KeyProtector).KeyProtectorType
        
        if ($tpm_key -contains "Tpm"){
            return $true

        }
        else 
        {
            return $false

        }
     }
     $BitlockerState | Add-Member ScriptMethod "IsRecoveryPassword" {
        $recovery_password = ($this.KeyProtector).KeyProtectorType

        if ($recovery_password -contains "RecoveryPassword")
        {
            return $true

        }
        else
        {
            return $false
        }
     }
     $BitlockerState | Add-Member ScriptMethod "IsRebootRequired"{
        $reboot_status = ($EncryptVol | Invoke-CimMethod -MethodName "GetSuspendCount").SuspendCount

        if ($reboot_status -gt 0)
        {
            return $true
        }
        else
        {
            return $false
        }
     }
     $BitlockerState | Add-Member ScriptMethod "IsVolumeEncrypted"{
        $encrypt_status = ($EncryptVol | Invoke-CimMethod -MethodName "GetConversionStatus").conversionstatus
        
        if ($encrypt_status -eq 0)
        {
            return $false
        }
        elseif ($encrypt_status -eq 1)
        {
            return $true
        }

     }
     $BitlockerState | Add-Member ScriptMethod "IsProtected"{
        $protection_status = ($EncryptVol | Invoke-CimMethod -MethodName "GetProtectionStatus").protectionstatus

        if ($protection_status -eq 0)
        {
            return $false
        }
        elseif($protection_status -eq 1)
        {
            return $true
        }

     }
    return $BitlockerState
}

# Enables Bitlocker
function Set-BitlockerState
{
   
    $bitlocker_options = @{

        MountPoint       = "C:"
        EncryptionMethod = "XtsAes128"
        TpmProtector     = $true
        UsedSpaceOnly    = $true
        SkiphardwareTest = $true

    }

    Enable-Bitlocker @bitlocker_options
    Add-KeyProtector -RecoveryPassword
}

# Check if Microsoft Visual C++ Redistributables are installed and if not install Visual C++ 2010 and Visual C++ 2015-2022
function Install-Redistributables
{
    param(
        [switch]$Install2010,
        [switch]$Install2022
    )
    # Microsoft Visual C++ 2010 Redistributable
    if ($Install2010)
    {
        $working_dir = $PWD

        [System.NET.WebClient]::new().DownloadFile("https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe", "$($LTSvc)\vcredist_2010_x64.exe")
        Set-Location $LTSvc
        .\vcredist_2010_x64.exe /extract:vc2010 /q /norestart
        Start-Sleep -Seconds 1.5
        Set-Location $LTSvc\vc2010
        .\Setup.exe /q | Wait-Process
        Set-Location $working_dir

    }
    # Microsoft Visual C++ 2015-2022 Redistributable
    if ($Install2022)
    {
        $working_dir = $PWD
        [System.NET.WebClient]::new().DownloadFile("https://aka.ms/vs/17/release/vc_redist.x64.exe", "$($LTSvc)\vc_redist.x64.exe")
        Set-Location $LTSvc
        .\vc_redist.x64.exe /q /norestart | Wait-Process
        Set-Location $working_dir
    }

    return
}

# Returns current password value as a [Bool]
function IsBIOSPasswordSet
{
    return [System.Convert]::ToBoolean((Get-Item -Path DellSmBios:\Security\IsAdminpasswordSet).CurrentValue)
}

# Gets BiosPW.txt file presence and count of passwords in file
#TODO Break into separate functions
function Get-PWFileInfo
{
    
    param (
        [switch]$IsFilePresent,
        [switch]$PasswordCount,
        [switch]$RetrieveLastPassword 
    )

    switch ($_) 
    {
        {$IsFilePresent} {(Test-Path -Path $LTSvc\BiosPW.txt -ErrorAction Stop); break}
        {$PasswordCount} {(Get-Content -Path $LTSvc\BiosPW.txt | Where-Object {$_ -ne ""} | Measure-Object -Line).Lines; break}
        {$RetrieveLastPassword} {(Get-Content $LTSvc\BiosPW.txt -Tail 1).ToString(); break}
    }
}

# Generates BIOS Admin Password
function Generate-BiosAdminPassword
{
    $request_password = (Invoke-WebRequest -Uri "https://www.dinopass.com/password/strong").Content -replace "\W", '_' | Out-File $LTSvc\BiosPW.txt -Append
    return $request_password
}

# Removes BIOS Admin Password
function Remove-BiosAdminPassword {
    $password = Get-Content $LTSvc\Biospw.txt -Tail 1
    Set-Item -Path DellSmbios:\Security\AdminPassword ""  -Password $password -ErrorAction Stop
    
}
# Sets BIOS Admin password
function Set-BiosAdminPassword
{
    $password = Get-Content $LTSvc\Biospw.txt -Tail 1
    Set-Item -Path DellSmBios:\Security\AdminPassword $password -ErrorAction Stop
}

# Add either a recovery password or TPM key protector
function Add-KeyProtector
{
    param(
        [switch]$RecoveryPassword,
        [switch]$TPMProtector
    )

    if ($RecoveryPassword) 
    {
        Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
    }
    elseif ($TPMProtector)
    {
        Add-BitLockerKeyProtector -MountPoint "C:" -TpmProtector
    }

}

# Check if TPM Security is enabled in the BIOS and return True or False
function IsTPMSecurityEnabled
{

    $security_enabled = (Get-Item -Path DellSmbios:\TPMSecurity\TPMSecurity).CurrentValue

    switch ($security_enabled)
    {
        {$_ -eq "Enabled"} {$true}
        {$_ -eq "Disabled"} {$false}
    }

}

# TODO Verify function
# Returns [bool] true or false if NuGet is installed and if a compatible version. Returns [string] if NuGet not installed
function IsNugetInstalled
{
    Get-PackageProvider -ListAvailable -Name Nuget -ErrorAction SilentlyContinue
}

# TODO Verify function
# Installs required version of Nuget
function Install-Nuget
{
    Install-PackageProvider -Name nuget -MinimumVersion "2.8.5.201" -Force
}
########################
### SCRIPT FUNCTIONS ###
########################

New-BitlockerLog -Type Info -Message "Starting script"

# Create logging folder
if (!(Test-Path -Path $LTSvc))
{
    New-BitlockerLog -Type Info -Message "Enable-Bitlocker folder NOT found: Creating folder at $($LTSvc)"
    
    New-Item -Path $LTSvc -ItemType Directory -Name "Enable-Bitlocker"

    New-BitlockerLog -Type Info -Message "Enable-Bitlocker folder has been created at: $($LTSvc)"

}
else
{
    New-BitlockerLog -Type Info -Message "Logging files are stored at: $($LTSvc)"
}



# Check Execution Policy
New-BitlockerLog -Type Info -Message "Checking execution policy."
if (!(Get-ExecutionPolicy) -eq "Bypass")
{
    try
    {
        Set-ExecutionPolicy Bypass -Force -ErrorAction Stop
    }
    catch [System.Management.Automation.RuntimeException]
    {
        # ERROR: Policy overridden by a policy defined at a more specific scope
            New-BitlockerLog -Type Error
            Stop-ScriptExecution -ExitScript
    }

}


$TPMState = Get-TPMState
$bitlocker_status = Get-BitlockerState
$bitlocker_settings = @{

    "IsRebootPending" = $bitlocker_status.IsRebootRequired()
    "Encrypted" = $bitlocker_status.IsVolumeEncrypted()
    "TPMProtectorExists" = $bitlocker_status.IsTPMKeyPresent()
    "RecoveryPasswordExists" = $bitlocker_status.IsRecoveryPassword()
    "Protected" = $bitlocker_status.IsProtected()
    "TPMReady" = $TPMState.CheckTPMReady()
}


# Main switch for checking Bitlocker status
Switch ($bitlocker_settings){

    # This first statement is to mitigate an instance that a reboot is detected, and reboot doesn't clear the flag
    # This is seen when the drive is fully encrypted with no key protectors and protection status off
    {$_.IsRebootPending}
    {
        try {
            switch ($bitlocker_settings)
            {

                {$_.TPMProtectorExists -eq $false}
                {
                    New-BitlockerLog -Type Info -Message "Adding TPM Protector."
                    Add-KeyProtector -TPMProtector
                    
                }
                {$_.RecoveryPasswordExists -eq $false}
                {
                    New-BitlockerLog -Type Info -Message "Adding Recovery Password."
                    Add-KeyProtector -RecoveryPassword      
                }
                {$_.Protected -eq $false}
                {
                    New-BitlockerLog -Type Info -Message "Enabling Protection."
                    Resume-BitLocker -MountPoint "C:"                
                }
            }
            New-BitlockerLog -Type Info -Message "Bitlocker is enabled"
            Exit
        }
        catch [System.Runtime.InteropServices.COMException]
        {
            New-BitlockerLog -Type Error -Message $_.Exception.Message
            New-BitlockerLog -Type Error -Message "FAILUE: Enabling Bitlocker was unsuccessful. Manual remediation required!"
            Exit
        }

        Exit
    }
    {$_.TPMReady -eq $false}
    {

        New-BitlockerLog -Type Info -Message "TPM not ready. Attempting to enable."; break}
    
    # This statment is to mitigate an instance of the drive being fully encrypted, with no key protectors and protection status off
    # It is similar to the first statement, but is for separate bugs    
    {$_.Encrypted}
    {
        Write-host "Drive is encrypted. Continuing checks"

        New-BitlockerLog -Type Info -Message "Drive is encrypted continuing checks."
        try {
            switch ($bitlocker_settings) 
            {

                {$_.TPMProtectorExists -eq $false}
                {
                    New-BitlockerLog -Type Info -Message "Adding TPM Protector."
                    Add-KeyProtector -TPMProtector
                    
                }
                {$_.RecoveryPasswordExists -eq $false}
                {
                    New-BitlockerLog -Type Info -Message "Adding Recovery Password."
                    Add-KeyProtector -RecoveryPassword      
                }
                {$_.Protected -eq $false}
                {
                    New-BitlockerLog -Type Info -Message "Enabling Protection."
                    Resume-BitLocker -MountPoint "C:"                
                }
            }

                New-BitlockerLog -Type Info -Message "Bitlocker is enabled"
                Exit
        }
        catch [System.Runtime.InteropServices.COMException]
        {
            New-BitlockerLog -Type Error -Message $_.Exception.Message
            
            New-BitlockerLog -Type Error -Message "FAILUE: Enabling Bitlocker was unsuccessful. Manual remediation required!"
            
            Exit
        }
      
        Exit

    }
    {($_.Encrypted -eq $false) -and ($_.TPMReady -eq $true)}
    {
            Write-Host "Drive unencrypted and TPM ready. Attempting to enable Bitlocker."

            New-BitlockerLog -Type Info -Message "Drive unencrypted and TPM ready. Attempting to enable Bitlocker."
        try {
            Set-BitlockerState
            New-BitlockerLog -Type Info -Message "Bitlocker is enabled. Protection status will change to ON once fully encrypted."

            Exit
        }
        catch [System.Runtime.InteropServices.COMException]{
            
            New-BitlockerLog -Type Error -Message $_.Exception.Message
            
            New-BitlockerLog -Type Error -Message "FAILUE: Enabling Bitlocker was unsuccessful. Manual remediation required!"

            Exit
        }

            Exit
        
    }
}



# Install DellBiosProvider
# Spawns new session to ensure module is loaded because it is inconsistent otherwise
# Else shoud run when session restarts

switch (Get-ScriptCheckpointExists -CheckpointName "CheckPoint_1") {
    $false {

        New-BitlockerLog -Type Info -Message "Checking for and installing DellBiosProvider if needed..." 

        if ($null -eq (Get-Module -ListAvailable DellBIOSProvider))
        {
        try {
            New-BitlockerLog -Type info  -Message "Checking for Nuget and installing if needed"
    
            if (!(IsNugetInstalled))
            {

                Install-PackageProvider -Name Nuget -Force
            }

            New-BitlockerLog -Type info  -Message "Missing Dell module. Installing module..."

            Install-Module -Name DellBiosProvider -MinimumVersion "2.7.2" -Force 

            New-BitlockerLog -Type info  -Message "Module installed`nRestarting script..."

            New-ScriptCheckpoint -CheckpointName "CheckPoint_1"

            Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `"$($PSCommandPath)`""

            New-BitlockerLog -Info -Message "Terminating previous session and continuing execution in new session"

            Stop-Process -Id $PID -Force

        }catch
        {
            New-BitlockerLog -Type Error
            Stop-ScriptExecution -ExitScript
        }

        }
        else
        {

            New-BitlockerLog -Type Info -Message "Importing DellBiosProvider"
            Import-Module -Name DellBIOSProvider -Force
        }
    }

    # If checkpoint found start here
    $true {

        New-BitlockerLog -Type Info -Message "Importing DellBiosProvider"
        Import-Module -Name DellBIOSProvider -Force

            # Install Microsoft Runtime Libraries
        New-BitlockerLog -Type Info -Message "Checking and installing Microsoft Runtimes libraries"

        $Products = Get-CimInstance Win32_Product

        if (!($bitlocker_settings.TPMReady) -and !(Get-SMBiosRequiresUpgrade))
        {
            try {

                    New-BitlockerLog -info -Message "Verifying Microsoft Visual runtime 2010 is installed"

                    if($Products | Where-Object { $_.name -like "Microsoft Visual C++ 2010*" })
                    {
                
                    New-BitlockerLog -Type Info -Message "Microsoft Visual runtime 2010 is already installed"
                
                    }
                    else
                    {
                    New-BitlockerLog -Type info -Message "Installing Microsoft Visual runtime 2010"
                
                    Install-Redistributables -Install2010
                
                    New-BitlockerLog -Type Info -Message "Microsoft Visual runtime 2010 is installed"
                    }

                }
            catch 
                {

                    New-BitlockerLog -Type Error 
                    Stop-ScriptExecution -ExitScript
                }

            try {

                New-BitlockerLog -info -Message "Verifying Microsoft Visual runtime 2022 is installed"

                if ($products | Where-Object { $_.name -like "Microsoft Visual C++ 2015-2022*" })
            {

                New-BitlockerLog -Type Info -Message "Microsoft Visual runtime 2022 is already installed"
            }
            else
            {
            
                New-BitlockerLog -Type info -Message "Installing Microsoft Visual runtime 2022"

                Install-Redistributables -Install2022

                New-BitlockerLog -Type Info -Message "Microsoft Visual runtime 2022 is installed"
            }
        
                }
            catch
                {
                    New-BitlockerLog -Type Error
                    Stop-ScriptExecution -ExitScript
                }
}
# TODO Review setting BIOS password and error handling
            # Set BIOS Password
            if (!(IsBIOSPasswordSet))
            {
            
                    New-BitlockerLog -Type Info -Message "Attempting to set password."
            
                    New-BitlockerLog -Type Info -Message "Generating Password."
            
                    Generate-BiosAdminPassword
            
                    New-BitlockerLog -Type Info -Message "Password had been set to $(Get-PWFileInfo -RetrieveLastPassword)."
            
                try 
                {
                    New-BitlockerLog -Type Info -Message "Setting BIOS Password."
                    # TODO BiosPassword set 
                    Set-BiosAdminPassword
                
                }
                catch [System.Management.Automation.PSSecurityException]
                {
                    # If this is caught then a password was previously set
                    New-BitlockerLog -Type Error

                    New-BitlockerLog -Type Info -Message "Failed to set password. A previous password has been set."
                
                    Stop-ScriptExecution -ExitScript
                }
                catch [System.Management.Automation.DriveNotFoundException]
                {
                    # If this is caught the DellSMBios PS Drive is not loaded
                    New-BitlockerLog -Type Error
                
                    if (Get-Module -ListAvailable DellBiosProvider)
                    {
                    
                        Import-Module -Name DellBIOSProvider -Force
                    
                        if ((Test-Path -Path "DellSMbios:") -and (!(IsBIOSPasswordSet)))
                        {
                        
                            New-BitlockerLog -Type Info -Message "Attempting to retry setting BIOS password"

                            # TODO Biospassword set
                        
                            Set-BiosAdminPassword
                        }
                    
                    }
                    else{
                        New-BitlockerLog -Type Error
                        New-BitlockerLog -Type Info -Message "Retry attempts to set BIOS password have failed because DellSMBios: was not found. Manual remediation required."
                    }
                }
            }
            elseif (IsBIOSPasswordSet)
            {

                New-BitlockerLog -Type Error -Message "Unknown BIOS password is set. Manual remediation required!"
                Stop-ScriptExecution -ExitScript
}

# Enable TPM scurity in the BIOS
            $credential = Get-PWFileInfo -RetrieveLastPassword
            if (IsTPMSecurityEnabled)
            {
            
                New-BitlockerLog -Type Info -Message "TPM security is already enabled in the BIOS."
            
            }
            else
            {
            
                try {
                    New-BitlockerLog -Type Info -Message "Attempting to enable TPM Security in the BIOS."
                
                    Set-Item -Path DellSmbios:\TpmSecurity\TpmSecurity Enabled -Password $credential -ErrorAction Stop
                
                    New-BitlockerLog -Type Info -Message "TPM Security has been enabled in the BIOS."
                }
                catch [System.Management.Automation.ItemNotFoundException]
                {
                
                    New-BitlockerLog -Type Error -Message $_.Exception.Message
                
                    New-BitlockerLog -Type Info -Message "The option to enable TPM Security was not found."
                }
            
            }

            # Check if TPM is enabled and activated in the BIOS then remove password
            if (((IsTPMSecurityEnabled) -eq $true))
            {

                try {
                    New-BitlockerLog -Type Info -Message "Attempting removal of BIOS password."
                
                    New-BitlockerLog -Type Info -Message "Password file found: $(Get-PWFileInfo -IsFilePresent)."
                
                    Remove-BiosAdminPassword
                }
                catch [System.Management.Automation.ItemNotFoundException]
                {
                    # Catches an error for the biospw.txt file missing
                    New-BitlockerLog -Type Error 
                
                }
                catch [System.InvalidOperationException]
                {
                
                    # Catches Incorrect Password error and checks if more than one password exists in the biospw.txt file
                    New-BitlockerLog -Type Error 
                
                    $fileCheck = Get-PWFileInfo -PasswordCount
                
                    switch ($fileCheck) 
                    {
                        {$_ -lt 1} {New-BitlockerLog -Type Info -Message "File contains $($_) password entries. Manual removal and remediation required!"; break}
                        {$_ -gt 1} {New-BitlockerLog -Type Info -Message "File contains $($_) password entries. Manual remediation required!"; break}
                        {$_ -eq 1} {New-BitlockerLog -Type Info -Message "File contains $($_) password entry, but it appears to be incorrect. Manual remediation required!"; break}
                    }
                    Stop-ScriptExecution -ExitScript

                }
                catch [System.ArgumentOutOfRangeException]
                {
                    # Catches password out range or not set error
                    New-BitlockerLog -Type Error 

                }
            
                New-BitlockerLog -Type Info -Message "Is BIOS password set: $(IsBIOSPasswordSet)"
            }

            # Remove BiosPW.txt
            if (IsBIOSPasswordSet)
            {
               try {
                    New-BitlockerLog -Type Info -Message "Remove the BIOS password before deleting the file. Manual remediation required!"
               }
               catch
               {
                    New-BitlockerLog -Type Error -Message $_.Exception.Message
                    Stop-ScriptExecution -ExitScript
               }
            }else
            {
                New-BitlockerLog -Type Info -Message "Removing password file."
            
                Remove-Item -Path $LTSvc\Biospw.txt -Force

                New-BitlockerLog -Type Info -Message "Password file has been successfully removed."
            }

            New-BitlockerLog -Type Info -Message "Reboot required! Rerun script after reboot to finish Bitlocker setup."

                } # End $true statement
            
}

