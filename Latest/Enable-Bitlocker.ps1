<#
.SYNOPSIS

This script is used to enable Bitlocker.

.DESCRIPTION

This script is used to enable Bitlocker with TPM and Recovery Password protectors. It will also attempt to activate the TPM on Dell computers using the DellBiosProvider module.

Author: Jon Witherspoon
Last Modified: 08-14-24

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
$global:LTSvc = "C:\Windows\LTSvc\packages"
$global:EncryptVol = Get-CimInstance -Namespace 'ROOT/CIMV2/Security/MicrosoftVolumeEncryption' -Class Win32_EncryptableVolume -Filter "DriveLetter='C:'"
<# $global:TPMStatus = Get-CimInstance -Namespace 'ROOT/CIMV2/Security/MicrosoftTPM' -Class Win32_TPM #>

# Creates a log entry in LTSvc\Packages\enable_bitlocker.txt
$Log = "$LTSvc\enable_bitlocker.txt"

enum Logs {
    Error
    Debug
    Info
}
function Add-LogEntry {
    
    Param(
    [string]$Message,
    [Logs]$Type
    )

    $timestamp = (Get-Date).ToString("MM/dd/yyyy HH:mm:ss")

    switch ($Type) {
        ([Logs]::Debug) {Add-Content $Log "$timestamp DEBUG: $message"; break  }
        ([Logs]::Error) {Add-Content $Log "$timestamp ERROR: $message"; break }
        ([Logs]::Info) {Add-Content $Log "$timestamp INFO: $message"; break}
        (default) {Add-Content $Log "$timestamp []: $message"} 
    }
}

# Convert exception to string, match for Hresult code and return it
function Get-ExceptionCode {

    param (
        [String]$errorcode
    )
    
    $regex = "\((0x[0-9A-Fa-f]+)\)"

    if ($errorcode.ToString() -match $regex) {

        $code = $Matches[1]
        return $code
    }

}



# BIOS verion check
function Get-SMBiosVersion {
    $Bios = Get-CimInstance Win32_BIOS 
    $Version = [float]::Parse("$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)")
    return $Version
}

# Returns true if BIOS version does not meet minium requirements. Returns false otherwise.
function Get-SMBiosRequiresUpgrade {
    Param(
        [float]$MinimumVersion = 2.4
    )
  
    if ((Get-SMBiosVersion) -lt $MinimumVersion) {
        return $true
    }
  
    return $false
}

##
# TODO Review Get-TPMState Function 
##
# Query TPM and return custom TPMState object <[bool]IsPresent, [bool]IsReady, [bool]IsEnabled, [function]CheckTPMReady>
<# ($TPMStatus | Invoke-CimMethod -MethodName "IsReady").IsReady
($TPMStatus | Invoke-CimMethod -MethodName "IsEnabled").IsEnabled
($TPMStatus | Invoke-CimMethod -MethodName "Isactivated").IsActivated #>
function Get-TPMState {

    $TPM = Get-Tpm

    $TPMState = New-Object psobject
    $TPMState | Add-Member NoteProperty "IsPresent" $TPM.TpmPresent
    $TPMState | Add-Member NoteProperty "IsReady" $TPM.TpmReady
    $TPMState | Add-Member NoteProperty "IsEnabled" $TPM.TpmEnabled

    $TPMState | Add-Member ScriptMethod "CheckTPMReady" {
        if ($this.IsPresent -and $this.IsReady -and $this.IsEnabled) {
            return $true
        }

        return $false
    }

    return $TPMState
}

# Query Bitlocker and return custom Get-BitlockerState object 
function Get-BitlockerState {
    $ERGBitlocker = Get-BitLockerVolume -MountPoint "C:"

    $BitlockerState = New-Object psobject
    $BitlockerState | Add-Member NoteProperty "VolumeStatus" $ERGBitlocker.VolumeStatus
    $BitlockerState | Add-Member NoteProperty "ProtectionStatus" $ERGBitlocker.ProtectionStatus
    $BitlockerState | Add-Member NoteProperty "KeyProtector" $ERGBitlocker.KeyProtector
    
    $BitlockerState | Add-Member ScriptMethod "IsTPMKeyPresent" {
        $tpm_key = ($this.KeyProtector).KeyProtectorType
        
        if ($tpm_key -contains "Tpm"){
            return $true
        }else {
            return $false
        }
     }
     $BitlockerState | Add-Member ScriptMethod "IsRecoveryPassword" {
        $recovery_password = ($this.KeyProtector).KeyProtectorType

        if ($recovery_password -contains "RecoveryPassword"){
            return $true
        }else {
            return $false
        }
     }
     $BitlockerState | Add-Member ScriptMethod "IsRebootRequired" {
        $reboot_status = ($EncryptVol | Invoke-CimMethod -MethodName "GetSuspendCount").SuspendCount

        if ($reboot_status -gt 0){
            return $true
        }else{
            return $false
        }
     }
     $BitlockerState | Add-Member ScriptMethod "IsVolumeEncrypted" {
        $encrypt_status = ($EncryptVol | Invoke-CimMethod -MethodName "GetConversionStatus").conversionstatus
        
        if ($encrypt_status -eq 0){
            return $false
        }elseif ($encrypt_status -eq 1){
            return $true
        }

     }
     $BitlockerState | Add-Member ScriptMethod "IsProtected" {
        $protection_status = ($EncryptVol | Invoke-CimMethod -MethodName "GetProtectionStatus").protectionstatus

        if ($protection_status -eq 0){
            return $false
        }elseif($protection_status -eq 1){
            return $true
        }

     }
    return $BitlockerState
}

# Query Bitlocker and Set-BitlockerState
function Set-BitlockerState {
    $tpm = Get-TPMState
    $encrypt_state = Get-BitlockerState

    $bitlocker_options = @{

        MountPoint       = "C:"
        EncryptionMethod = "XtsAes128"
        TpmProtector     = $true
        UsedSpaceOnly    = $true
        SkiphardwareTest = $true

    }

    if ((!($encrypt_state.IsVolumeEncrypted())) -and $tpm.CheckTPMReady()) {

        try {
            
            Enable-Bitlocker @bitlocker_options
            Add-KeyProtector -RecoveryPassword
        }
        catch {

            try {
                throw "Bitlocker was not enabled. Manual remediation required!" 
            }
            catch {
               Add-LogEntry -Type Error -Message $_.Exception.Message
               Exit
            }
            
        }  
        # TODO add error handling here for enabling TPM 
    }
    #elseif () {
    #    Add-LogEntry -Type Debug -Message "TPM Ready: $tpm `nVolume Encrypted: $($encrypt_state.IsVolumeEncrypted())"#
    #}

}

# Check if Visual C++ Redistributables are installed and if not install Visual C++ 2010 and Visual C++ 2015-2022
# TODO Add error handling here
function Install-Redistributables {
   
  
    $products = Get-CimInstance win32_product
 

    # Visual C++ 2010 Redistributable
  
    if (($products | Where-Object { $_.name -like "Microsoft Visual C++ 2010*" })) {
    
        Add-LogEntry -Type Info -Message "Microsoft Visual C++ 2010 already installed"
    }
    
    else {
       
        Add-LogEntry -Debug -Message "Installing Microsoft Visual C++ 2010"

        $working_dir = $PWD

        [System.NET.WebClient]::new().DownloadFile("https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe", "$($LTSvc)\vcredist_2010_x64.exe")
        Set-Location $LTSvc
        .\vcredist_2010_x64.exe /extract:vc2010 /q 
        Start-Sleep -Seconds 1.5
        Set-Location $LTSvc\vc2010
        .\Setup.exe /q | Wait-Process
    
        Set-Location $working_dir

        Add-LogEntry -Type Info -Message "Visual C++ 2010 has been installed"
    }
    # Visual C++ 2022 Redistributable
 
    if (($products | Where-Object { $_.name -like "Microsoft Visual C++ 2022*" })) {

        Add-LogEntry -Type Info -Message "Microsoft Visual C++ 2022 already installed"

    }
   
    else {
        
        Add-LogEntry -Type Debug -Message "Installing Visual C++ 2022"

        $working_dir = $PWD

        [System.NET.WebClient]::new().DownloadFile("https://aka.ms/vs/17/release/vc_redist.x64.exe", "$($LTSvc)\vc_redist.x64.exe")
        Set-Location $LTSvc
        .\vc_redist.x64.exe /q | Wait-Process
    
        Set-Location $working_dir

        Add-LogEntry -Type Info -Message "Microsoft Visual C++ 2022 has been installed"
    }
}


# Returns current password value as a [Bool]
function IsBIOSPasswordSet {
    return [System.Convert]::ToBoolean((Get-Item -Path DellSmBios:\Security\IsAdminpasswordSet).CurrentValue)
}

# Generates a random passowrd from Dinopass to pass to Set-BiosAdminPassword
# Replaces symbols with "_"
function GenerateRandomPassword {
    Param(
        [switch]$SaveToFile
    )

    $password = (Invoke-WebRequest -Uri "https://www.dinopass.com/password/strong").Content 
    $replaced_password = $password -replace "\W", '_'

    if ($SaveToFile) {

        $replaced_password | Out-File $LTSvc\BiosPW.txt 
    }
    
    return $replaced_password
}

# Update Set-BiosAdminPassword function with GenerateRandomPassword
function Set-BiosAdminPassword {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Password
    )
    $Password = Get-Content $LTSvc\BiosPW.txt 

    Set-Item -Path DellSmBios:\Security\AdminPassword $Password

}

# Remove BIOS admin password
function Remove-BiosAdminPassword {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$RemovePassword
    )
    
    Set-Item -Path DellSmbios:\Security\AdminPassword ""  -Password $CurrentPW


}

# Add either a recovery password or TPM key protector
function Add-KeyProtector {
    param(
        [switch]$RecoveryPassword,
        [switch]$TPMProtector
    )

    if ($RecoveryPassword) {
        Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
    }elseif ($TPMProtector) {
        Add-BitLockerKeyProtector -MountPoint "C:" -TpmProtector
    }

}


# Check if TPM Security is enabled in the BIOS - Returns True or False
function IsTPMSecurityEnabled {
        
    return (Get-Item -Path DellSmbios:\TPMSecurity\TPMSecurity).CurrentValue
}

# Check if TPM is Activated in the BIOS - Returns Enabled or Disabled
function IsTPMActivated {

    return (Get-Item -Path DellSmbios:\TPMSecurity\TPMActivation).CurrentValue
}

# TODO Refactor all of this to work as a function
function Enable-TPM {
  
# Visual C++ Runtime Libraries
Install-Redistributables

# Install DellBiosProvider
if (!(Get-SMBiosRequiresUpgrade) -and !($TPMState.CheckTPMReady())) {

    Add-LogEntry -Type Debug -Message "Installing DellBiosProvider"

    try {
        Install-Module -Name DellBiosProvider -MinimumVersion 2.7.2 -Force
        Import-Module DellBiosProvider -Verbose
        
    }
    catch {
        Add-LogEntry -Type Error -Message $_.Exception.Message
        Exit 
        
    }

    Add-LogEntry -Type Info -Message "DellBiosProvider installed successfully!" 

}
# Set BIOS Password
if (!(IsBIOSPasswordSet)) {

    Add-LogEntry -Type Debug -Message "Setting BIOS Password"
    try {
       
        Set-BiosAdminPassword -Password (GenerateRandomPassword -SaveToFile) 
        $GeneratedPW = Get-Content -Path $LTSvc\Biospw.txt
    }
    catch {
        Add-LogEntry -Type Error -Message $_.Exception.Message
        Exit
    
    }
    Add-LogEntry -Type Info -Message "Current BIOS Password: $GeneratedPW and is saved in biospw.txt"
    
}elseif (IsBIOSPasswordSet) {
    
    Add-LogEntry -Type Error -Message "Unknown BIOS password is set. Manual remediation is required"
    Exit
}
 
# Enable TPM scurity in the BIOS

$bios_pw = Get-Content -Path $LTSvc\BiosPW.txt
if (IsTPMSecurityEnabled) {
    Add-LogEntry -Type Info -Message "TPM security is already enabled in the BIOS."
}
else {

    try {
        Set-Item -Path DellSmbios:\TpmSecurity\TpmSecurity Enabled -Password $bios_pw

        Add-LogEntry -Type Info -Message "TPM Security has been enabled in the BIOS"
    }
    catch [System.Management.Automation.ItemNotFoundException]{
        Add-LogEntry -Type Error -Message $_.Exception.Message
    }
   
}

# Enable TPM Activation in the BIOS
if ((IsTPMSecurityEnabled) -and (IsTPMActivated -eq "Disabled")) {

    try {
        Set-Item -Path DellSmbios:\TPMSecurity\TPMActivation Enabled -Password $bios_pw
    }
    catch {
        throw "TPM not enabled. Manual remediation required!"
        Add-LogEntry -Type "Error"
    }

    Add-LogEntry -Type "Debug" -Message "TPM Enabled: REBOOT REQUIRED"

}

# Check if TPM is enabled and activated in the BIOS then remove password
$CurrentPW = Get-Content -Path $LTSvc\biospw.txt
if ((IsTPMSecurityEnabled) -and (IsTPMActivated -eq "Enabled")) {
    
    $biospw_validation = IsBIOSPasswordSet
    Write-Host "Attempting BIOS password removal..." -ForegroundColor Yellow
    try {
        
        Remove-BiosAdminPassword -RemovePassword $CurrentPW
    }
    catch {
        throw "BIOS password was not removed. Manual remediation required!"
         Add-LogEntry -Type "Error"
    }

    Write-Host "BIOS password has been removed:" $biospw_validation -ForegroundColor Green -BackgroundColor Black
}
else {

    throw "Bitlocker was not enabled. Manual remediation required!"
     Add-LogEntry -Type "Error"
}

# Remove BiosPW.txt
if (IsBIOSPasswordSet) {
    Write-Host "Attempting to delete BiosPW.txt" -ForegroundColor Yellow

    throw "Remove the BIOS password before deleting the file. Manual remediation required!"
    Add-LogEntry -Type "Error"

}
else {
    
    Remove-Item -Path $LTSvc\Biospw.txt -Force
    
    Add-LogEntry -Type "Debug" -Message "Biospw.txt has been successfully removed!" 
}

Add-LogEntry -Type "Debug" -Message "REBOOT REQUIRED: Rerun after script reboot to finish Bitlocker setup"

# REBOOT REQUIRED HERE






}



########################
### SCRIPT FUNCTIONS ###
########################

# Check Execution Policy
Add-LogEntry -Type Debug -Message "Checking execution policy"
if (!(Get-ExecutionPolicy) -eq "Bypass") {
    try {
        Set-ExecutionPolicy Bypass -Force -ErrorAction Stop
    }
    catch [System.Management.Automation.RuntimeException] {
        # ERROR: Policy overridden by a policy defined at a more specific scope
            Add-LogEntry -Type Error -Message $_.Exception.Message
            Add-LogEntry -Type Error -Message $_.ErrorDetails
    }
}

# Check BIOS Version
# Upgrade BIOS if not up to date
Add-LogEntry -Type Debug -Message "Checking BIOS version"
$current_ver = Get-SMBiosVersion
$required_ver = 2.4
if (Get-SMBiosRequiresUpgrade) {
   try {

    throw "Current BIOS version $current_ver : Version is out of date. Update BIOS to $required_ver or later and try again"

   }catch {

    Add-LogEntry -Type Error -Message $_.Exception.Message
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

Switch ($bitlocker_settings.IsRebootPending){
    {$_ -eq $true} {

        try {
            if (($bitlocker_settings.Encrypted -eq $true) -and ($bitlocker_settings.TPMProtectorExists -eq $false) -and ($bitlocker_settings.RecoveryPasswordExists -eq $false)){

                Add-KeyProtector -TPMProtector
                Add-KeyProtector -RecoveryPassword
                Resume-BitLocker -MountPoint "C:" 

                Add-LogEntry -Type Info -Message "TPM and Recovery Password protectors have been added. Protection Status has been turned on"
                Exit

            }else{

            throw "REBOOT REQUIRED before proceeding."

            }
        }
        catch {
            Add-LogEntry -Type Error -Message $_.Exception.Message 
            Exit 
        }
        
        
    }
}

Add-LogEntry -Type Info -Message "Starting Bitlocker setting checks"
Switch ($bitlocker_settings) {
    {$_.TPMReady -eq $false } {
        Add-LogEntry -Type Debug -Message "TPM NOT Ready: Attempting to enable"; break
    }

    {($_.Encrypted -eq $false) -and ($_.TPMReady -eq $true)} {
        try {
            Add-LogEntry -Type Debug -Message "Drive Unencrypted and TPM Ready: Attempting to enable Bitlocker"

            Set-BitlockerState
            Resume-BitLocker -MountPoint C:

            Add-LogEntry -Type Info -Message "Bitlocker is now enabled: Exiting script"
            Exit
        }
        catch [System.Runtime.InteropServices.COMException] {
            
            Add-LogEntry -Type Error -Message $_.Exception.Message
        }
        
    }
    {$_.TPMProtectorExists -eq $false} {
        try {
            Add-LogEntry -Type Debug -Message "TPMProtector NOT found: Attempting to add TPM Protector"

            Add-KeyProtector -TPMProtector

            Add-LogEntry -Type Info -Message "TPM Protector has been added"
        }
        catch [System.Runtime.InteropServices.COMException] {
            Add-LogEntry -Type Error -Message $_.Exception.Message

            # (0x80310031) Only one key protector of this type is allowed for this drive.
            if (Get-ExceptionCode -contains "0x80310031") {
                
                Add-LogEntry -Type Debug -Message "TPM Protector already exists"
                
            }else {
                Add-LogEntry -Type Error -Message $_.Exception.Message
            }
        }
       
    }
    {$_.RecoveryPasswordExists -eq $false} {
        Add-LogEntry -Type Debug -Message "Recovery Password NOT found: Attempting to add Recovery Password"
        try {
            
            Add-KeyProtector -RecoveryPassword

            Add-LogEntry -Type Info -Message "Recovery Password has been added"
        }
        catch [System.Runtime.InteropServices.COMException] {

            Add-LogEntry -Type Error -Message $_.Exception.Message
        }
        
        
    }
    {$_.Protected -eq $false} {
        Add-LogEntry -Type Debug -Message "Protection is NOT enabled. Attempting to enable protection"
        try {

            Resume-BitLocker -MountPoint c: -ErrorAction Stop

            Add-LogEntry -Type Info -Message "Protection has been enabled: Exiting script"
            Exit 
        }
        catch [System.Runtime.InteropServices.COMException] {
            Add-LogEntry -Type Error -Message $_.Exception.Message
             # 0x80310001: Drive not encrypted - Attempt to recover and encrypt the drive
            if (Get-ExceptionCode -errorcode $_.Exception.Message -contains "0x80310001") {
                
            Set-BitlockerState
            Add-KeyProtector -RecoveryPassword
            Resume-BitLocker -MountPoint C:

            Add-LogEntry -Type Info -Message "Bitlocker has been enabled: Exiting script"
            Exit

            }else {
                
                Add-LogEntry -Type Error -Message $_.Exception.Message
            }
        
            
        }
      }
   
    
}





