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


# Query TPM and return custom TPMState object <[bool]IsPresent, [bool]IsReady, [bool]IsEnabled, [function]CheckTPMReady>
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



#############
# SCRIPT
#############

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

