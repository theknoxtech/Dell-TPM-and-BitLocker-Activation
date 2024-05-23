<#
.SYNOPSIS

This script is used to enable Bitlocker.

.DESCRIPTION

This script is used to enable Bitlocker with TPM and Recovery Password protectors. It will also attempt to activate the TPM on Dell computers using the DellBiosProvider module.

Author: Jon Witherspoon
Last Modified: 05-03-24

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

# Global Storage Path
$global:LTSvc = "C:\Windows\LTSvc\packages"

# Start Transcript
Start-Transcript -Path $LTSvc\enable_bitlocker.txt -Verbose

# Bitlocker status check
function IsVolumeEncrypted {
 
    $volume_status = (Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue).VolumeStatus

    if ($volume_status -eq "FullyEncrypted" -or $volume_status -eq "EncryptionInProgress") {
        return $true
    }

    return $false
}

#Gets the current encryption state of the volume and returns it.
function Get-EncryptionState {

    $encryption_state = (Get-BitLockerVolume -MountPoint "C:").VolumeStatus
    
    return $encryption_state
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

# Check if Visual C++ Redistributables are installed and if not install Visual C++ 2010 and Visual C++ 2015-2022
function VCChecks {
    # Visual C++ Redistributable logic
    # Check for Visual C++ Redistributable packages
    Write-Host "Loading installed applications..." -ForegroundColor Yellow
    $products = Get-CimInstance win32_product
    Write-Host "Complete" -ForegroundColor Green

    # Visual C++ 2010 Redistributable
    Write-Host "Checking for 'Microsoft Visual C++ 2010 Redistributable'..." -ForegroundColor Yellow
    if (($products | Where-Object { $_.name -like "Microsoft Visual C++ 2010*" })) {
        Write-Host "`tMicrosoft Visual C++ 2010 Redistributable detected!" -ForegroundColor Green
    }
    # Handle install logic
    else {
        Write-Host "`tInstalling Microsoft Visual C++ 2010 Redistributable..." -ForegroundColor Yellow
        Install-VCRedist2010
        Write-Host "`tComplete" -ForegroundColor Green
    }

    # Visual C++ 2022 Redistributable
    Write-Host "Checking for 'Microsoft Visual C++ 2022 Redistributable'..." -ForegroundColor Yellow
    if (($products | Where-Object { $_.name -like "Microsoft Visual C++ 2022*" })) {
        Write-Host "`tMicrosoft Visual C++ 2022 Redistributable detected!" -ForegroundColor Green
    }
    # Handle install logic
    else {
        Write-Host "`tInstalling Microsoft Visual C++ 2022 Redistributable..." -ForegroundColor Yellow
        Install-VCRedist2022
        Write-Host "`tComplete" -ForegroundColor Green
    }
}

# Visual C++ Redistributable 2010
function Install-VCRedist2010 {
    $working_dir = $PWD

    [System.NET.WebClient]::new().DownloadFile("https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe", "$($LTSvc)\vcredist_2010_x64.exe")
    Set-Location $LTSvc
    .\vcredist_2010_x64.exe /extract:vc2010 /q 
    Start-Sleep -Seconds 1.5
    Set-Location $LTSvc\vc2010
    .\Setup.exe /q | Wait-Process

    Set-Location $working_dir
}

# Visual C++ Redistributable 2015-2022
function Install-VCRedist2022 {
    $working_dir = $PWD

    Start-BitsTransfer -Source "https://aka.ms/vs/17/release/vc_redist.x64.exe" -Destination "$($LTSvc)\vc_redist.x64.exe"
    Set-Location $LTSvc
    .\vc_redist.x64.exe /q | Wait-Process

    Set-Location $working_dir
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

# Bitlocker state object
# IsBitlockerEnabled returns TRUE if volume is fully encrypted, keyprotector is present, and protection status is "On"
# IsBitlockerEnabled returns FALSE if volume is fully encrypted, keyprotector is present, and protection status is "Off"
function Get-BitlockerState {

    $ERGBitlocker = Get-BitLockerVolume -MountPoint "C:"

    $BitlockerState = New-Object psobject
    $BitlockerState | Add-Member NoteProperty "VolumeStatus" $ERGBitlocker.VolumeStatus
    $BitlockerState | Add-Member NoteProperty "ProtectionStatus" $ERGBitlocker.ProtectionStatus
    $BitlockerState | Add-Member NoteProperty "KeyProtector" $ERGBitlocker.KeyProtector

    $BitlockerState | Add-Member ScriptMethod "IsBitlockerEnabled" {
        if ($this.VolumeStatus -like "FullyEncrypted" -and $this.KeyProtector.RecoveryPassword -and $this.ProtectionStatus -like "On") {
            return $true
        }
        elseif ($this.VolumeStatus -like "FullyEncrypted" -and $this.KeyProtector.RecoveryPassword -and $this.ProtectionStatus -like "Off") {
            return $false
        }   
    }

    # $BitlockerState | Add-Member ScriptMethod "IsRecoveryPasswordSet" {

    #     if (($this.KeyProtector.RecoveryPassword)) {
    #         return $true
    #     }
    #     else {
    #         return $false
    #     }

    #}




    return $BitlockerState
}

# If volume is unencrypted and TPM is ready, then enable Bitlocker
function Set-ERGBitlocker {

    $tpm = Get-TPMState

    $bitlocker_options = @{

        MountPoint       = "C:"
        EncryptionMethod = "XtsAes128"
        TpmProtector     = $true
        UsedSpaceOnly    = $true
        SkiphardwareTest = $true

    }

    if ((!(IsVolumeEncrypted)) -and $tpm.CheckTPMReady()) {

        try {
            
            Enable-Bitlocker @bitlocker_options
        }
        catch {

            throw "Bitlocker was not enabled. Check TPM and try again." 
        }   
    }

}

# If Bitlocker is enabled, then add recovery password protector
function Add-RecoveryKeyProtector {
    
    if (IsVolumeEncrypted) {
        Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector
    }
}

# Gets the Bitlocker recovery key
function Get-RecoveryKey {

    $key = (Get-BitLockerVolume -MountPoint "C:").KeyProtector.recoverypassword
    return $key
    
}


# Check if TPM Security is enabled in the BIOS - Returns True or False
function IsTPMSecurityEnabled {
        
    return (Get-Item -Path DellSmbios:\TPMSecurity\TPMSecurity).CurrentValue
}

# Check if TPM is Activated in the BIOS - Returns Enabled or Disabled
function IsTPMActivated {

    return (Get-Item -Path DellSmbios:\TPMSecurity\TPMActivation).CurrentValue
}

########################
### SCRIPT FUNCTIONS ###
########################



# Check Execution Policy
if (((Get-ExecutionPolicy) -ne "Unrestricted") -and ((Get-ExecutionPolicy) -eq "Bypass")) {

    try {
        Set-ExecutionPolicy Bypass -Force
    }
    catch {
        throw "Current ExecutionPolicy prohibits this script from running and should be set to Bypass. Manual remediation required!"
    }
}

# Check BIOS Version
# Upgrade BIOS if not up to date
if (Get-SMBiosRequiresUpgrade) {
    throw "BIOS version does not meet minimum requirements and needs to be upgraded. Manual remediation required!"
}

# Initial check for Bitlocker. Checks for VolumeStatus, KeyProtectors, and ProtectionStatus
$bitlocker_status = Get-BitlockerState

if ($bitlocker_status.IsBitlockerEnabled()){

    Write-Host "Bitlocker is enabled and protection is ACTIVE!" -ForegroundColor Green
    return $bitlocker_status

}elseif (!($bitlocker_status.IsBitlockerEnabled())) {

    try {
        Resume-BitLocker -MountPoint C:
    }
    catch {
        throw "Protection was NOT turned. Manual remediation required!"
    }
    return Get-BitlockerState
    
}

# If TPM is ready and volume is NOT encrypted, enable Bitlocker
$TPMState = Get-TPMState
if ($TPMState.CheckTPMReady() -and !(IsVolumeEncrypted)) {
    Write-Host "TPM is ready! Attempting to enable Bitlocker......" -ForegroundColor Green
    try {

        Set-ERGBitlocker
        
        Write-Host "`tBitlocker has been ENABLED" -ForegroundColor Green

        Write-Host "`tAttempting to add recovery password...." -ForegroundColor Yellow

        Add-RecoveryKeyProtector

        Write-Host "`tRecovery key has been added" -ForegroundColor Green
        
    }
    catch {
        throw "Bitlocker was not enabled."
    }
    Write-Host "Bitlocker enabled. REBOOT REQUIRED" -ForegroundColor Red -BackgroundColor Black  
    return
    
}
elseif (!($TPMstate.CheckTPMReady())) {

    Write-Host "TPM check has failed! Attempting to remeditate..." -ForegroundColor Yellow

} 
# REBOOT REQUIRED here if Bitlocker is enabled above

# Visual C++ Runtime Libraries
VCChecks

# Install DellBiosProvider
if (!(Get-SMBiosRequiresUpgrade) -and !($TPMState.CheckTPMReady())) {

    Write-Host "Attempting to install DellBiosProvider...." -ForegroundColor Yellow

    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module -Name DellBiosProvider -MinimumVersion 2.7.2 -Force
        Import-Module DellBiosProvider -Verbose
        
    }
    catch {
        throw "DellBiosProvider was not installed. Manual remediation required!"
    }

    Write-Host "DellBiosProvider installed successfully!" -ForegroundColor Green

}
elseif (!(Get-SMBiosRequiresUpgrade) -and ($TPMState.CheckTPMReady())) {

    Write-Host "Attempting to enable Bitlocker..." -ForegroundColor Yellow
    try {

        Set-ERGBitlocker
        
        Write-Host "`tBitlocker has been ENABLED" -ForegroundColor Green

        Write-Host "`tAttempting to add recovery password...." -ForegroundColor Yellow

        Add-RecoveryKeyProtector

        Write-Host "`tRecovery key has been added" -ForegroundColor Green
    }
    catch {
        throw "Bitlocker was not enabled. Manuel remediation required"
    }

    Write-Host "Bitlocker enabled. REBOOT REQUIRED" -ForegroundColor Red -BackgroundColor Black
    return 

}

# REBOOT REQUIRED here if Bitlocker is enabled above

# Set BIOS Password
if (!(IsBIOSPasswordSet)) {

    Write-Host "Setting BIOS password..." -ForegroundColor Yellow
    try {
       
        Set-BiosAdminPassword -Password (GenerateRandomPassword -SaveToFile) 
        $GeneratedPW = Get-Content -Path $LTSvc\Biospw.txt
    }
    catch {

        throw "Setting BIOS password FAILED. Manual remediation required"
    }
    Write-Host "Current BIOS Password: $GeneratedPW" -ForegroundColor Green -BackgroundColor Black
    Write-Host "Password has been saved to C:\Windows\LTSVC\Packages\biospw.txt" -ForegroundColor Green -BackgroundColor Black
}
else {
    
    throw "Unknown BIOS password detected. Manual remediation required."
}
 
# Enable TPM scurity in the BIOS

$bios_pw = Get-Content -Path $LTSvc\BiosPW.txt
if (IsTPMSecurityEnabled) {
    Write-Host "TPM security is enabled in the BIOS." -ForegroundColor Green -BackgroundColor Black
}
else {
    Set-Item -Path DellSmbios:\TpmSecurity\TpmSecurity Enabled -Password $bios_pw
}

# Enable TPM Activation in the BIOS
if ((IsTPMSecurityEnabled) -and (IsTPMActivated -eq "Disabled")) {

    try {
        Set-Item -Path DellSmbios:\TPMSecurity\TPMActivation Enabled -Password $bios_pw
    }
    catch {
        throw "TPM not enabled. Manual remediation required!"
    }

    Write-Host "TPM enabled. REBOOT REQUIRED!" -ForegroundColor Red -BackgroundColor Black

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
    }

    Write-Host "BIOS password has been removed:" $biospw_validation -ForegroundColor Green -BackgroundColor Black
}
else {

    throw "Bitlocker is NOT enabled. Manual remediation required!"
}

# Remove BiosPW.txt
if (IsBIOSPasswordSet) {
    Write-Host "Attempting to delete BiosPW.txt" -ForegroundColor Yellow

    throw "Remove the BIOS password before deleting the file. Manual remediation required!"

}
else {
    
    Remove-Item -Path $LTSvc\Biospw.txt -Force
    
    Write-Host "Biospw.txt has been successfully removed!" -ForegroundColor Green
}

Write-Host "TPM is now ready. Reboot the system and rerun the script to enable Bitlocker" -ForegroundColor Red -BackgroundColor Black

# REBOOT REQUIRED HERE

Stop-Transcript 