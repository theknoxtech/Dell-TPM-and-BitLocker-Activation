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

# Start Transcript
#Start-Transcript -Path $LTSvc\enable_bitlocker.txt -Verbose
$Log = "$LTSvc\enable_bitlocker.txt"

# Bitlocker status check
# TODO Refactor all references to use Get-BitlockerState
<# function IsVolumeEncrypted {
 
    $volume_status = (Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue).VolumeStatus

    if ($volume_status -eq "FullyEncrypted" -or $volume_status -eq "EncryptionInProgress") {
        return $true
    }

    return $false
}
 #>

# Creates a log entry in LTSvc\Packages\enable_bitlocker.txt
function Add-LogEntry {
    
    Param(
    [string]$Message,
    [string]$Type
    )

    $date_time = (Get-Date).ToString("MM/dd/yyyy HH:mm:ss")

    $entry = "$message"

    if ($type -eq "Debug") {

        Add-Content $Log -Value "$date_time DEBUG: $entry"

    }elseif ($type -eq "Error") {

        Add-Content $Log -Value "$date_time ERROR: $($_.Exception.Message)"
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
        }
        catch {

            throw "Bitlocker was not enabled. Check TPM and try again." 
        }   
    }

}

# Check if Visual C++ Redistributables are installed and if not install Visual C++ 2010 and Visual C++ 2015-2022
function Install-Redistributables {
    # Visual C++ Redistributable logic
    # Check for Visual C++ Redistributable packages
  
    $products = Get-CimInstance win32_product
 

    # Visual C++ 2010 Redistributable
  
    if (($products | Where-Object { $_.name -like "Microsoft Visual C++ 2010*" })) {
    
        Add-LogEntry "Visual C++ 2010 already installed"
    }
    # Handle install logic
    else {
       
        Install-VCRedist2010

         Add-LogEntry "Visual C++ 2010 has been installed"
    }
    # Visual C++ 2022 Redistributable
 
    if (($products | Where-Object { $_.name -like "Microsoft Visual C++ 2022*" })) {

         Add-LogEntry "Visual C++ 2022 already installed"

    }
    # Handle install logic
    else {
        
        Install-VCRedist2022

        Add-LogEntry "Visual C++ 2010 has been installed"
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

    [System.NET.WebClient]::new().DownloadFile("https://aka.ms/vs/17/release/vc_redist.x64.exe", "$($LTSvc)\vc_redist.x64.exe")
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

########################
### SCRIPT FUNCTIONS ###
########################

# Check Execution Policy
if (((Get-ExecutionPolicy) -ne "Unrestricted") -and ((Get-ExecutionPolicy) -eq "Bypass")) {
# TODO add error handling here
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


$TPMState = Get-TPMState
$bitlocker_status = Get-BitlockerState
$bitlocker_settings = @{

    "Encrypted" = $bitlocker_status.IsVolumeEncrypted()
    "TPMProtectorExists" = $bitlocker_status.IsTPMKeyPresent()
    "RecoveryPasswordExists" = $bitlocker_status.IsRecoveryPassword()
    "Protected" = $bitlocker_status.IsProtected()
}

Switch ($bitlocker_status.IsRebootRequired()){
    {$_ -gt 0} {
        throw "REBOOT REQUIRED"
    }
}

Switch ($bitlocker_settings) {
    {($_.Encrypted -eq $false) -and ($TPMState.CheckTPMReady() -eq $true)} {
        
        Set-BitlockerState
    }
    {$_.TPMProtectorExists -eq $false} {
        Add-KeyProtector -TPMProtector
        
    }
    {$_.RecoveryPasswordExists -eq $false} {
        Add-KeyProtector -RecoveryPassword
        
    }
    {$_.Protected -eq $false} {
        # TODO add error handling here
        Resume-Bitlocker -MountPoint "C:"
        break
    }
    
  
}

$enabled_settings = 0
ForEach ($setting in $bitlocker_settings.GetEnumerator()){

    if ($setting.value -eq $true) {
        
        Write-Host "The setting $($setting.Name) is $($setting.value)"
        $enabled_settings = $enabled_settings + 1
    }
    
}
$enabled_settings





if ($TPMState.CheckTPMReady() -and !($bitlocker_settings.Encrypted)) {
    Write-Host "TPM is ready! Attempting to enable Bitlocker..." -ForegroundColor Green
    try {

        Set-BitlockerState

        Add-KeyProtector -RecoveryPassword
        
        Write-Host "Bitlocker enabled." -ForegroundColor Green
        Write-Host "Recovery key added." -ForegroundColor Green
        
    }
    catch {
        throw "Bitlocker was not enabled."
    }
    Write-Host "Bitlocker enabled. REBOOT REQUIRED!" -ForegroundColor Red -BackgroundColor Black  
    return
    Stop-Transcript
    
}elseif (!($TPMstate.CheckTPMReady())) {

    Write-Host "TPM check has failed! Attempting to remeditate..." -ForegroundColor Yellow

}
 
# REBOOT REQUIRED here if Bitlocker is enabled above

# Visual C++ Runtime Libraries
Install-Redistributables

# Install DellBiosProvider
if (!(Get-SMBiosRequiresUpgrade) -and !($TPMState.CheckTPMReady())) {

    Write-Host "Attempting to install DellBiosProvider..." -ForegroundColor Yellow

    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module -Name DellBiosProvider -MinimumVersion 2.7.2 -Force
        Import-Module DellBiosProvider -Verbose
        
    }
    catch {
        throw "DellBiosProvider was not installed. Manual remediation required!"
        Stop-Transcript
    }

    Write-Host "DellBiosProvider installed successfully!" -ForegroundColor Green

}elseif (!(Get-SMBiosRequiresUpgrade) -and ($TPMState.CheckTPMReady())) {

    Write-Host "Attempting to enable Bitlocker..." -ForegroundColor Yellow
    try {

        Set-BitlockerState
        
        Write-Host "`tBitlocker enabled." -ForegroundColor Green

        Write-Host "`tAdding recovery key..." -ForegroundColor Yellow
        
        Add-KeyProtector -RecoveryPassword

        Write-Host "`tRecovery key added." -ForegroundColor Green
    }
    catch {
        throw "Bitlocker was not enabled. Manual remediation required!"
        Stop-Transcript
    }

    Write-Host "Bitlocker enabled. REBOOT REQUIRED!" -ForegroundColor Red -BackgroundColor Black
    return 
    Stop-Transcript

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

        throw "Setting BIOS password failed. Manual remediation required!"
        Stop-Transcript
    }
    Write-Host "Current BIOS Password: $GeneratedPW" -ForegroundColor Green -BackgroundColor Black
    Write-Host "Password has been saved to C:\Windows\LTSVC\Packages\biospw.txt" -ForegroundColor Green -BackgroundColor Black
}
else {
    
    throw "Unknown BIOS password detected. Manual remediation required!"
    Stop-Transcript
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
        Stop-Transcript
    }

    Write-Host "TPM enabled. REBOOT REQUIRED!" -ForegroundColor Red -BackgroundColor Black
    Stop-Transcript

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
        Stop-Transcript
    }

    Write-Host "BIOS password has been removed:" $biospw_validation -ForegroundColor Green -BackgroundColor Black
}
else {

    throw "Bitlocker was not enabled. Manual remediation required!"
    Stop-Transcript
}

# Remove BiosPW.txt
if (IsBIOSPasswordSet) {
    Write-Host "Attempting to delete BiosPW.txt" -ForegroundColor Yellow

    throw "Remove the BIOS password before deleting the file. Manual remediation required!"
    Stop-Transcript

}
else {
    
    Remove-Item -Path $LTSvc\Biospw.txt -Force
    
    Write-Host "Biospw.txt has been successfully removed!" -ForegroundColor Green
}

Write-Host "REBOOT REQUIRED: Rerun after script reboot to finish Bitlocker setup" -ForegroundColor Red -BackgroundColor Black

# REBOOT REQUIRED HERE

Stop-Transcript
