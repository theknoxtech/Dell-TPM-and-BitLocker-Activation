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

    if ($volume_status -eq "FullyEncrypted" -or $volume_status -eq "EncryptionInProgress")
    {
        return $true
    }

    return $false
}

# BIOS verion check
function Get-SMBiosVersion {
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
  
  if ((Get-SMBiosVersion) -lt $MinimumVersion){
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
        if ($this.IsPresent -and $this.IsReady -and $this.IsEnabled)
        {
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

function IsBIOSPasswordSet {
    return (Get-Item -Path DellSmBios:\Security\IsAdminpasswordSet).CurrentValue
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
      
    $current_password = Get-Content -Path $LTSvc\biospw.txt 
    Set-Item -Path DellSmbios:\Security\AdminPassword ""  -Password $current_password

}

# If volume is unencrypted and TPM is ready, then enable Bitlocker
function Set-ERGBitlocker {

    $tpm = Get-TPMState

    $bitlocker_options = @{

        MountPoint       = "C:"
        EncryptionMethod = "XtsAes128"
        TpmProtector     = $true
        UsedSpaceOnly    = $true
        SkiphardwareTest  = $true

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
function IsTPMActivated{

    return (Get-Item -Path DellSmbios:\TPMSecurity\TPMActivation).CurrentValue
}

########################
### SCRIPT FUNCTIONS ###
########################

# Check Execution Policy
if (((Get-ExecutionPolicy) -ne "Unrestricted") -and ((Get-ExecutionPolicy) -eq "Bypass")){

    try {
        Set-ExecutionPolicy Bypass
    }
    catch {
        throw "Current ExecutionPolicy prohibits this script from running and should be set to Bypass. Manual remediation required!"
    }
}

# Check BIOS Version
    # Upgrade BIOS if not up to date
    if (Get-SMBiosRequiresUpgrade)
    {
        throw "BIOS version does not meet minimum requirements and needs to be upgraded. Manual remediation required!"
    }

# Bitlocker Validation
# If Bitlocker is enabled and recovery key is found, exit and return the key!
# If Bitlocker is enabled and recovey key is NOT found, add recovery key and return the key
if ((IsVolumeEncrypted) -and (Get-RecoveryKey)) {

    Write-Host "Bitlocker already enabled! Checking for recovery key....." -ForegroundColor Yellow
    return Get-RecoveryKey

}
elseif ((IsVolumeEncrypted) -and (!(Get-RecoveryKey))) {

    Write-Host "Adding recovery key...."  -ForegroundColor Yellow  
    Add-RecoveryKeyProtector

    Write-Host "Recovery key added..." -ForegroundColor Green
    return Get-RecoveryKey  
}


# TPM Logic if Bitlocker not enabled
$TPMState = Get-TPMState
if ($TPMState.CheckTPMReady())
{
    Write-Host "TPM is ready!" -ForegroundColor Green
    
}
else 
{
    Write-Host "TPM check has failed! Attempting to remeditate..." -ForegroundColor Yellow
    
}

# Visual C++ Runtime Libraries
VCChecks

# Install DellBiosProvider
if (!(Get-SMBiosRequiresUpgrade) -and !($TPMState.CheckTPMReady())){

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

}elseif (!(Get-SMBiosRequiresUpgrade) -and ($TPMState.CheckTPMReady())) {

    Write-Host "Attempting to enable Bitlocker..." -ForegroundColor Yellow
    try {

        Set-ERGBitlocker
        
    }
    catch {
        throw "Bitlocker was not enabled."
    }

    Write-Host "Bitlocker enabled. REBOOT REQUIRED!"

}

# REBOOT REQUIRED here if Bitlocker is enabled above

# Set BIOS Password
if (!(IsBIOSPasswordSet)) {
    Write-Host "Setting BIOS password..." -ForegroundColor Yellow

    Set-BiosAdminPassword -Password (GenerateRandomPassword -SaveToFile)

    Write-Host "Password has been saved to C:\Windows\LTSVC\Packages\biospw.txt" -ForegroundColor Green

}
else {

    throw "BIOS password already set and must be cleared before proceeding. Manual remediation required!"
}

# Enable TPM scurity in the BIOS

$bios_pw = Get-Content -Path $LTSvc\BiosPW.txt
if (IsTPMSecurityEnabled)
{
    Write-Host "TPM security is enabled in the BIOS." -ForegroundColor Green
}
else 
{
    Set-Item -Path DellSmbios:\TpmSecurity\TpmSecurity Enabled -Password $bios_pw
}

# Enable TPM Activation in the BIOS
if ((IsTPMSecurityEnabled) -and (IsTPMActivated -eq "Disabled"))
{

    try {
        Set-Item -Path DellSmbios:\TPMSecurity\TPMActivation Enabled -Password $bios_pw
    }
    catch {
        throw "TPM not enabled. Manual remediation required!"
    }

    Write-Host "TPM enabled. REBOOT REQUIRED!"

}

# REBOOT REQUIRED HERE

# Enable Bitlocker 
if ((IsTPMSecurityEnabled) -and (IsTPMActivated -eq "Enabled")){
    Write-Host "Attempting to enable Bitlocker..." -ForegroundColor Yellow

    Set-ERGBitlocker

    Write-Host "`t\Bitlocker enabled. REBOOT REQUIRED!" -ForegroundColor Green

}else{

    throw "Bitlocker not enabled. Manual remediation required!"
}

# REBOOT REQUIRED HERE

# Add Recovery Key Protector 
if (IsVolumeEncrypted){

    Write-Host "Attempting to add recovery key protector..." -ForegroundColor Yellow

    try {
        Add-RecoveryKeyProtector
    }
    catch {
        throw "Recovery key protector was not added. Manual remediation required!"
    }
    
    Write-Host "`t\Operation complete..." -ForegroundColor Yellow

    return Get-RecoveryKey

}

# Remove BIOS Password
Write-Host "Bitlocker is now enabled. Attempting removal of BIOS password." -ForegroundColor Yellow

if (IsVolumeEncrypted) {
    
    $biospw_validation = IsBIOSPasswordSet
    Write-Host "Attempting BIOS password removal..." -ForegroundColor Yellow
    try {
        
        Remove-BiosAdminPassword -RemovePassword $current_password
    }
    catch {
        throw "BIOS password was not removed. Manual remediation required!"
    }
    
    Write-Host "Operation complete..." -ForegroundColor Yellow
   
    Write-Host "BIOS password has been removed:" $biospw_validation -ForegroundColor Green

}

# Remove BiosPW.txt
if (IsBIOSPasswordSet){
    Write-Host "Attempting to delete BiosPW.txt" -ForegroundColor Yellow

    throw "Remove the BIOS password before deleting the file. Manual remediation required!"

}else {
    
    Remove-Item -Path $LTSvc\Biospw.txt -Force
    
    Write-Host "Biospw.txt has been successfully removed!" -ForegroundColor Green
}

Stop-Transcript
