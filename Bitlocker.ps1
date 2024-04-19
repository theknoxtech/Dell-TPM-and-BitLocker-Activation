#Global Storage Path
$LTSvc = "C:\Windows\LTSvc\packages"

#Start Transcript
# Start-Transcript -Path $LTSvc -Verbose

#Bitlocker Check
function IsVolumeEncrypted {
    Param(
        [Parameter(Mandatory=$true)]
        [char]$DriveLetter
    )

    $volume_status = (Get-BitLockerVolume -MountPoint "$($DriveLetter):" -ErrorAction SilentlyContinue).VolumeStatus

    if ($volume_status -eq "FullyEncrypted" -or $volume_status -eq "EncryptionInProgress")
    {
        return $true
    }

    return $false
}

#Bios verion check
function Get-SMBiosVersion {
    $Bios = Get-CimInstance Win32_BIOS 
    $Version = [float]::Parse("$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)")
    return $Version
}

# Returns true if BIOS version does not meet minium requirements. Returns False otherwise.
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

function IsVCRedistInstalled {
    Param(
        [Parameter(Mandatory = $true)]
        [int]$Version
    )
    $version = Get-CimInstance Win32_Product | Select-Object -Property Name, PackageName 
    $installed_version = New-Object psobject
    $installed_version | Add-Member NoteProperty "Name" $version.Name
    $installed_version | Add-Member NoteProperty "PackageName" $version.PackageName

    $installed_version | Add-Member ScriptMethod "CheckInstalledVersions" {
        if ($this.PackageName -eq "vc_red.msi" -or $this.PackageName -eq "vc_runtimeMinimum_x64.msi"){
            Return $true
        } 

        return $false
    }

    return $Version


}







#Redistributable 2010
function Get-VCRedist10 {
    



    $2010 = Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.displayname -like "Microsoft Visual C++ 2010" }

    if (-not ($2010)) {
    
        #Start-BitsTransfer -Source "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe" -Destination "$($LTSvc)\2010vc_redist_x64.exe"
        [System.NET.WebClient]::new().DownloadFile("https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe", "$($LTSvc)\vcredist_2010_x64.exe")
        Set-Location $LTSvc
        .\2010vc_redist_x64.exe /extract:vc2010 /q
        Start-Sleep -Seconds 1.5
        Set-Location $LTSvc\vc2010
        .\Setup.exe /q

        #$path = [System.IO.Path]::Combine($LTSvc, "\2010vc_redist_x64.exe")

        Write-Host $path

        #Start-Process -NoNewWindow -FilePath "$($LTSvc)\2010vc_redist_x64.exe" -ArgumentList "/extract:vc2010", "/q" -Wait
        #Start-Process -NoNewWindow -FilePath "$($LTSvc)\vc2010\Setup.exe" -ArgumentList "/q" -Wait
    }
}

#Redistributable 2015-2022
function Get-VCRedist22 {
    $2015 = Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.displayname -like "Microsoft Visual C++ 2015-2022" }

    if (-not($2015)) {
       
        Start-BitsTransfer -Source "https://aka.ms/vs/17/release/vc_redist.x64.exe" -Destination "$($LTSvc)\vc_redist.x64.exe" #C:\Windows\LTSvc\packages
        Set-Location $LTSvc
        .\vc_redist.x64.exe /extract:x64 /q
    }
}

# #Nuget
# Install-PackageProvider -Name nuget -MinimumVersion 2.8.5.201 -Force

# #DellBiosProvider
# Install-Module -Name DellBIOSProvider -Force
# Import-Module DellBiosProvider -Verbose



# #GetBiosAdminPassword
# $AdminPasswordCheck = Get-Item -Path DellSmBios:\Security\IsAdminpasswordSet | Select-Object -ExpandProperty CurrentValue
# $PwdCheck = $AdminPasswordCheck

# #GeneratePassword
# $DinoPass = "https://www.dinopass.com/password/strong"
# $GeneratePW = Invoke-WebRequest -Uri $DinoPass | Select-Object -ExpandProperty Content 
# $GeneratePW | Out-File -FilePath $LTSvc\BiosPW.txt


#SetBiosAdminPassword
function Set-BiosAdminPassword {
    param(
        [String]$Password
    )
    if ($PwdCheck -eq $false) {
        $Password = Get-Content $LTSvc\BiosPW.txt
        Set-Item -Path DellSmBios:\Security\AdminPassword $Password
    }
    else {
        Get-ComputerInfo | Select-Object -ExpandProperty CsName | Out-File c:\temp\bitlockerpwlog.txt -append
        return "Bios password detected it's borked"
    }

}

# Set-BiosAdminPassword -$Password










#Stop Transcript
# Stop-Transcript

#IsVolumeEncrypted -DriveLetter D

function Get-BiosRequiresUpdate {
    $CurVer = Get-SMBiosVersion
    $MinVer = 4.2

    if (Get-SMBiosRequiresUpgrade -MinimumVersion 4.2){
        Write-Host "Bios is at version $($CurVer). Bios must be at $($MinVer) or higher." -ErrorAction Stop
    }

    else {
        Write-Host "Bios meets minimum version requirements"
    }


}


Get-BiosRequiresUpdate