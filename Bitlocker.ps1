#Bios verion check
function Get-SMBiosVersion {
    $Bios = Get-CimInstance Win32_BIOS 
    $Version = [float]::Parse("$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)")
    return $Version
}



function Get-BiosRequiresUpdate {
    $CurrentVer = Get-SMBiosVersion
    $MinVer = 2.4

    if (($CurrentVer) -le $MinVer){
        Return Write-Host "Bios is at version $($CurrentVer). Bios must be at $($MinVer) or higher." -ErrorAction Stop
    }
    Return Write-Host "Bios meets minimum version requirements"


}

Get-BiosRequiresUpdate


#Check TPM

function Get-TPMState {

    $Check1 = Get-Tpm | Select-Object -ExpandProperty TpmPresent
    $Check2 = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'win32_tpm' | Select-Object -ExpandProperty IsEnabled_InitialValue

    if ($Check1) {
        Write-Host "TPM is present" 
        if ($Check2) {
            Return "TPM is enabled"
        }else { 
            return "TPM is NOT enabled"; break 
        }
    }else {
        Write-Host "NO TPM Present"; break
    }
}


Get-TPMState



#Redistributable 2010
function Get-VCRedist10 {
    $2010 = Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.displayname -like "Microsoft Visual C++ 2010"}

    if (-not ($2010)){
        Start-BitsTransfer -Source "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe" -Destination "C:\vcdownload\2010vc_redist_x64.exe"
        Set-Location C:\vcdownload
        .\2010vc_redist_x64.exe /q /norestart /passive
    }
}

#Redistributable 2015-2022
function Get-VCRedist22 {
    $2015 = Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.displayname -like "Microsoft Visual C++ 2015-2022"}

    if (-not($2015)){
        Start-BitsTransfer -Source "https://aka.ms/vs/17/release/vc_redist.x64.exe" -Destination "C:\vcdownload\vc_redist.x64.exe"
        Set-Location C:\vcdownload
        .\vc_redist/x64.exe /q /norestart /passive
    }
}

#Nuget
Install-PackageProvider -Name nuget -MinimumVersion 2.8.5.201 -Force

#DellBiosProvider
Install-Module -Name DellBIOSProvider -Force
Import-Module DellBiosProvider -Verbose
