function Get-SMBiosVersion {
    $Bios = Get-CimInstance Win32_BIOS 
    $Version = [float]::Parse("$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)")
    return $Version
}



function Get-BiosRequiresUpdate {
    $CurrentVer = Get-SMBiosVersion
    $MinVer = 2.4

    if (($CurrentVer) -le $MinVer) {
        Return Write-Host "Bios is at version $($CurrentVer). Bios must be at $($MinVer) or higher." -ErrorAction Stop
    }
    Return Write-Host "Bios meets minimum version requirements"


}

Get-BiosRequiresUpdate