#Bios Check

function Get-SMBiosVersion {
    $Bios = Get-CimInstance Win32_BIOS 
    $Version = [float]::Parse("$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)")
    

    if ($Version -ge "2.4"){

        Write-Host "The bios version is"
    }

}

Get-SMBiosVersion
