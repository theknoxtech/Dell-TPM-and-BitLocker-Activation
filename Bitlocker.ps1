#Bios Check

function Get-SMBiosVersion {
    $Bios = Get-CimInstance Win32_BIOS 
    $Version = [float]::Parse("$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)")
    
    if ($Version -ge "2.4"){
        Write-Host "Version is compatible"
    }
    else{
        Write-Host "Version is not compatible" -ErrorAction Stop
    }

}

Get-SMBiosVersion
