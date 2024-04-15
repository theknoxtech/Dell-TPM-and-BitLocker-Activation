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

#TPM Check

function Get-TPMState {

    $CheckTPM = Get-Tpm | Select-Object TpmPresent

    if ($CheckTPM -eq $false){
        Return "TPM is not present "
    }
    Return "TPM is present"

}

Get-TPMState