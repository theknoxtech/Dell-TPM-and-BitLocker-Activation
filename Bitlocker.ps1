#Bios verion check
function Get-SMBiosVersion {
    $Bios = Get-CimInstance Win32_BIOS 
    $Version = [float]::Parse("$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)")
    return $Version
}

Get-SMBiosVersion


<#TPM Check

function Get-TPMState {

    $TPM = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'win32_tpm' 
    return $TPM.IsActivated_InitialValue

    #Return "TPM is not found"
}

Get-TPMState

#$TPMActive = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -class 'win32_tpm' | Select-Object -Property IsActivated_InitialValue
#>

