#Bios verion check
function Get-SMBiosVersion {
    $Bios = Get-CimInstance Win32_BIOS 
    $Version = [float]::Parse("$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)")
    return $Version
}

#Get-SMBiosVersion

TPM Check

function Get-TPMState {

    $TPMEnabled = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -class 'win32_tpm' | Select-Object -Property IsEnabled_InitialValue
    $TPMActive = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -class 'win32_tpm' | Select-Object -Property IsActivated_InitialValue
    if ($TPMEnabled){
        Return $TPMEnabled
        elseif ($TPMActive) {
            Return "TPM Enabled: $($TPMEnabled)"+"TPM Active: $($TPMActive)"
        }
    }
    Return "TPM is not found"



}

Get-TPMState


