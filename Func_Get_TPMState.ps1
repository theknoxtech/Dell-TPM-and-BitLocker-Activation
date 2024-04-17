function Get-TPMState {

    $TPMCheck1 = Get-Tpm | Select-Object -Property 
    return $TPM

    #Return "TPM is not found"
}

Get-TPMState

#$TPMActive = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -class 'win32_tpm' | Select-Object -Property IsActivated_InitialValue
#>
#Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'win32_tpm'