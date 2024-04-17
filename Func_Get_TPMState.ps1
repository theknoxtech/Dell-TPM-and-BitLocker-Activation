function Get-TPMState {

    $Check1 = Get-Tpm | Select-Object -Property TpmPresent
    $Check2 = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'win32_tpm' | Select-Object IsEnabled_InitialValue
    
    if ($Check1){
        Write-Host "TPM is present" 
        if ($Check2) {
            Return "TPM is enabled"
            }

        }
    }


    #Return "TPM is not found"


Get-TPMState

#$TPMActive = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -class 'win32_tpm' | Select-Object -Property IsActivated_InitialValue
#>
#Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'win32_tpm'