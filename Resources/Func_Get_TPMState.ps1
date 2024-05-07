function Get-TPMState {

        $Check1 = Get-Tpm | Select-Object -ExpandProperty TpmPresent
        $Check2 = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'win32_tpm' | Select-Object -ExpandProperty IsEnabled_InitialValue
        
        if ($Check1) {
            Write-Host "TPM is present" 
            if ($Check2) {
                Write-Host "TPM is enabled"
            }
            else { 
                Write-Host "TPM is NOT enabled"; break 
            }
        }
        else {
            Write-Host "NO TPM Present"; break
        }
    }


    #Return "TPM is not found"


    Get-TPMState

   <# if ($Check1){
        Write-Host "TPM is present"
        if ($Check2) {
            Return "TPM is enabled"
            else {
                Return "TPM not enabled"
        }    
        }
            else {
                Return "TPM not present"
        
    }
        } #>
    


    #Return "TPM is not found"

#$TPMActive = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -class 'win32_tpm' | Select-Object -Property IsActivated_InitialValue
#>
#Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'win32_tpm'