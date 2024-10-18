function EncryptState{
    
}


switch ($bitlocker_status.IsVolumeEncrypted()) {

    {$_ -eq 0} {   
        Write-Error -Message "FAILURE: DRIVE NOT ENCRYPTED" -Category NotEnabled
        Write-Host "`tContinuing to enable Bitlocker" -ForegroundColor Yellow break
    }
    {$_ -eq 1} { 
        Write-Host "SUCCESS: Drive is FullyEncrypted. Checking Key Protectors." -ForegroundColor Yellow
    }
    
}

switch ($bitlocker_status.IsTPMKeyPresent()) {
    {$_ -eq $true} {  
        Write-Host "SUCCESS: TPM Protector found...Continuing checks" -ForegroundColor Yellow
    }
    {$_ -eq $false} { 
        # TODO Actions for TPM Protector not found
        try {                            
            Add-TPMKeyProtector
            Write-Host "SUCCESS: TPM key ADDED" -ForegroundColor Green
            $TPMKey = $true
        }
        catch {
            throw "FAILURE: TPM key NOT ADDED. Manual Remediation required!"
        }
    }
    
}


switch ($bitlocker_status.IsRecoveryPassword()) {
    {$_ -eq $true} {  
        Write-Host "SUCCESS: Recovery Password found...Continue checks" -ForegroundColor Yellow
    }
    {$_ -eq $false} {  
        # TODO Actions for Recovery Password not found
        try {                                    
            Add-RecoveryKeyProtector
            Write-Host "SUCCESS: Recovery key added" -ForegroundColor Green
            $RecoveryKey = $true
        }
        catch {
            throw "FAILURE: Recovery key NOT added. Manual Remediation required!"
        }
    }
    
}



switch ($bitlocker_status.IsProtected()) {
                                    {$_ -eq 1} {
                                        Write-Host "SUCCESS: Bitlocker fully ENABLED. No action needed!" -ForegroundColor Green
                                        # TODO Script termination needed here
                                        break 
                                    }
                                    {$_ -eq 0} {
                                        # TODO Actions if Protection Status is OFF
                                        try {
                                            Resume-Bitlocker -MountPoint C:
                                            Write-Host "SUCCESS: Protection is ENABLED" -ForegroundColor Green
                                            
                                        }
                                        catch {
                                            throw "FAILURE: Protection NOT ENABLED. Manual Remediation required!"
                                        }
                                    }
                                    
                                }