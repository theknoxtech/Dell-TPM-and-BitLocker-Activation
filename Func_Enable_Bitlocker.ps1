function IsVolumeEncrypted {
    Param(
        [Parameter(Mandatory = $true)]
        [char]$DriveLetter
    )

    $volume_status = (Get-BitLockerVolume -MountPoint "$($DriveLetter):" -ErrorAction SilentlyContinue).VolumeStatus

    if ($volume_status -eq "FullyEncrypted" -or $volume_status -eq "EncryptionInProgress") {
        return $true
    }

    return $false
}


function Get-TPMState {

    $TPM = Get-Tpm

    $TPMState = New-Object psobject
    $TPMState | Add-Member NoteProperty "IsPresent" $TPM.TpmPresent
    $TPMState | Add-Member NoteProperty "IsReady" $TPM.TpmReady
    $TPMState | Add-Member NoteProperty "IsEnabled" $TPM.TpmEnabled

    $TPMState | Add-Member ScriptMethod "CheckTPMReady" {
        if ($this.IsPresent -and $this.IsReady -and $this.IsEnabled) {
            return $true
        }

        return $false
    }

    return $TPMState
}


funtion Set-Bitlocker {


    $bitlocker_options = @{

        MountPoint                = "C:"
        EncryptionMethod          = "XtsAes128"
        TpmProtector              = $true
        UsedSpaceOnly             = $true

    }

    if (IsVolumeEncrypted -eq $false -and $TPMState.CheckTPMReady() -eq $true) {

        try {
            
            Enable-Bitlocker @bitlocker_options
        }
        catch {

            throw "There was an issue enabling Bitlocker. Please try again" 
        }   
}

}


