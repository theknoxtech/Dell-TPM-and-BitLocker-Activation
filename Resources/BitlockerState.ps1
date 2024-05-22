function Get-BitlockerState {

    $ERGBitlocker = Get-BitLockerVolume -MountPoint "C:"

    $BitlockerState = New-Object psobject
    $BitlockerState | Add-Member NoteProperty "VolumeStatus" $ERGBitlocker.VolumeStatus
    $BitlockerState | Add-Member NoteProperty "ProtectionStatus" $ERGBitlocker.ProtectionStatus
    $BitlockerState | Add-Member NoteProperty "KeyProtector" $ERGBitlocker.KeyProtector

    $BitlockerState | Add-Member ScriptMethod "IsProtectionOn" {
        if ($this.VolumeStatus -like "FullyEncrypted" -and $this.KeyProtector.RecoveryPassword -and $this.ProtectionStatus -like "On") {
            return $true
        }
        return $false
    }


    return $BitlockerState
}