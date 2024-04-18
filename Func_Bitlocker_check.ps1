function Get-BitlockerStatus {
    $Encrypted =  Get-Bitlockervolume -Mountpoint C: | Select-Object -ExpandProperty EncryptionPercentage
    $Status =  Get-Bitlockervolume -Mountpoint C: | Select-Object -ExpandProperty ProtectionStatus

    if (($Encrypted -gt 0) -and ($Status -eq "On")) {
        return "Bitlocker is Enabled"
    }
}

Get-BitlockerStatus
