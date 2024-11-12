enum Logs {
    Error
    Debug
    Info
}
function Add-LogEntry {
    
    Param(
    [string]$Message,
    [Logs]$Type
    )

    $timestamp = (Get-Date).ToString("MM/dd/yyyy HH:mm:ss")

    switch ($Type) {
        ([Logs]::Debug) {Add-Content $Log "$timestamp DEBUG: $message"; break  }
        ([Logs]::Error) {Add-Content $Log "$timestamp ERROR: $message"; break }
        ([Logs]::Info) {Add-Content $Log "$timestamp INFO: $message"; break}
        (default) {Add-Content $Log "$timestamp []: $message"} 
    }
}

# Convert exception to string, match for Hresult code and return it
function Get-ExceptionCode {
    $errorcode = ($_.Exception.Message).ToString()
    $regex = "\((0x[0-9A-Fa-f]+)\)"

    if ($errorcode -match $regex) {

        $regex = $Matches[1]
        return $regex
    }

}


    $bitlocker_status = Get-BitlockerState
    $bitlocker_settings = @{
    
        "IsRebootPending" = $bitlocker_status.IsRebootRequired()
        "Encrypted" = $bitlocker_status.IsVolumeEncrypted()
        "TPMProtectorExists" = $bitlocker_status.IsTPMKeyPresent()
        "RecoveryPasswordExists" = $bitlocker_status.IsRecoveryPassword()
        "Protected" = $bitlocker_status.IsProtected()
        "TPMReady" = $TPMState.CheckTPMReady()
    }



    switch ($bitlocker_settings) {
        {$_.Protected -eq $false} {
            try {
                Resume-BitLocker -MountPoint c: -ErrorAction Stop
            }
            catch [System.Runtime.InteropServices.COMException] {
                Add-LogEntry -Type Error -Message $_.Exception.Message
                 # Attempt to encrypt drive
                #$errorcode = ($_.Exception.Message).ToString()
                
                if (Get-ExceptionCode -contains "0x80310001") {
                    
                    Set-BitlockerState
    
                }else {
                    
                    Add-LogEntry -Type Error -Message $_.Exception.Message
                }
            
                
            }
          }
     
    }