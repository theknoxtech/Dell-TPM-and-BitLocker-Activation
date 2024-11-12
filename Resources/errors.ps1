if (!($var.IsProtected())) {
    >> try {
    >> Resume-Bitlocker -MountPoint "c:" -ErrorAction Stop
    >> }catch [System.Runtime.InteropServices.COMException] {
    >> Add-KeyProtector -TPMProtector
    >> Resume-Bitlocker -MountPoint c: 
    >> }
    >> }