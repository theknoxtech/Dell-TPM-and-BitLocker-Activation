function IsVCRedistInstalled {
    # Param(
    #     [Parameter(Mandatory = $false)]
    #     [int]$Version
    # )
    $version = Get-CimInstance Win32_Product | Where-Object -Property Vendor -eq "Microsoft Corporation" 
    $installed_version = New-Object psobject
    $installed_version | Add-Member NoteProperty "Name" $version.Name
    $installed_version | Add-Member NoteProperty "PackageName" $version.PackageName
    $installed_version | Add-Member NoteProperty "Vendor" $version.Vendor

    $installed_version | Add-Member ScriptMethod "CheckInstalledVersions" {
        if ($this.PackageName -like "vc_red" -or $this.PackageName -like "vc_runtimeMinimum_x64") {
            Return 
        } 

        return $false
    }

    return $installed_version


}
(IsVCRedistInstalled).CheckInstalledVersions