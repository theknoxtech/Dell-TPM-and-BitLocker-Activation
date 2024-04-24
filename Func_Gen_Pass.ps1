#$LTSvc = "C:\Windows\LTSvc\Packages"

function IsBIOSPasswordSet {
    return (Get-Item -Path DellSmBios:\Security\IsAdminpasswordSet).CurrentValue
}

function GenerateRandomPassword {
    Param(
        [switch]$SaveToFile
    )

    $password = (Invoke-WebRequest -Uri "https://www.dinopass.com/password/strong").Content

    if ($SaveToFile) {
        $password | Out-File $LTSvc\BiosPW.txt
    }
    
    return $password
}

#TODO Update Set-BiosAdminPassword function with GenerateRandomPassword
function Set-BiosAdminPassword {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Password
    )
    $Password = Get-Content $LTSvc\BiosPW.txt
    Set-Item -Path DellSmBios:\Security\AdminPassword $Password
   

}

###SCRIPTFUNCTION####

if (IsBIOSPasswordSet) {

    Set-BiosAdminPassword -Password (GenerateRandomPassword -SaveToFile)
}
else {

    throw "BIOS Password already set: Clear BIOS password before proceeding"
}