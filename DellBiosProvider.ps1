$AdminPasswordCheck = Get-Item -Path DellSmBios:\Security\IsAdminpasswordSet | Select-Object -ExpandProperty CurrentValue
$PwdCheck = $AdminPasswordCheck

function Set-BiosAdminPassword {
   
    param(
        [String]$Password
    )

    if ($PwdCheck -eq $false){
        Set-Item -Path DellSmBios:\Security\AdminPassword $Password
    }else {
        Get-ComputerInfo | Select-Object -ExcludeProperty CsName | Out-File c:\temp\test.txt -append
        return "Bios password detected it's borked"
    }

}

Set-BiosAdminPassword -Password AVeryStrongPassword

