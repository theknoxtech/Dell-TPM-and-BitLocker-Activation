$LTSvc = "C:\Windows\LTSvc\packages"

$AdminPasswordCheck = Get-Item -Path DellSmBios:\Security\IsAdminpasswordSet | Select-Object -ExpandProperty CurrentValue
$PwdCheck = $AdminPasswordCheck

$DinoPass = "https://www.dinopass.com/password/strong"
$GeneratePW = Invoke-WebRequest -Uri $DinoPass | Select-Object -ExpandProperty Content 
$GeneratePW | Out-File -FilePath $LTSvc\BiosPW.txt





#SetBiosAdminPassword
function Set-BiosAdminPassword {
    param(
        [String]$Password
    )
    if ($PwdCheck -eq $false) {
        $Password = Get-Content $LTSvc\BiosPW.txt
        Set-Item -Path DellSmBios:\Security\AdminPassword $Password
    }
    else {
        Get-ComputerInfo | Select-Object -ExpandProperty CsName | Out-File c:\temp\bitlockerpwlog.txt -append
        return "Bios password detected it's borked"
    }

}

Set-BiosAdminPassword -$Password