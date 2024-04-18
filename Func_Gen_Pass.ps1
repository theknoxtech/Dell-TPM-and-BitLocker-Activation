function Create-Password {

    param (
        [Parameter(Mandatory)]
        [int]$length
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($length)
}

Create-Password 10