# Base OU for searching for expired accounts
$BaseSearchOU="OU=Users,DC=Domain,DC=Local"

# OU that the expired accounts will be moved to
$DestinationOU="OU=DisabledUsers,DC=Domain,DC=Local"

# Imports the PowerShell AD module **NOTE** RSAT needs to be installed on the system running the script
if (Get-Module -ListAvailable -Name ActiveDirectory) {

    Import-Module ActiveDirectory

#  If the module is not available write a message to the terminal and end the script   
} else {
    Write-Host "No Active Directory Module found. MS RSAT tools need to be installed, see https://www.microsoft.com/en-ca/download/details.aspx?id=45520" -ForegroundColor Red

    throw "Error"
}


# Function to generat a new random password
function New-Password {
    param(
        [Parameter()]
        [int]$MinPasswordLength = 15,
        [Parameter()]
        [int]$MaxPasswordLength = 24,
        [Parameter()]
        [int]$MinSpecialCharacters = 1,
        [Parameter()]
        [int]$MaxSpecialCharacters = 5
           )
    
    Add-Type -AssemblyName 'System.Web'
    $length = Get-Random -Minimum $MinPasswordLength -Maximum $MaxPasswordLength
    $special = Get-Random -Minimum $MinSpecialCharacters -Maximum $MaxSpecialCharacters
    $password = [System.Web.Security.Membership]::GeneratePassword($length,$special)
   
    $password
}

# Searches the set base OU for accounts that have passed their expiry date
$Users=Search-ADAccount -AccountExpired -UsersOnly -SearchBase $BaseSearchOU

# Goes through each account and check to see if it is disabled or not
ForEach ($user in $Users) 
    {
        $Status=Get-ADUser $user -Properties *
        $SAM=$user.SamAccountName
            
# If the account is not currently disabled this statement will disable it        
            If ($Status.Enabled -eq $True)
                {
                Disable-ADAccount -Identity $user
                }
           
# A check to confirm that the account was successfully disabled and saves the result to a variable 
        $disabled = If ($Status.Enabled -eq $False)
                    {       
                    continue  
                    }
                
                    Else
                   {
                    Write-Host "There was an issue with disabling $SAM"
                   }                   
                   
# If there was an issue with disabling the account an error will be displayed in the terminal            
            If($disbaled){
               $disabled
                }
            
# If no error continue with the password reset and OU move            
                Else{

                    # Uses the New-Password function to generate a secure password and store in a variable
                    $newpass = New-Password
                   
# Rest the accounts password with one created by the New-Password function
                    Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newpass -Force)

# Moves the account to the selected Destination OU        
                    Move-ADObject -Identity $user -TargetPath $DestinationOU
     
# Outputs the results to the PowerShell terminal        
                    Write-Host "$SAM was moved to $DestinationOU is the new password of $newpass"                   
                }
    }
