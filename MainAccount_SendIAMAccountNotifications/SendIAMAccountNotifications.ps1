# PowerShell script file to be executed as a AWS Lambda function. 
# 
# When executing in Lambda the following variables will be predefined.
#   $LambdaInput - A PSObject that contains the Lambda function input data.
#   $LambdaContext - An Amazon.Lambda.Core.ILambdaContext object that contains information about the currently running Lambda environment.
#
# The last item in the PowerShell pipeline will be returned as the result of the Lambda function.
#
# To include PowerShell modules with your Lambda function, like the AWS.Tools.S3 module, add a "#Requires" statement
# indicating the module and version. If using an AWS.Tools.* module the AWS.Tools.Common module is also required.

#Requires -Modules @{ModuleName='AWS.Tools.Common';ModuleVersion='4.1.105'}
#Requires -Modules @{ModuleName='AWS.Tools.IdentityManagement';ModuleVersion='4.1.105'}
#Requires -Modules @{ModuleName='AWS.Tools.EC2';ModuleVersion='4.1.105'}
#Requires -Modules @{ModuleName='AWS.Tools.S3';ModuleVersion='4.1.105'}
#Requires -Modules @{ModuleName='AWS.Tools.SecretsManager'; ModuleVersion='4.1.105'}

# Uncomment to send the input event to CloudWatch Logs
# Write-Host (ConvertTo-Json -InputObject $LambdaInput -Compress -Depth 5)

$ErrorActionPreference = Stop

# The credential log can be as much as 12 hours behind any changes.
Write-Host "Getting IAM Credential Log"
Request-IAMCredentialReport -Force |Out-Null

Start-Sleep 5
Write-Host
Write-Host "Getting Account ID"
$AccountId = (Get-EC2SecurityGroup -GroupName 'default')[0].OwnerId

$txt_report = Get-IAMCredentialReport -AsTextArray
$iamUsers = ConvertFrom-Csv $txt_report

$currentDate = Get-Date

# Retrieve the SES credentials from Secrets Manager.
# note to users:
# This script uses AWS SES to send Emails. Then Access Keys stored in Secrets Manager are for your SES user
# that was created by SES. Modify the Secret ID to fit your setup.
Write-Host "Retrieving SES_SMTP_User access Keys from Secrets Manager."
$SES_Creds = (Get-SECSecretValue -SecretId 'SES_SMTP_User').SecretString | ConvertFrom-Json

# Configure the email parameters.
$smtpUser = $SES_Creds.SmtpUsername
$smtpPass = ConvertTo-SecureString -AsPlainText -String $SES_Creds.SmtpPassword -Force 
$smtpCreds = New-Object System.Management.Automation.PSCredential($smtpUser, $smtpPass)
$SMTPServer = "email-smtp.us-east-1.amazonaws.com"
$From = "AWSIAM@balfourbeattyus.com"
$Subject = "AWS IAM Password & Access Key Notification"
$strbody = "Please review your IAM credentials for IAM account {0} in AWS Account {1}. `n`r `n`r{2}{3}"

# Body messages.
$NewKeyMsg = "New AWS Access Keys have been created for your account.`n`r" + `
             "You can retrieve these keys using the My AWS Secrets application.`n`r" + `
             "Your previous keys will be deactivated in 10 days, then deleted in 20 days."
$oldKeyWarning = "AWS Access Keys with Key ID {0} will be deactivated in {1} days.`n`r" + `
                 "You have not accessed your new keys yet. `n`r" + `
                 "Please retrieve your new keys with the My AWS Secrets application and update your applications/profile."
$DeactivateKeyMsg = "AWS Access Keys with Key ID {0} was inactivated!"
$DeletedKeyMsg = "AWS Access Keys with Key ID {0} was deleted."
$KeyFooter = "`n`r`n`rYou can install the MY AWS Secrets application from the Software Center on your laptop. `n`r`n`r" + `
             "If you have any difficulty retrieving your Access Keys please contact your AWS Administrator or the Service Desk."
$ses_User_Msg  = "The SES User Account {0} Access Keys are {1} days old. Please create a new SES User and update the secret"


#Uncomment below to test outgoing email. Then update Lambda function.
#Comment out after testing then update Lambda function.
<#
Write-Host "Testing Email"
$to = 'cwilliams@balfourbeattyus.com'
$body = 'Testing email'
Send-MailMessage -SmtpServer $SMTPServer -To $to -From $From -Subject $Subject -Body $body -UseSsl -Credential $smtpCreds -Port 587
exit
#>

function RotateKeys() {
    Param(
        [string]$IamUserName,
        [string]$AccessKeyID,
        [string]$SecretName,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('New','Deactivate','Delete')]
        [string]$Action
    )
    #
    # The Secret ARN is required if you are retrieveing Secrets cross account. 
    # modify this to match your account that holds Secrets.
    $SecretNameURN = "arn:aws:secretsmanager:us-east-1:268928949034:secret:{0}" -f $SecretName
    switch ($Action) {
        'New' {
            try {
                $newAccessKey = New-IAMAccessKey -UserName $IamUserName
            } catch {
                throw $_
            }
            $AccessKeys.AccessKeyID = $newAccessKey.AccessKeyId
            $AccessKeys.SecretAccessKey = $newAccessKey.SecretAccessKey
            $AccessKeysJSON = $newAccessKey | Select-Object AccessKeyID, SecretAccessKey | ConvertTo-Json -Compress
            try {
                Update-SECSecret -SecretId $SecretNameURN -SecretString $AccessKeysJSON
            } catch {
                throw $_
            }
            $msg = "Created New Access Keys with AccessKeyID {0} for {1} and stored in secret {2}." -f $newAccessKey.AccessKeyId, $IamUserName, $SecretName
            Write-Host $msg
        }
        'Deactivate' {
            try {
                Update-IAMAccessKey -UserName $IamUserName -AccessKeyId $AccessKeyID -Status Inactive
            } catch {
                throw $_
            }
            $msg = "Inactivated Access Keys with AccessKeyID {0} for user {1}" -f $AccessKeyID, $IamUserName
            Write-Host $msg
        }
        'Delete' {
            try {
                Remove-IAMAccessKey -UserName $IamUserName -AccessKeyId $AccessKeyID -Confirm:$false -Force
            } catch {
                throw $_
            }
            $msg = "Deleted Access Keys with AccessKeyID {0} for user {1}" -f $AccessKeyID, $IamUserName
        }
    }

}

$ExcludeUsers = @("root")

foreach ($iamUser in $iamUsers) {
    $pwMsg = $null
    $KeyMsg = $null
    #$key1Msg = $null
    #$key2Msg = $null
    $secretName = $null
    $iamUserInfo = $iamUser.arn.Split(":")
    if ($iamUserInfo[5] -eq 'root') {
        $iamUserEmail = $iamUserInfo[5]
    } else {
        try {
            $iamAccount = Get-IAMUser $iamUser.User
            Write-Host "Beginning processing for IAM user:$($iamUser.User)"
        } catch {
            #This most often occures when an account is deleted and the security report is not updated as of yet.
            #Handle the error and contnue on to the next user.
            Continue
        }
        $tags = $iamAccount.Tags

        If ($tags.Count -gt 0) {
            If ($tags.Key.IndexOf("SecretName") -gt -1) {
                $secretName = $tags[$tags.Key.indexOf("SecretName")].Value
            }
        }
              
        if ($iamUser.user.contains('@')) {
            $iamUserEmail = $IamUser.user
        } else {
            $iamUserEmail = $tags[$tags.Key.IndexOf("Notify")].Value
        }
    }
    if (-not $iamUserEmail) { continue }

    if ($iamUserEmail -notin $ExcludeUsers) {
        $sendEmail = $false
        #$iamUserEmail = $iamUserInfo[5].Split("/")[1]
        #
        # Does the user have a password
        #
        if ([System.Convert]::ToBoolean($iamUser.password_enabled)) {
            #
            # Get The Password Expiration date
            #
            $passwordExpireDate = [datetime]::Parse($iamUser.password_next_rotation)
            #
            # If the password is expired send a notice informing the user,
            # else if the password is less than 16 days from expiration send a notice informint the user.
            #
            if ($currentDate -gt $passwordExpireDate) {
                $sendEmail = $true
                $pwMsg = "Your Password has expired!`n`r"
            } else {
                $daysLeft = ($passwordExpireDate - $currentDate).Days
                if ($daysLeft -lt 16) {
                    $sendEmail = $true
                    $pwMsg = "Your password will expire in {0} days!`n`r" -f $daysLeft
                }
            }
            #Write-Host "$iamUserEmail : $Msg"
        }
        #
        # The ses-smtp-User is a special IAM acccount for use to authenticate to AWS Simple Email Service (SES).
        # These keys cannot be rotated in the normal fashion. To do so will break SES.
        # To rotate these keys you must create a new SES user in the SES dashboard.
        # The new users keys must be stored in th3 secret used above.
        # The name of the account is 'ses-smtp-user.' appended with a series of numbers devided by a dash.
        # Here we check just that user user begins with 'ses-smtp-user' and continue the loop.
        If ($iamUser.User.StartsWith("ses-smtp-user")) {
            $AccessKeys = Get-IAMAccessKey -UserName $iamUser.User
            $AccessKey = $AccessKeys[0]
            [datetime]$ExpirationDate = $AccessKey.CreateDate.AddDays(80)
            $keyAge = ($currentDate - $ExpirationDate).Days
            if ($AccessKey.Status -eq "Active" -and $currentDate -gt $ExpirationDate) {
                $KeyMsg = $ses_User_Msg -f $iamUser.User, $keyAge
                $body = $strbody -f $iamUser.User, $AccountId, $pwMsg, $keyMsg            
                #comment for testing
                Send-MailMessage -SmtpServer $SMTPServer -To $iamUserEmail -From $From -Subject $Subject -Body $body `
                    -UseSsl -Credential $smtpCreds -Port 587    
                #comment out for production
                #write-Host ("Will Send to $iamUserEmail`n`r`n`r" + $body)

                Continue
            }
        }
        #
        # Check the access keys. No user can have more than 2 access keys, one currently active and one inactive.
        # New keys are generated at 90 days and the Secret is updated. 
        # User is informed that they have a new keys in their secret.
        # The old keys are inactivated at 100 days, then deleted at 110 days.
        Write-Host "Retrieving Access Keys for IAM User $($iamUser.User)"
        $AccessKeys = Get-IAMAccessKey -UserName $iamUser.User
        foreach ($AccessKey in $AccessKeys) {
            [datetime]$ExpirationDate = $AccessKey.CreateDate.AddDays(80)
            [datetime]$deactivateDate = $AccessKey.CreateDate.AddDays(90)
            [datetime]$deleteDate = $AccessKey.CreateDate.AddDays(100)

            if ($accessKey.Status -eq "Inactive" -and ($CurrentDate -ge $deleteDate)) {
                rotateKeys -IamUserName $iamUser.User -AccessKeyID $AccessKey.AccessKeyId -Action:Delete
                $sendEmail = $true
                if ($keyMsg.Length -gt 0) {
                    $keyMsg += $DeletedKeyMsg -f $AccessKey.AccessKeyId
                } else {
                    $keyMsg = $DeletedKeyMsg -f $AccessKey.AccessKeyId
                }

            } elseif ($AccessKey.Status -eq "Active" -and ($currentDate -ge $deactivateDate)) {
                RotateKeys -IamUserName $iamUser.User -AccessKeyID $AccessKey.AccessKeyId -Action:Deactivate
                $sendEMail = $true
                $keyMsg = $DeactivateKeyMsg -f $AccessKey.AccessKeyId            

            } elseif ($AccessKey.Status -eq "Active" -and ($currentDate -gt $ExpirationDate -and $currentDate -lt $deactivateDate)) {
                $secret = Get-SECSecret -SecretId $secretName
                if ($secret.LastChangedDate -gt $ExpirationDate) {
                    # A new secret was created with a key newer than this key
                    if ($Secret.LastChangedDate -gt $secret.LastAccessedDate) {
                        # The secret has not been accessed. Bitch at the user!
                        $sendEmail = $true
                        $daysLeft = ($deactivateDate - $currentDate).Days
                        $keyMsg = $oldKeyWarning -f $AccessKey.AccessKeyId, $daysLeft
                        $keyMsg += $KeyFooter
                    }
                } else {
                    # The key has expired and the secret has not been updated.                    
                    # Rotate the keys!
                    RotateKeys -IamUserName $iamUser.User -AccessKeyID $AccessKey.AccessKeyId -SecretName $secretName -Action:New
                    $sendEmail = $true
                    if ($keyMsg.Length -gt 0) {
                        $keyMsg += $NewKeyMsg
                    } else {
                        $keyMsg = $NewKeyMsg
                    }
                    $keyMsg += $KeyFooter    
                }
            }
        }
 
        if ($sendEmail) {
            #$body = $strbody -f $iamUser.User, $AccountId, $pwMsg, $key1Msg, $key2Msg            
            $body = $strbody -f $iamUser.User, $AccountId, $pwMsg, $keyMsg            
            #comment for testing
            Write-Host "Sending Message!"
            Send-MailMessage -SmtpServer $SMTPServer -To $iamUserEmail -From $From -Subject $Subject -Body $body -UseSsl -Credential $smtpCreds -Port 587    
            #comment out for production
            #write-Host ("Will Send to $iamUserEmail`n`r`n`r" + $body)

        }
    }
}
