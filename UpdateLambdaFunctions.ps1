$Version = "2.0.5"
$description = "SendIAMAccountNotifications Version {0}" -f $Version

Set-Location -Path "./MainAccount_SendIAMAccountNotifications"
Set-AWSCredential -ProfileName default
publish-AWSPowerShellLambda -ScriptPath ./SendIAMAccountNotifications.ps1 -Name SendIAMAccountNotifications `
    -IAMRoleArn arn:aws:iam::268928949034:role/service-role/IAM_PasswordExpiryNotification-role-0w2s3e6j
Update-LMFunctionConfiguration -FunctionName SendIAMAccountNotifications -Description $description

Set-Location -Path "../CrossAccount_SendIAMAccountNotifications"
Set-AWSCredential -ProfileName devops
publish-AWSPowerShellLambda -ScriptPath ./SendIAMAccountNotifications.ps1 -Name SendIAMAccountNotifications `
    -IAMRoleArn arn:aws:iam::099010331511:role/IAM_AccountNotification-role-0w4sf65i9
Update-LMFunctionConfiguration -FunctionName SendIAMAccountNotifications -Description $description

Set-AWSCredential -ProfileName jde
publish-AWSPowerShellLambda -ScriptPath ./SendIAMAccountNotifications.ps1 -Name SendIAMAccountNotifications `
    -IAMRoleArn arn:aws:iam::940388263884:role/IAM_SendAccountNotificationsRole      
Update-LMFunctionConfiguration -FunctionName SendIAMAccountNotifications -Description $description

Set-AWSCredential -ProfileName pip-dev
publish-AWSPowerShellLambda -ScriptPath ./SendIAMAccountNotifications.ps1 -Name SendIAMAccountNotifications `
    -IAMRoleArn arn:aws:iam::026297738052:role/SendIAMAccountNotification-role  
Update-LMFunctionConfiguration -FunctionName SendIAMAccountNotifications -Description $description

Set-AWSCredential -ProfileName pip-prod
publish-AWSPowerShellLambda -ScriptPath ./SendIAMAccountNotifications.ps1 -Name SendIAMAccountNotifications `
    -IAMRoleArn arn:aws:iam::593301682982:role/SendIAMAccountNotifications-role 
Update-LMFunctionConfiguration -FunctionName SendIAMAccountNotifications -Description $description

Set-AWSCredential -ProfileName pip-shared
publish-AWSPowerShellLambda -ScriptPath ./SendIAMAccountNotifications.ps1 -Name SendIAMAccountNotifications `
    -IAMRoleArn arn:aws:iam::569287770824:role/SendIAMAccountNotifications-role  
Update-LMFunctionConfiguration -FunctionName SendIAMAccountNotifications -Description $description
