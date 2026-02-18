# AWS IAM Password Notification and and Access Key Management LAMBDA scripts

The powershell scripts in this repository are used in AWS LAMBDA function to perform the following tasks.

1. Inform IAM users that their password are about to expire or already have expired.
2. Rotate IAM Access Keys and store the newly created keys in AWS Secrets Manager.

These scripts were designed to operate withing my organization but can be easily edited to function in your AWS organization.  

There are 2 scripts:

1. [MainAccount_SendIAMNotifications](https://github.com/Clifra-Jones/sendIAMAccountNotifications/blob/master/MainAccount_SendIAMAccountNotifications/SendIAMAccountNotifications.ps1) is a script for use in your main AWS Account. This is the account that holds your secrets.
It is AWS best practice to keep all your secrets in one main account, but this is entirely up to you.
2. [CrossAccount_SendIAMNotifications](https://github.com/Clifra-Jones/sendIAMAccountNotifications/blob/master/CrossAccount_SendIAMAccountNotifications/SendIAMAccountNotifications.ps1) is a script designed to retrieve secrets from your main account.

These scripts utilize role assumptions so there are a few places where you will need to replace the role ARN with the one for your organization.

There are also permission json files you can use for granting permission. Replace any values inside {} with appropriate ones from your organization.

It is assumed you have a working knowledge of the following:  
PowerShell  
AWS Tools for PowerShell  
AWS IAM  
AWS Lambda  
AWS Secrets Manager  
AWS Key Management System  
AWS Simple Mail Service  

## Passwords
Password expiration dates are retrieved from the IAM Credential Report. This report is generated on a scheduled basis withing AWS. The expiration dates are determined by your password policy in your AWS Accounts.  

Notifications are sent starting 15 days prior to expiration.

## Access Keys
You will store IAM Access Keys in Secrets Manager in a Key Value pair as: AccessKeyID and SecretAccessKey.

The script will check the age of the keys in IAM and perform the following functions when the keys are at the designated age.

80 Days: Generate a new set of keys and update the secret associated with the user.  
90 Days: Deactivate the keys.  
111 Days: Delete the keys.  

## Secrets Manager, KMS and IAM
For every user that is granted access keys a Secret must be created in Secrets Manager.

### Secrets Manager
The IAM User should have a Secret in Secrets Manager setup to hold their access Keys.  

**SecretName**
This should be something identifiable such as the IAM Users's username. If this is for a cross account append with an account identifier, i.e. _devops.

**Encryption Key**  
If this secret is for a IAM User in the same account then you can use the default 'aws/secretsmanager' encryption key. If this is for a cross account IAM User you must use a custom KMS key. See the KMS section below.

**Secret Value**  
The secret value is a Key/Value pair in the following format.  
AccessKeyId     : IAM Access Key ID
SecretAccessKey : IAM Secret Access Key

The Key names are case sensitive so make sure the case is correct when creating the secret value.

**Permissions**  
Grant the IAM User the 'secretsmanager:GetSecretValue' permission.  
[User Secret Permission Example](./policies/SecretPermission.json)

### Key Management Service (KMS)
In order to decrypt secrets from another account you need use a custom KMS key to encrypt your secrets.

**Alias**  
Create an understandable alias to identify this key.

**Key Rotation**  
Set key rotation to automatic.

**Key policy**  
Allow account from your other AWS Account to use this key.  
[KMS Key Policy](./policies/KMS_Key_Policy.json)

### IAM Users, Groups and Roles

#### IAM Users
Each user with a managed IAM Access Key must have a tag named 'SecretName' whose value is the secret name of their associated secret.

#### IAM Groups
In each of your accounts create a group named 'SecretManagerUsers', any IAM user who will need to retrieve secrets must be a member of this group.

**Permissions**  
This group should have the following permissions applied.
(I use inline permissions to prevent these permissions from inadvertently being applied to other users/groups)

[Use Secrets Manager KMS Key](./policies/KMS_KEY_Access.json)  
This policy only applies for cross account access. Use this policy in accounts that need to access secrets stored in another account.

[IAM User Read Self](./policies/IAM_User_Read_Self.json)  
This policy allows the use to read their own IAM Account.  
(Note: the text '${aws:username}' should not be changed.)  

[Secrets Manager Get Secret Value](./policies/Secrets_Manager_get_Secret_Value.json)  
This allows users to retrieve the secret value from secrets they have access to.

#### Roles
The following roles are used by this process.

**Manage_Secrets_Role**  
This role exists in your primary account that holds your secrets. This role will be assumed by the Lambda functions in your other accounts in order to manage secrets.

*Permissions*  
[Manage Secrets Policy](./policies/ManageSecrets_policy.json)  

*Trust Relationships*  
[Manage Secrets Trust Relationship](./policies/ManagedSecrets_Trust_Relationships.json)  
Add all accounts that will need to assume this role.

**Lambda Execution Role**  
The role that is assigned to your Lambda function should have the following permissions.

*AmazonEC2ReadOnlyAccess*  
This is required to retrieve the Account # the function is running under.

*IAMReadOnlyAccess*  
This is required to read the IAM Accounts being managed.

*AWSLambdaBasicExecutionRole*  
This grants all necessary permission to execute the Lambda function.

Add the following inline policies.  
[Assume Role Managed Secrets Role](./policies/Assume_Role_Manage_Secrets_Role.json)  

[KMS Key Access](./policies/KMS_KEY_Access.json)  

## Lambda
You cannot edit PowerShell scripts in the Lambda console to create your Lambda function. Use the Publish-AWSPowerShellLambda Powershell command.  
If you have a lot of roles in your IAM Roles it is probably best to pre-create your Lambda execution role and supply the ARN with this command.

```powershell
Publish-AWSPowerShellLambda -Name [Function Name] -Region [AWS Region] -ScriptPath [Path to script file] -IAMRoleArn [ARN of Lambda role]
```

**Triggers**  
Create an Event Bridge trigger to execute your function. Once per day is sufficient.

**Permissions**  
Your Lambda execution role should be already assigned when you published your function.

**Asynchronous Invocation**  
Make sure to set "Retry attempts" to 0. This will prevent the function from running again in the case of an error. (The default is 3)

## Simple Mail Service (SES)
Setup SES and verify your domains.  
If you are sending a low volume of email and you only sending to your owned domains then you can leave SES in 'sandbox' mode.  
From the Account Dashboard under Authentication create SMTP Credentials. Save these credentials and create a secret in Secrets Manager to hold these credentials.  
Create the Secret Value as a Key/Value pair as:  
SmtpUsername: SES User access Key  
SmtpPassword: SES User Secrets Key  

In the scripts is the section where we retrieve the SES credentials from Secrets Manager, change the Secret ID to match the secret name your created.

In the Main Account script there is a section specifically used for this user.  
You cannot generate new keys in IAM for this user. THEY WILL NOT WORK WITH SES. Therefor we exempt this user from any Access Key management. The default name for the SES User starts with 'ses-smtp-user'. If you change this name then modify the code where it checks for this name.

## Cloud Watch
Create a Cloud Watch Alarm for Lambda function error with the threshold of: Errors > 0 for 1 data points within 1 days.
Subscribe an SNS topic to send you emails if the alarm occurs.
