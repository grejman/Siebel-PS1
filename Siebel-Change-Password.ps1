## Pre-Requisites
## **************
## Install Active Directory 
##  1) Execute: Execute: Import-Module ActiveDirectory
##     a) If not found install Remote Server Administration Tools
##        https://www.microsoft.com/en-us/download/confirmation.aspx?id=45520
## Install SBL.Module.psm1
##  1) Execute: Import-Module -FullyQualifiedName "Siebel-IP19-Module.psm1"

## Instructions
## ************
## 0) Generate Passwords.
## 1) Settings.
## 2) Backup Gateway.
## 3) Change Gateway Passwords.
## 4) Change Gateway SybSys Passwords.
## 5) Stop Siebel Servers & AI.
## 6.1) Change Siebel DB Password (SADMIN\SIEBEL\ADSIUSER)
## 6.2) Change Domain Passwords (SADMIN)
## 7) Remove Siebel Services
## 8) Create Siebel Servers, with new credentials
## 9) Set AI Auth Token, with new credentials
## 10) Start Siebel Servers & AI

## 0) Generate Passwords
## https://www.roboform.com/password-generator  
## Setting: Length: 10, Max Num: 2, Special Chars: -_.+!*()

## 1) Settings
## -----------
remove-module Siebel-IP19-Module
Import-Module -FullyQualifiedName "Siebel-IP19-Module.psm1"

## Old Password
$pSADMIN            = "xx"    ## Old SADMIN password   
$pSIEBEL            = "yy"    ## Old SIEBEL password

## New Password (Add new password as required)
$pnSADMIN           = "!6q8PmQz79"    ## New SADMIN password
$pnSIEBEL           = "K3bfSNv4_E"    ## New SIEBEL password
$pnADSIUSER         = "zorDGFbN-6"    ## New ADSIUSER password
$pnGUESTCST         = "5Z+8k6dzAb"    ## New GUESTCST password

## Set Env (We assume that the sadmin user is also a domain user)
Set-SBLEnv -Env PRD

$c =  New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "domain\sadmin", (ConvertTo-SecureString -String $pSADMIN  -AsPlainText -Force) ## Old Service User
$sc = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "domain\sadmin", (ConvertTo-SecureString -String $pnSADMIN -AsPlainText -Force) ## New Service User

## Check SADMIN user on domain
Get-ADUser -identity "sadmin" -Properties "SamAccountName", "Enabled", "DisplayName", "msDS-UserPasswordExpiryTimeComputed", "UserPrincipalName" -Server "{my.domain.controler}"      | Select-Object -Property "SamAccountName","Enabled","Displayname",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}

## 2) Backup Gateway
## -----------------
Backup-SBLGtwy -Credential $c -Verbose

## 3) Change Gateway Passwords (Change the SADMIN\SIEBEL password on the gateway)
## ------------------------------------------------------------------------------
Set-SBLGtwyEnvParam -Credential $c -Name "TableOwnPass" -Value $pnSIEBEL -Password $pSADMIN -Verbose  ## SIEBEL User
Set-SBLGtwyEnvParam -Credential $c -Name "password"     -Value $pnSADMIN -Password $pSADMIN -Verbose  ## SADMIN User

## 4) Change Gateway SybSys Passwords (Add SubSys as required based on your enviroment)
## ------------------------------------------------------------------------------------
  ## LDAPEASSecAdpt (ADSIUSER)
Set-SBLGtwySubSysParam  -Credential $c -SybSystems "LDAPEASSecAdpt"   -Name "SharedDBPassword"     -Value $pnADSIUSER      -Password $pSADMIN -Verbose
Set-SBLGtwySubSysParam  -Credential $c -SybSystems "LDAPEASSecAdpt"   -Name "ApplicationPassword"  -Value $pnSADMIN        -Password $pSADMIN -Verbose

## 5) Stop Siebel Servers & AI Services
## ------------------------------------
Stop-SBLServer   -Credential $c -Verbose
Get-SBLServer    -Credential $c -Verbose

Stop-SBLAIServer -Credential $sc -Verbose
Get-SBLAIServer  -Credential $sc -Verbose

## 6.1) Change Siebel DB Password (SADMIN\SIEBEL\ADSIUSER) - Must be 32bit mode
## ----------------------------------------------------------------------------
$SBLDBConn1 = new-object system.data.odbc.odbcconnection
$SBLDBConn1.connectionstring = "DSN=SBLPRD;PWD={0};UID=siebel" -f $pSIEBEL  ## Create a ODBC driver named SBLPRD
$SBLDBConn1.open()

$DBCmd = new-object System.Data.Odbc.OdbcCommand(("ALTER USER ""SADMIN""    IDENTIFIED BY ""{0}""" -f $pnSADMIN),$SBLDBConn1)
$DBCmd.ExecuteNonQuery()

$DBCmd = new-object System.Data.Odbc.OdbcCommand(("ALTER USER ""SIEBEL""    IDENTIFIED BY ""{0}""" -f $pnSIEBEL),$SBLDBConn1)
$DBCmd.ExecuteNonQuery()

$DBCmd = new-object System.Data.Odbc.OdbcCommand(("ALTER USER ""ADSIUSER""  IDENTIFIED BY ""{0}""" -f $pnADSIUSER),$SBLDBConn1)
$DBCmd.ExecuteNonQuery()

$DBCmd = new-object System.Data.Odbc.OdbcCommand(("ALTER USER ""ADSIUSER""  IDENTIFIED BY ""{0}""" -f $pnGUESTCST),$SBLDBConn1)
$DBCmd.ExecuteNonQuery()

#$SBLDBConn1.close()

## 6.2) Change Domain Passwords (SADMIN)
## -------------------------------------
Set-ADAccountPassword -identity "sadmin" -Credential vc\sadmin -OldPassword (ConvertTo-SecureString -AsPlainText $pSADMIN -Force) -NewPassword (ConvertTo-SecureString -AsPlainText $pnSADMIN -Force) -Server "my.domain.controler"      

## 7) Remove Siebel Services
## -------------------------
Remove-SBLService -Credential $sc -Verbose

## 8) Create Siebel Servers, with new credentials (based on the Servers set on the enviroment varables found in the module)
## ------------------------------------------------------------------------------------------------------------------------
Add-SBLService -Credential $sc -NewPassword $pnSADMIN -ServiceUserPassword $pnSADMIN -Verbose -Servers $SBLAllServers

## 9) Set AI Auth Token, with new credentials
## ----------------------------------------------
Set-SBLAIAuthToken -Credential $sc -NewPassword $pnSADMIN -Verbose

## 10) Start Siebel Servers
## ------------------------
Start-SBLServer -Credential $sc -Verbose
Get-SBLServer   -Credential $sc -Verbose

Start-SBLAIServer -Credential $sc -Verbose
Get-SBLAIServer   -Credential $sc -Verbose
