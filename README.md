# Siebel-PS1

**Siebel-IP19-Module.psm1**: Siebel PowerShell Library of commands for managing Siebel environment.

**Siebel-Change-Password.ps1**: Change password commands to change the Siebel\sadmin password on the domain, gateway, services and DB.

## Steps
1) Download the Module

2) Edit the Mobule and set the Default & Env section, the section contains the host and server names for the enviroment as well the location components are installed.

`
  $SBLAppIntPath        = "d:\Oracle\Siebel\ai"
  $SBLGtwyPath          = "d:\Oracle\Siebel\gw\gtwysrvr"  
  $SBLSrvrPath          = "d:\Oracle\Siebel\ses\SiebSrvr" 
  $SBLTempPath          = "c:\Temp\"  
  $SBLClientPath        = "C:\Oracle\Siebel\16.0.0.0.0\Client"  
  ...
`

`
  ...
  "QA" {
    $global:SBLHost       = "siebel.yy.com"
    $global:SBLGtwyServer = "a123dwawi"
    $global:SBLAIServers  = "a123dwawi"
    $global:SBLServers    = "a123dwawi"
    $global:SBLAllServers = "a123dwawi"
    $global:SBLGtwyPath   = "d:\Oracle\Siebel\gw\gtwysrvr"
    Break
  }
  "P-Prod" {
  ...
`
  
3) Install the module:
  
  **Import-Module** -FullyQualifiedName "Siebel-IP19-Module.psm1"
  
4) To Remove Module
  
  **Remove-Module** Siebel-IP19-Module
 
5) Set the environment call Set-SBLEnv and pass in DEV\QA.  Note the default is Dev

  **Set-SBLEnv** -Env QA

- Note: The enviroments settings, hosts, server names are stored in the Mobile.  Edit the file and adjust as required.

## Functions

* **Testing**

	Invoke-SBLWFP

* **Siebel Services**

	Stop-SBLServer
	Start-SBLServer
	Get-SBLServer
	Remove-SBLService
	Add-SBLService

* **Backup Gateway**

	Backup-SBLGtwy
	Stop-SBLGtwyServer
	Start-SBLGtwyServer
	Get-SBLGtwyServer

* **Siebel Server Components**

	Set-SBLSrvrComp
	Get-SBLSrvrComp

* **Siebel Gateway Param**

	Set-SBLGtwyEnvParam
	Set-SBLGtwySubSysParam

* **Siebel Gateway Log Level**

	Set-SBLGtwyEvtLogLevel
	Get-SBLGtwyEvtLogLevel

* **Siebel Logs**

	Get-SBLSrvrLogs
	Remove-SBLSrvrLogs
	 
   
**Note**: For help on the input parameters use the PowerShell command  "Get-Help {MethodName}"

## Example

	Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
	Import-Module -FullyQualifiedName "Siebel-IP19-Module.psm1"
	##remove-module Siebel-IP19-Module

	## Set Credential
	$SiebPass = "SADMIN1"  ## Siebel SADMIN Password
	$c  = Get-Credential vodacom\xxxx
	$cs = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "SADMIN", (ConvertTo-SecureString -String $SiebPass -AsPlainText -Force) 

	## Set Environment REP, DEV, QA (Default: Dev)
	Set-SBLEnv -Env QA

	## Clear the Cache
	Remove-SBLSrvrLogs -Credential $c -Types Temp -Verbose  -Filter "Cache*"

	Remove-SBLSrvrLogs -Credential $c -Types Log -Filter "EAI*" -Verbose

	## Get Server Log
	Get-SBLSrvrLogs -Credential $c -Types Log -Filter "EAI*" -Pattern "{File Content}" -Verbose

	## Get\Remove FDR
	Get-SBLSrvrLogs    -Credential $c -Types FDR,Crash -Verbose

	Remove-SBLSrvrLogs -Credential $c -Types FDR,Crash -Verbose

	## Set Log Level of Component
	Set-SBLGtwyEvtLogLevel -Credential $c -Value 1 -CompAliasName eCommunicationsObjMgr_enu -Password SADMIN

	## Start\Stop Get Siebel Server
	Stop-SBLServer -Credential $c -Verbose
	Get-SBLServer -Credential $c -Verbose
	Start-SBLServer -Credential $c -Verbose

	## Start\Stop Get Siebel Server
	Stop-SBLGtwServer -Credential $c -Verbose
	Get-SBLGtwyServer -Credential $c -Verbosey
	Start-SBLGtwyServer -Credential $c -Verbose

	## Call WFP 
	##[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12"
	Invoke-SBLWFP -WFPName "VSFA Function - OM Offer Add Instance" -Parameters "OfferId=2-AUO9AYV&AssetIntegrationId=2-18104762448&InputObjectType=SIS OM Quote?workspace=main" -Credential $cs -Verbose
