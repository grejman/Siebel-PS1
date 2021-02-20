## ************************************** ##
## Siebel IP29+ Powershell Module 2020/01 ##
## ************************************** ##
## Import-Module -FullyQualifiedName "Siebel-IP19-Module.psm1"
## remove-module Siebel-IP19-Module.psm1

## Defaults ##
$SBLAppIntPath         = "d:\Oracle\Siebel\ai"
$SBLGtwyPath           = "d:\Oracle\Siebel\gw\gtwysrvr"
$SBLSrvrPath           = "d:\Oracle\Siebel\ses\SiebSrvr"
$SBLTempPath           = "c:\Temp\"
$SBLGtwyServer         = "xx.yy.com"
[string[]] $SBLServers = "xx.yy.com"
$SBLClientPath         = "C:\Oracle\Siebel\16.0.0.0.0\Client"

## Turn off Certificate check for Siebel selfsigned Cert
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()


## Set Env
function Set-SBLEnv {
    param ([ValidateSet('Rep','Dev','QA','PProd','Prd-DP','Prd-CM','Prd')][string[]]$Env = ("QA"),
           [switch]$Verbose)

    switch ($Env) {
        "Rep" {
            $global:SBLHost       = "siebel.yy.com"
            $global:SBLGtwyServer = "mm"
            $global:SBLAIServers  = "mm"
            $global:SBLServers    = "mm"
            $global:SBLAllServers = "mm"
            $global:SBLGtwyPath   = "d:\Oracle\Siebel\gw\gtwysrvr"
            Break
        }
        "Dev" {
            $global:SBLHost       = "siebel.yy.com"
            $global:SBLGtwyServer = "mm"
            $global:SBLAIServers  = "mm"
            $global:SBLServers    = "mm"
            $global:SBLAllServers = "mm"
            $global:SBLGtwyPath   = "d:\Oracle\Siebel\gw\gtwysrvr"
            Break
        }
        "QA" {
            $global:SBLHost       = "siebel.yy.com"
            $global:SBLGtwyServer = "mm"
            $global:SBLAIServers  = "mm"
            $global:SBLServers    = "mm"
            $global:SBLAllServers = "mm"
            $global:SBLGtwyPath   = "d:\Oracle\Siebel\gw\gtwysrvr"
            Break
        }
        "PProd" {
            $global:SBLHost       = "siebel.yy.com"
            $global:SBLGtwyServer = "mm"
            $global:SBLAIServers  = "mm"
            $global:SBLServers    = "mm"
            $global:SBLAllServers = "mm"
            $global:SBLGtwyPath   = "d:\Oracle\Siebel\gw\gtwysrvr"
            Break
        }
        "Prd" {
            $global:SBLHost       = "siebel.yy.com"
            $global:SBLGtwyServer = "mm"
            $global:SBLAIServers  = "mm"
            $global:SBLServers    = "mm"
            $global:SBLAllServers = "mm"
            $global:SBLGtwyPath   = "d:\Oracle\Siebel\gs\gtwysrvr"
            Break
        }       
        "Prd-DP" {
            $global:SBLHost       = "siebel.yy.com"
            $global:SBLGtwyServer = "mm"
            $global:SBLAIServers  = "mm"
            $global:SBLServers    = "mm"
            $global:SBLAllServers = "mm"
            $global:SBLGtwyPath   = "d:\Oracle\Siebel\gs\gtwysrvr"
            Break
        }
        "Prd-CM" {
            $global:SBLHost       = "siebel.yy.com"
            $global:SBLGtwyServer = "mm"
            $global:SBLAIServers  = "mm"
            $global:SBLServers    = "mm"
            $global:SBLAllServers = "mm"
            $global:SBLGtwyPath   = "d:\Oracle\Siebel\gs\gtwysrvr"
            Break
        }
    }

    Write-Verbose -Message ("Siebel Host          '$($global:SBLHost)'")       -Verbose:$Verbose
    Write-Verbose -Message ("Siebel Gtwy Path     '$($global:SBLGtwyPath)'")   -Verbose:$Verbose
    Write-Verbose -Message ("Siebel Gtwy Server   '$($global:SBLGtwyServer)'") -Verbose:$Verbose
    Write-Verbose -Message ("Siebel AI Servers    '$($global:SBLAIServers)'")  -Verbose:$Verbose
    Write-Verbose -Message ("Siebel Servers       '$($global:SBLServers)'")    -Verbose:$Verbose
    Write-Verbose -Message ("Siebel Servers (All) '$($global:SBLAllServers)'") -Verbose:$Verbose
}

## Invoke Siebel WFP
function Invoke-SBLWFP {
    param ([string]$Host = $global:SBLHost,
           [string]$WFPName,
           [string]$Parameters,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

    $URI = ("https://{0}/siebel/v1.0/service/Workflow Process Manager/RunProcess?ProcessName={1}&{2}" -f $Host, $WFPName, $Parameters)

    $Result = Invoke-WebRequest -Uri $URI -ContentType application/json -Method POST -Credential $Credential -Verbose:$Verbose

    return $Result
}

## Stop Siebel Server Service ##
function Stop-SBLServer {
    param ([string[]]$Servers = $global:SBLServers,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

    Write-Verbose -Message ("Stoping Siebel Service(s) on '{0}'" -f $Servers) -Verbose:$Verbose
    Invoke-Command -ComputerName $Servers -ScriptBlock { stop-service -InputObject $(get-Service | where {$_.Name -like 'SiebSrvr_Siebel*'}) } -Credential $Credential -Verbose:$Verbose
}

## Start Siebel Server Service ##
function Start-SBLServer {
    param ([string[]]$Servers = $global:SBLServers,
            [Management.Automation.PSCredential]$Credential,
            [switch]$Verbose)

    Write-Verbose -Message ("Start Siebel Service(s) on '{0}'" -f $Servers) -Verbose:$Verbose
    Invoke-Command -ComputerName $Servers -ScriptBlock { start-service -InputObject $(get-Service | where {$_.Name -like 'siebSrvr_Siebel*'}) } -Credential $Credential -Verbose:$Verbose
}

function Get-SBLServer {
    param ([string[]]$Servers = $global:SBLServers,
           [Management.Automation.PSCredential]$Credential)

    Invoke-Command -ComputerName $Servers -ScriptBlock { get-Service | where {$_.Name -like 'siebSrvr_Siebel*'} } -Credential $Credential
}

## Remove Siebel Server Service ##
function Remove-SBLService {
    param ([string[]]$Servers = $global:SBLServers,
            [string]$Path = $SBLSrvrPath,
            [Management.Automation.PSCredential]$Credential,
            [switch]$Verbose)

    $lSrvrCmd01 = "{0}\bin\siebctl.exe -d -S siebsrvr -i ""SIEBEL_{1}"""

    foreach ($Server in $Servers) {
        
        $Service = ($Server -replace "ZA", "").ToLower()

        Write-Verbose -Message ("Removing Siebel service on '{0}'" -f $Server.ToLower()) -Verbose:$Verbose
        Invoke-Command -ComputerName $Server -ScriptBlock ([Scriptblock]::Create(($lSrvrCmd01 -f $Path,$Service))) -Credential $Credential -Verbose:$Verbose
    }
}

## Add Siebel Server Service ##
function Add-SBLService {
    param ([string[]]$Servers = $global:SBLServers,
            [string]$GatewayServer = $global:SBLGtwyServer,
            [string]$Path = $SBLSrvrPath,
            [string]$NewPassword,
            [Management.Automation.PSCredential]$Credential,
            [string]$ServiceUser,
            [string]$ServiceUserPassword,
            [switch]$Verbose)

    foreach ($Server in $Servers) {

        $Service = ($Server -replace "ZA", "").ToLower()

        Write-Verbose -Message ("Adding Siebel Services on '{0}' for {1}" -f $Server,$Service) -Verbose:$Verbose

        if ($ServiceUserPassword) {
            $lSrvrCmd02 = "{0}\bin\siebctl.exe -h {0} -S siebsrvr -i ""SIEBEL_{1}"" -a -g ""-g {2}:9999 -e SIEBEL -s {1} -l enu -u SADMIN"" -e ""{3}"" -u {4} -p ""{3}"""
            Write-Verbose -Message ($lSrvrCmd02 -f $Path,$Server,$GatewayServer,$NewPassword,$ServiceUser,$ServiceUserPassword) -Verbose:$Verbose
            Invoke-Command -ComputerName $Server -ScriptBlock ([Scriptblock]::Create(($lSrvrCmd02 -f $Path,$Service,$GatewayServer.ToLower(),$NewPassword,$ServiceUser,$ServiceUserPassword))) -Credential $Credential -Verbose:$Verbose
        } else {
            $lSrvrCmd02 = "{0}\bin\siebctl.exe -h {0} -S siebsrvr -i ""SIEBEL_{1}"" -a -g ""-g {2}:9999 -e SIEBEL -s {1} -l enu -u SADMIN"" -e ""{3}"""
            Write-Verbose -Message ($lSrvrCmd02 -f $Path,$Server,$GatewayServer,$NewPassword) -Verbose:$Verbose
            Invoke-Command -ComputerName $Server -ScriptBlock ([Scriptblock]::Create(($lSrvrCmd02 -f $Path,$Service,$GatewayServer.ToLower(),$NewPassword))) -Credential $Credential -Verbose:$Verbose
        }
        Invoke-Command -ComputerName $Server -ScriptBlock { set-service -InputObject $(get-Service | where {$_.Name -like 'SiebSrvr_Siebel*'}) -StartupType Automatic } -Credential $Credential -Verbose:$Verbose
    }
}

## Backup Siebel Gateway siebns.dat file ##
function Backup-SBLGtwy {
    param ([string]$GatewayServer = $global:SBLGtwyServer,
           [string]$Path = $global:SBLGtwyPath,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

    Write-Verbose -Message "Gateway backing up zookeaper." -Verbose:$Verbose
    Invoke-Command -ComputerName $GatewayServer -ScriptBlock ([Scriptblock]::Create(("Compress-Archive -Path {0}\zookeeper\version-2 -DestinationPath {0}\zookeeper\version-2_{1}.zip -Force -Verbose" -f $Path,$(get-date -f yyyy-MM-dd)))) -Credential $Credential -Verbose:$Verbose
}

function Stop-SBLGtwyServer {
    param ([string[]]$Servers = $global:SBLGtwyServer,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

    Write-Verbose -Message ("Stoping Siebel Gateway Service on '{0}'" -f $Servers) -Verbose:$Verbose
    Invoke-Command -ComputerName $Servers -ScriptBlock { stop-service -InputObject $(get-Service | where {$_.Name -like 'gtwyns'}) } -Credential $Credential -Verbose:$Verbose
}

## Start Siebel Server Service ##
function Start-SBLGtwyServer {
    param ([string[]]$Servers = $global:SBLGtwyServer,
            [Management.Automation.PSCredential]$Credential,
            [switch]$Verbose)

    Write-Verbose -Message ("Start Siebel Gateway Service on '{0}'" -f $Servers) -Verbose:$Verbose
    Invoke-Command -ComputerName $Servers -ScriptBlock { start-service -InputObject $(get-Service | where {$_.Name -like 'gtwyns'}) } -Credential $Credential -Verbose:$Verbose
}

function Get-SBLGtwyServer {
    param ([string[]]$Servers = $global:SBLGtwyServer,
           [Management.Automation.PSCredential]$Credential)

    Invoke-Command -ComputerName $Servers -ScriptBlock { get-Service | where {$_.Name -like 'gtwyns'} } -Credential $Credential
}

## Change Siebel Gateway Enterprize Paramiter ##
function Set-SBLGtwyEnvParam {
    param ([string]$Name,
           [string]$Value,
           [string]$GatewayServer = $global:SBLGtwyServer,
           [string]$Path = $global:SBLGtwyPath,
           [string]$Password,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

  $lGtwyCmd   = '{0}\BIN\srvrmgr.exe -g {1} -e siebel -u sadmin -p "{2}" -c "change ent param {3}=""{4}"""'

  Write-Verbose -Message "Gateway update enterpize paramiter $Name." -Verbose:$Verbose
  Invoke-Command -ComputerName $GatewayServer -ScriptBlock ([Scriptblock]::Create(($lGtwyCmd -f $Path,$GatewayServer,$Password,$Name,$Value))) -Credential $Credential -Verbose:$Verbose
}

## Change Siebel Gateway SybStstem Paramiter ##
function Set-SBLGtwySubSysParam {
    param ([string]$Name,
           [string]$Value,
           [string[]]$SybSystems,
           [string]$GatewayServer = $global:SBLGtwyServer,
           [string]$ComputerName  = $global:SBLGtwyServer,
           [string]$Path = $global:SBLGtwyPath,
           [string]$Password,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

    $lGtwyCmd01   = '{0}\BIN\srvrmgr.exe -g {1} -e siebel -u sadmin -p "{2}" -c "change param {3}=""{4}"" for named subsystem {5}"'

    foreach ($SybSystem in $SybSystems) {
        Write-Verbose -Message ("Gateway update SubSystem paramiter '{0}' for '{1}'." -f $Name,$SybSystem)
        Invoke-Command -ComputerName $ComputerName -ScriptBlock ([Scriptblock]::Create(($lGtwyCmd01 -f $Path,$GatewayServer,$Password,$Name,$Value,$SybSystem))) -Credential $Credential -Verbose:$Verbose
    }
}

## Change Siebel Gateway SybSystem Paramiter ##
function Get-SBLGtwyEvtLogLevel {
    param ([ValidateSet("CommInboundRcvr","EIM","CustomAppObjMgr_enu","eCommunicationsObjMgr_enu","eProdCfgObjMgr_enu","EAIObjMgr_enu","PRMPortal_enu","VCVPPObjMgr_enu","VCDHAObjMgr_enu","VCEAIQWfProcMgr","VCIFObjMgr_enu","VCIFTObjMgr_enu","WfProcMgr","WfProcBatchMgr","AsgnSrvr","XMLPReportServer","CommInboundProcessor")][string]$CompAliasName,
           [string]$GatewayServer = $global:SBLGtwyServer,
           [string]$Path = $global:SBLGtwyPath,
           [string]$Password,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

    if ($Server) {
        $lGtwyCmd01   = '{0}\BIN\srvrmgr.exe -g {1} -e siebel -u SADMIN -p "{2}" -c "list evtloglvl for server {3} component {4}"'
        Write-Verbose -Message ("Gateway: Get Event logging level for server '{0}', compoment '{1}'." -f $Server,$CompAliasName) -Verbose:$Verbose
        Invoke-Command -ComputerName $GatewayServer -ScriptBlock ([Scriptblock]::Create(($lGtwyCmd01 -f $Path,$GatewayServer,$Password,$Server,$CompAliasName))) -Credential $Credential -Verbose:$Verbose
    } else {
        $lGtwyCmd01   = '{0}\BIN\srvrmgr.exe -g {1} -e siebel -u SADMIN -p "{2}" -c "list evtloglvl for component {3}"'
        Write-Verbose -Message ("Gateway: Get Event logging level for compoment '{0}'." -f $CompAliasName) -Verbose:$Verbose
        Invoke-Command -ComputerName $GatewayServer -ScriptBlock ([Scriptblock]::Create(($lGtwyCmd01 -f $Path,$GatewayServer,$Password,$CompAliasName))) -Credential $Credential -Verbose:$Verbose
    }
}

function Set-SBLGtwyEvtLogLevel {
    param ([string]$Name = "%",
           [ValidateSet("0","1","2","3","4","5")][string]$Value = "1",
           [ValidateSet("CommInboundRcvr","EIM","CustomAppObjMgr_enu","eCommunicationsObjMgr_enu","eProdCfgObjMgr_enu","EAIObjMgr_enu","EAIObjMgrOTP_enu", "eChannelObjMgr_enu","eChannelObjMgrAD_enu","VCVPPObjMgr_enu","VCIFObjMgr_enu","VCIFTObjMgr_enu","VCDHAObjMgr_enu","VCEAIQWfProcMgr","WfProcMgr","WfProcBatchMgr","AsgnSrvr","XMLPReportServer","CommInboundProcessor")][string]$CompAliasName,
           [string]$Server,
           [string]$GatewayServer = $global:SBLGtwyServer,
           [string]$Path = $global:SBLGtwyPath,
           [string]$Password,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

    if ($Server) {
        $lGtwyCmd01   = '{0}\BIN\srvrmgr.exe -g {1}:9999 -e siebel -u SADMIN -p "{2}" -c "change evtloglvl {3}={4} for server {5} component {6}"'
        Write-Verbose -Message ("Gateway: change evtloglvl {0}={1} for server {2} component {3}." -f $Name,$Value,$Server,$CompAliasName) -Verbose:$Verbose
        Invoke-Command -ComputerName $GatewayServer -ScriptBlock ([Scriptblock]::Create(($lGtwyCmd01 -f $Path,$GatewayServer,$Password,$Name,$Value,$Server,$CompAliasName))) -Credential $Credential -Verbose:$Verbose
    } else {
        $lGtwyCmd01   = '{0}\BIN\srvrmgr.exe -g {1}:9999 -e siebel -u SADMIN -p "{2}" -c "change evtloglvl {3}={4} for component {5}"'
        Write-Verbose -Message ("Gateway: change evtloglvl {0}={1} for component {2}." -f $Name,$Value,$CompAliasName) -Verbose:$Verbose
        Invoke-Command -ComputerName $GatewayServer -ScriptBlock ([Scriptblock]::Create(($lGtwyCmd01 -f $Path,$GatewayServer,$Password,$Name,$Value,$CompAliasName))) -Credential $Credential -Verbose:$Verbose
    }
}

function Set-SBLSrvrComp {
    param ([ValidateSet("CustomAppObjMgr_enu","eCommunicationsObjMgr_enu","eProdCfgObjMgr_enu","EAIObjMgr_enu","EAIObjMgrOTP_enu", "eChannelObjMgr_enu","eChannelObjMgrAD_enu","VCVPPObjMgr_enu","VCIFTObjMgr_enu","VCIFObjMgr_enu","VCDHAObjMgr_enu","VCEAIQWfProcMgr","WfProcMgr","WfProcBatchMgr","AsgnSrvr","XMLPReportServer","CommInboundProcessor")][string]$CompAliasName,
    [ValidateSet("Startup","Kill","Shutdown")][string]$Command,
           [string]$Server,
           [string]$GatewayServer = $global:SBLGtwyServer,
           [string]$Path = $global:SBLGtwyPath,
           [string]$Password,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

    if ($Server) {
        $lGtwyCmd01   = '{0}\BIN\srvrmgr.exe -g {1} -e siebel -u sadmin -p "{2}" -c "{3} comp {4} for server {5}"'
        Write-Verbose -Message ("SiebelServer: {0} comp '{1}' for server '{2}'." -f $Command,$CompAliasName,$Server) -Verbose:$Verbose
        Invoke-Command -ComputerName $GatewayServer -ScriptBlock ([Scriptblock]::Create(($lGtwyCmd01 -f $Path,$GatewayServer,$Password,$Command,$CompAliasName,$Server))) -Credential $Credential -Verbose:$Verbose
    } else {
        $lGtwyCmd01   = '{0}\BIN\srvrmgr.exe -g {1} -e siebel -u sadmin -p "{2}" -c "{3} comp {4}"'
        Write-Verbose -Message ("SiebelServer: {0} compoment '{1}'." -f $Command,$CompAliasName) -Verbose:$Verbose
        Invoke-Command -ComputerName $GatewayServer -ScriptBlock ([Scriptblock]::Create(($lGtwyCmd01 -f $Path,$GatewayServer,$Password,$Command,$CompAliasName))) -Credential $Credential -Verbose:$Verbose
    }
}

function Get-SBLSrvrComp {
    param ([ValidateSet("CustomAppObjMgr_enu","eCommunicationsObjMgr_enu","eProdCfgObjMgr_enu","EAIObjMgr_enu", "EAIObjMgrOTP_enu", "eChannelObjMgr_enu","eChannelObjMgrAD_enu","VCVPPObjMgr_enu","VCIFTObjMgr_enu","VCIFObjMgr_enu","VCDHAObjMgr_enu","VCEAIQWfProcMgr","WfProcMgr","WfProcBatchMgr","AsgnSrvr","XMLPReportServer","CommInboundProcessor")][string]$CompAliasName,
           [string]$Server,
           [string]$GatewayServer = $global:SBLGtwyServer,
           [string]$Path = $global:SBLGtwyPath,
           [string]$Password,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

    if ($Server) {
        $lGtwyCmd01   = '{0}\BIN\srvrmgr.exe -g {1} -e siebel -u sadmin -p "{2}" -c "list comp {3} for server {4}"'
        Write-Verbose -Message ("SiebelServer: list comp '{0}' for server '{1}'." -f $CompAliasName,$Server) -Verbose:$Verbose
        Invoke-Command -ComputerName $GatewayServer -ScriptBlock ([Scriptblock]::Create(($lGtwyCmd01 -f $Path,$GatewayServer,$Password,$CompAliasName,$Server))) -Credential $Credential -Verbose:$Verbose
    } else {
        $lGtwyCmd01   = '{0}\BIN\srvrmgr.exe -g {1} -e siebel -u sadmin -p "{2}" -c "list comp {3}"'
        Write-Verbose -Message ("SiebelServer: list compoment '{0}'." -f $CompAliasName) -Verbose:$Verbose
        Invoke-Command -ComputerName $GatewayServer -ScriptBlock ([Scriptblock]::Create(($lGtwyCmd01 -f $Path,$GatewayServer,$Password,$CompAliasName))) -Credential $Credential -Verbose:$Verbose
    }
}

function Get-SBLSrvrLogs {
    param ([ValidateSet('Log','Temp','FDR','Crash')][string[]]$Types = ("Log"),
           [string]$Filter = "*",
           [string]$Pattern,
           [string[]]$Servers   = $global:SBLServers,
           [string]$Destination = $SBLTempPath,
           [Management.Automation.PSCredential]$Credential,
           [switch]$Verbose)

    $Sessions = New-PSSession -ComputerName $Servers -Credential $Credential

    $Path = "{0}\{1}\{2}.{3}"

    foreach ($Type in $Types) {
        foreach ($Session in $Sessions) {
            Write-Verbose -Message ("Remote Server: {0}." -f $Session.ComputerName) -Verbose:$Verbose
            switch ($Type) {
                "Log" { 
                    Write-Verbose -Message "Getting file from '\Log'." -Verbose:$Verbose

                    if ($Pattern) {
                        $Temp = "Get-Item {0} | select-string -list -pattern {1} | group path |select name"
                        $Files = Invoke-Command -Session $Session -ScriptBlock ([Scriptblock]::Create(($Temp -f ($Path -f $SBLSrvrPath,"log",$Filter,"log"),$Pattern))) -Verbose:$Verbose
                        
                        foreach ($File in $Files) {
                            Copy-Item $File.Name -Force -Destination $Destination -FromSession $Session -Verbose:$Verbose -ErrorAction SilentlyContinue 
                        }
                    } else {
                        Copy-Item ($Path -f $SBLSrvrPath,"log",$Filter,"log") -Force -Destination $Destination -FromSession $Session -Verbose:$Verbose -ErrorAction SilentlyContinue 
                    }
                    Break;
                }
                "Temp" {
                    Write-Verbose -Message "Getting file from '\TEMP'." -Verbose:$Verbose
                    Copy-Item ($Path -f $SBLSrvrPath,"TEMP",$Filter,"csv")  -Force -Destination $Destination -FromSession $Session -Verbose:$Verbose -ErrorAction SilentlyContinue 
                    Copy-Item ($Path -f $SBLSrvrPath,"TEMP",$Filter,"tmp")  -Force -Destination $Destination -FromSession $Session -Verbose:$Verbose -ErrorAction SilentlyContinue 
                    Copy-Item ($Path -f $SBLSrvrPath,"TEMP",$Filter,"xml")  -Force -Destination $Destination -FromSession $Session -Verbose:$Verbose -ErrorAction SilentlyContinue 
                    Copy-Item ($Path -f $SBLSrvrPath,"TEMP",$Filter,"ini")  -Force -Destination $Destination -FromSession $Session -Verbose:$Verbose -ErrorAction SilentlyContinue 
                    Copy-Item ($Path -f $SBLSrvrPath,"TEMP",$Filter,"pdf")  -Force -Destination $Destination -FromSession $Session -Verbose:$Verbose -ErrorAction SilentlyContinue 
                    Break
                }
                "FDR" {
                    Write-Verbose -Message "Getting file from '\FDR'." -Verbose:$Verbose
                    $Cmd = "{0}\bin\sarmanalyzer.exe -f {0}\BIN\{1} -x -o {0}\temp\{1}.csv";

                    $Temp  = "Get-Item {0}\BIN\{1}.fdr"
                    $Files = Invoke-Command -Session $Session -ScriptBlock ([Scriptblock]::Create(($Temp -f $SBLSrvrPath,$Filter))) -Verbose:$Verbose

                    foreach ($File in $Files) {
                        Write-Verbose -Message  ("Converting: {0}" -f $File.Name) -Verbose:$Verbose
                        Invoke-Command -Session $Session -ScriptBlock ([Scriptblock]::Create(($Cmd -f $SBLSrvrPath,$File.Name))) -Verbose:$Verbose

                        Copy-Item ($Path -f $SBLSrvrPath,"Temp",$File.Name,"csv")  -Destination $Destination -FromSession $Session -Verbose:$Verbose -ErrorAction SilentlyContinue
                    }
                    Break
                }
                "Crash" {
                    Write-Verbose -Message "Getting file from '\Crash'." -Verbose:$Verbose
                    $Temp = "crash_" + $Filter
                    Copy-Item ($Path -f $SBLSrvrPath,"BIN",$Temp,"txt")  -Destination $Destination -FromSession $Session -Verbose -ErrorAction SilentlyContinue 
                    Break
                }
                ##"LOGARCHIVE" {
                ##    Write-Verbose -Message "Getting file from '\LOGARCHIVE'." -Verbose:$Verbose
                ##    Copy-Item ($Path -f $SBLSrvrPath,"LOGARCHIVE",$Filter,"log")  -Destination $Destination -FromSession $Session -Verbose -ErrorAction SilentlyContinue 
                ##    Break;
                ##}
            }
        }
    }
    Remove-PSSession $Sessions
}

function Remove-SBLSrvrLogs {
    param ([ValidateSet('AI','EmailResponce','Log','Temp','FDR','Crash','LOGARCHIVE','DRCache')][string[]]$Types = ("EmailResponce","Log","Temp","FDR","Crash","LOGARCHIVE"),
           [string]$Filter = "*",
           [string[]]$Servers = $global:SBLServers,
           [Management.Automation.PSCredential][System.Management.Automation.Credential()]$Credential,
           [int32]$AddMin = 0,
           [switch]$Verbose)

    $Sessions = New-PSSession -ComputerName $Servers -Credential $Credential

    if ($Verbose) {
        $Command  = "Get-ChildItem ""{0}\{1}\*"" -Include {2}.{3} | Where-Object LastWriteTime -lt (Get-Date).AddMinutes({4} | Remove-Item -ErrorAction  SilentlyContinue -Verbose"
        $Command1 = "Get-ChildItem ""{0}\{1}\*"" -Include {2}.{3} -Recurse | Where-Object LastWriteTime -lt (Get-Date).AddMinutes({4}) | Remove-Item -ErrorAction  SilentlyContinue -Verbose"
    } else {
        $Command  = "Get-ChildItem ""{0}\{1}\*"" -Include {2}.{3} | Where-Object LastWriteTime -lt (Get-Date).AddMinutes({4}) | Remove-Item -ErrorAction  SilentlyContinue"
        $Command1 = "Get-ChildItem ""{0}\{1}\*"" -Include {2}.{3} -Recurse | Where-Object LastWriteTime -lt (Get-Date).AddMinutes({4}) | Remove-Item -ErrorAction  SilentlyContinue"
    }

    $AddMin = $AddMin * -1;

    foreach ($Type in $Types) {
        switch ($Type) {
            "AI" {
                Write-Verbose -Message "Removing '\AI Log' files." -Verbose:$Verbose
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command -f $SBLAppIntPath,"applicationcontainer\logs",$Filter,"*",$AddMin)))
                Break
            }
            "EmailResponce" {
                Write-Verbose -Message "Removing '\Email Responce (processing\incomming)' files." -Verbose:$Verbose
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command -f $SBLSrvrPath,"BIN\processed",$Filter,"*",$AddMin)))
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command -f $SBLSrvrPath,"BIN\incoming",$Filter,"*",$AddMin))) 
                Break
            }
            "Log" { 
                Write-Verbose -Message "Removing '\Log' files." -Verbose:$Verbose
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command -f $SBLSrvrPath,"log",$Filter,"log",$AddMin)))
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command -f $SBLSrvrPath,"log",$Filter,"dmp",$AddMin)))
                Break;
            }
            "Temp" {
                Write-Verbose -Message "Removing '\Temp' files." -Verbose:$Verbose
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command2 -f $SBLSrvrPath,"TEMP",$Filter,"*",$AddMin)))
                Break
            }
            "FDR" {
                $Temp = "T" + $Filter
                Write-Verbose -Message "Removing '\FDR' files." -Verbose:$Verbose
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command -f $SBLSrvrPath,"BIN",$Temp,"fdr",$AddMin)))
                Break
            }
            "Crash" {
                $Temp = "crash_" + $Filter
                Write-Verbose -Message "Removing '\Crash' files." -Verbose:$Verbose
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command -f $SBLSrvrPath,"BIN",$Temp,"txt",$AddMin)))
                Break
            }
            "LOGARCHIVE" {
                Write-Verbose -Message "Removing '\LOGARCHIVE' files." -Verbose:$Verbose
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command1 -f $SBLSrvrPath,"LOGARCHIVE",$Filter,"log",$AddMin)))
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command1 -f $SBLSrvrPath,"LOGARCHIVE",$Filter,"dmp",$AddMin)))
                Break;
            }
            "DRCache" {
                $Temp = "*cache"
                Write-Verbose -Message "Removing '\DRCache' files." -Verbose:$Verbose
                Invoke-Command -Session $Sessions -ScriptBlock ([Scriptblock]::Create(($Command -f $SBLSrvrPath,"BIN",$Temp,"dat",$AddMin)))
                Break;
            }
        }
    }
    Remove-PSSession $Sessions
}

##change evtloglvl event_alias_name=level for component component_alias_name
##change evtloglvl event_alias_name=level for server siebel_server_name component component_alias_name
##list evtloglvl for component component_alias_name
## File Analyzer (LFA) 

## Export ##
##Export-ModuleMember -Variable 'SBLGtwyPath'
##Export-ModuleMember -Variable 'SBLSrvrPath'
##Export-ModuleMember -Variable 'SBLGtwyServer'
##Export-ModuleMember -Variable 'SBLTempPath'

Export-ModuleMember -Function 'Set-SBLEnv'

Export-ModuleMember -Function 'Invoke-SBLWFP'

## Siebel Services
Export-ModuleMember -Function 'Stop-SBLServer'
Export-ModuleMember -Function 'Start-SBLServer'
Export-ModuleMember -Function 'Get-SBLServer'
Export-ModuleMember -Function 'Remove-SBLService'
Export-ModuleMember -Function 'Add-SBLService'

## Backup Gateway
Export-ModuleMember -Function 'Backup-SBLGtwy'
Export-ModuleMember -Function 'Stop-SBLGtwyServer'
Export-ModuleMember -Function 'Start-SBLGtwyServer'
Export-ModuleMember -Function 'Get-SBLGtwyServer'

## Siebel Server Components
Export-ModuleMember -Function 'Set-SBLSrvrComp'
Export-ModuleMember -Function 'Get-SBLSrvrComp'

## Siebel Gateway Param
Export-ModuleMember -Function 'Set-SBLGtwyEnvParam'
Export-ModuleMember -Function 'Set-SBLGtwySubSysParam'

## Siebel Gateway Log Level
Export-ModuleMember -Function 'Set-SBLGtwyEvtLogLevel'
Export-ModuleMember -Function 'Get-SBLGtwyEvtLogLevel'

## Siebel Logs
Export-ModuleMember -Function 'Get-SBLSrvrLogs'
Export-ModuleMember -Function 'Remove-SBLSrvrLogs'
