<#PSScriptInfo

.VERSION 2.0

.AUTHOR Gautam Kumar

.RELEASENOTES
Version 2.0: Stable version.Tested for around 1k devices.

.DESCRIPTION 
co-management details and detecting potential issues in Co-management
Get log errors and event log error details for Co-management along with state message details.
Co-management success or failure details including co-management workload, hybrid join state, enrollemet state etc

#> 

#Memcm client log path
$logpath = "C:\Windows\CCM\Logs"
#Getting data from different source to be used to create co-management report
try {
    $checksuccess1 = Select-String -SimpleMatch "Machine is already enrolled with MDM" -Path "$logpath\CoManagementHandler.log" -Quiet
    $eventlog1 = Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" | where { ($_.Id -eq 75) } | select -First 1
    $policycheck = Get-WmiObject -Namespace "root/ccm/policy/Machine" -Query "SELECT * FROM CCM_CoMgmt_Configuration"
    $eventlog2 = Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" | where { ($_.Id -eq 76) } | select -Property id, message, TimeCreated -First 2
    $workload = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DeviceManageabilityCSP\Provider\WMI_Bridge_Server"
    #Quering for state message which needs admin access
    $statemsg = get-wmiobject -namespace root\ccm\statemsg -query "select * from ccm_statemsg where topictype=810" -ErrorAction SilentlyContinue
}
catch {
    #Write-Output "Error detected in getting initial details"
    #Write-Output = $_
}
#Getting guid from enrollment task and using it to get enrollment details from registry
try {
    $s = Get-ScheduledTask -TaskPath *EnterpriseMgmt*
    $s1 = $s[0].TaskPath.Replace('\Microsoft\Windows\EnterpriseMgmt\', "")
    if ($s.Count -ge 2) {
        $Enrollment = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\$s1"
    }
}
catch {
    #Write-Output "Error detected while checking co-management status"
    #Write-Output $_
}
#function to convert co-management workload value into workload strings
Function Comange-workload() {
    $w2 = $workload.ConfigInfo
    $W1 = @{
        3   = "Compliance policies"
        5   = "Resource access policies"
        9   = "Device Configuration"
        17  = "Windows Updates Policies"
        33  = "Endpoint Protection"
        65  = "Client Apps"
        129 = "Office Click-to-Run apps"
    }
    if ($w2 -gt 1) {
        foreach ($key in $W1.Keys) {
            if (($key -band $w2) -eq $key) {
                $W1[$key]
            }
        }
    }
    else {
        Write-Output "No workload assigned"
    }
}
#Checking hybrid azure AD join and AzureADPRT status
Function HAADcheck() {
    $m1 = (dsregcmd /status)
    $m = ($m1 | Select-String -SimpleMatch "azureadjoin").ToString()
    $m = $m.Replace(" ", "")
    $z = 'AzureAdJoined : YES'
    $z = $z.Replace(" ", "")
    if ($z -eq $m) {
        Write-Output "Device is already hybrid joined"
        (($m1 | Select-String -SimpleMatch "AzureAdPrt :").ToString()).Replace(" ", "")
    }
    else {
        Write-Output "Hybrid join not detected, getting event logs and triggering HAAD task"
        Get-WinEvent -LogName "Microsoft-Windows-User Device Registration/Admin" | where { ($_.Id -eq 304) -or ($_.Id -eq 305) -or ($_.Id -eq 204) } | select -Property id, message, TimeCreated  -First 3 
        Start-ScheduledTask "\Microsoft\Windows\Workplace Join\Automatic-Device-Join"
    }
}
#Refining co-management state message
try {
    $msg = $statemsg.StateDetails.ToString()
    $s1 = $msg.Substring($msg.IndexOf('MDMEnrollment'), ($msg.IndexOf('/><ServiceUri')) - ($msg.IndexOf('MDMEnrollment')))
    $s2 = $msg.Substring($msg.IndexOf('ScheduledEnrollTime'), ($msg.IndexOf('/><WorkloadFlags')) - ($msg.IndexOf('ScheduledEnrollTime')))
}
catch {
    #Write-Output $_
}

if (($checksuccess1 -ne 'True') -and ($eventlog1.id -ne 75)) {
    #Getting error details from co-management handler log
    try {
        $checkerror = Select-String -SimpleMatch "Failed" -Path "$logpath\CoManagementHandler.log"
        $a2 = @()
        if ($checkerror.Count -gt 12) {
            $x = 12
        }
        else { $x = $checkerror.Count }
        for ($i = 0; $i -lt $x; $i++) {
            $a = $checkerror[$i].ToString()
            $a1 = $a.Substring($a.IndexOf('LOG['), ($a.IndexOf('component')) - ($a.IndexOf('LOG[')))
            $a2 += $a1
        }
    }

    catch {
        #Write-Output "Issue accessing co-management handler log"
        #Write-Output $_
    }

    #Calling Hybrid Azure AD check
    $haad = HAADcheck
    #Checking Dmwappush service state
    $service = Get-Service -Name dmwappushservice
    $Prop = [ordered]@{              
        'Status'                  = 'Not Co-Managed'
        'Policy_mdmurl'           = $policycheck.MDMEnrollmentUrl
        'HAADJ_status'            = $haad
        'Co-manage state msg'     = "$s1 $s2"
        'Dmwappushservice_status' = "<starttype = $($service.StartType)> <status = $($service.Status)>"
        'Enrollment_event_error'  = $eventlog2
        'Error_logs'              = $a2
    }

    $Obj = New-Object -TypeName PSObject -Property $Prop 
    Write-Output $Obj
}
Else {
    $workloads = Comange-workload
    $Prop = [ordered]@{ 
        'Status'              = 'Co-Managed'
        'Co-manage state_msg' = $s1
        'Policy_mdmurl'       = $policycheck.MDMEnrollmentUrl
        'Co-manage workloads' = $workloads
        'EnrollmentState'     = $Enrollment.EnrollmentState              
    }

    $Obj = New-Object -TypeName PSObject -Property $Prop 
    Write-Output $Obj

}
