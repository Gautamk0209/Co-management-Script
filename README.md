# Co-management-Script

PowerShell script to get co-management details needed for analysis and troubleshooting

For Co-managed devices, we get status, policy and mdm url check, co-management state message details,co-management workload,Enrollment state value

For not co-managed devices, We get status, policy and mdm url check, co-management state message details, Hybrid Azure AD check, Dmwappush service state, Enrollment event log for errors and co-management handler log error details

In this script, quering for state message would need admin access. Deploying this through MEMCM script feature will  get complete details While executing it manually for devices with not admin previllage will not return co-manage state information.

All the catch block has been commented to avoid bulk output during errors when deployed through sccm. We can un comment it as required.

If the co-management autoenrollent policy is removed, MDM url remains intact hence will show up. The co-management CIs which gets removed is not checked.

Script is not design for scenario were machine is removed for co-management pilot/All hence we expect it to show up as not co-managed as it doesnt revert state and only autoenrollment CI is removed to stop any future enrollment through MEMCM
