# Co-management-Script

PowerShell script to get co-management details needed for analysis and troubleshooting

For Co-managed devices, we get status, policy and mdm url check, co-management state message details, OS version, Mdm cert check, co-management workload, Enrollment state value

For not co-managed devices, We get status, policy and mdm url check, co-management state message details, Hybrid Azure AD check, Dmwappush service state, Enrollment event log for errors and co-management handler log error details

In this script, quering for state message would need admin access. Deploying this through MEMCM script feature will  get complete details, while executing it manually for devices with no admin previllage will not return co-manage state information.

All the catch block has been commented to avoid bulk output during errors when deployed through MEMCM. We can un-comment it as required.

If the co-management autoenrollent policy is removed (removing device from co-management collection), MDM url remains intact hence will show up. The co-management CIs which gets removed is not checked.

Script is not design for scenario where machine is removed from co-management pilot/All and expect it to show up as not co-managed as it doesnt revert state and only autoenrollment CI is removed to stop any future enrollment through MEMCM.

This script is doing shallow mdm cert check, which is just looking for cert with issuer by attribute, hence please validate it for you env and make required changes if needed.
