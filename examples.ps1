Import-Module .\IvantiDiscoveryServices -Force

<#
    N.B. The -IgnoreCertificate switch is being used in this example as the server is using a self-signed certificate which was not available in the
         certificate store.  This switch should not be needed in a full production environment.
#>

$DiscoveryServer = 'localhost'

# Attempt  to automatically get the Client ID (this will fail unless the server specified is the machine that the script is running on)
Get-DiscoveryServicesClientId -Server $DiscoveryServer

# Check if we can authenticate to the Discovery Services server successfully (will look for a stored access token and check if it is valid)
if (-not (Test-DiscoveryServices -Server $DiscoveryServer -IgnoreCertificate)) {
    # Generate a new access token and store it locally for reuse
    Get-DiscoveryServicesOAuthAccessToken -Server $DiscoveryServer -ClientId (Get-DiscoveryServicesClientId -Server $DiscoveryServer) -ClientSecret (Get-DiscoveryServicesClientSecret -Server $DiscoveryServer) -IgnoreCertificate | Out-Null
}

# Get the total number of records stored
Measure-DiscoveryServicesRecord -Server $DiscoveryServer -IgnoreCertificate

# Get the OS version of the first record that can be returned
(Get-DiscoveryServicesItem -Server $DiscoveryServer -QueryParameters '$top=1' -IgnoreCertificate).value.OS.Version

# Return the count of items who have a device name that starts with a D
(Get-DiscoveryServicesItem -Server $DiscoveryServer -QueryParameters "`$filter=(startswith(DeviceName, 'D'))")."@odata.count"

# Return the DeviceName and OS Name of items who have a device name that starts with a D
(Get-DiscoveryServicesItem -Server $DiscoveryServer -QueryParameters "`$filter=(startswith(DeviceName, 'D'))&`$select=DeviceName,OS.Name")

# Return the DeviceName and OS Name of items who have a device name that starts with a D and have Mac in the OS Name
(Get-DiscoveryServicesItem -Server $DiscoveryServer -QueryParameters "`$filter=(startswith(DeviceName, 'D') and contains(OS.Name, 'Mac'))&`$select=DeviceName,OS.Name")

# Export all fields, for the first record that can be returned, into the specified file
Export-DiscoveryServicesItem -Server $DiscoveryServer -Query '$colset=all&$top=1' -OutputFile "$env:UserProfile\Desktop\results.json" -IgnoreCertificate

# Export all fields, for all records, into the specified file
### THIS COULD TAKE A LONG TIME AND MAY TIME OUT UNLESS YOU ADJUST THE SCROLL TIMEOUT SETTING ###
#$start = [int] (Get-Date -UFormat "%s")
#Export-DiscoveryServicesItem -Server $DiscoveryServer -OutputFile "$env:UserProfile\Desktop\results.json" -IgnoreCertificate
#$end = $([int] (Get-Date -UFormat "%s"))
#Write-Host "Duration: $($end - $start) seconds"

# Export all fields, for all records, but do not combine the returned pages
### THIS COULD TAKE A LONG TIME AND MAY TIME OUT UNLESS YOU ADJUST THE SCROLL TIMEOUT SETTING ###
#$start = [int] (Get-Date -UFormat "%s")
#Export-DiscoveryServicesItem -Server $DiscoveryServer -OutputFolder "$env:UserProfile\Desktop\results" -Paged -IgnoreCertificate
#$end = $([int] (Get-Date -UFormat "%s"))
#Write-Host "Duration: $($end - $start) seconds"

# Export default fields, for all records, but do not combine the returned pages and change the file prefix from the default
Export-DiscoveryServicesItem -Server $DiscoveryServer -Query '$colset=default' -OutputFolder "$env:UserProfile\Desktop\results" -Paged -IgnoreCertificate
