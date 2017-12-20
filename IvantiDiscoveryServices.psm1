$script:TempPath = "$env:Temp\uvjim"
$script:SettingsFile = (Join-Path -Path $script:TempPath -ChildPath 'DiscoveryServices.json')

if (-not (Test-Path -Path $script:TempPath)) {
    New-Item -Path $script:TempPath -ItemType Directory -Force
}

<##
    Aim:        To replace the PowerShell Write-Verbose cmdlet with one that includes the
                time in the message string.
##>
function Write-Verbose([string]$Message) {
    Microsoft.PowerShell.Utility\Write-Verbose "$((Get-Date).ToLongTimeString()) $Message"
}

<##
    Aim:        To replace the PowerShell Write-Debug cmdlet with one that includes the
                time in the message string.
##>
function Write-Debug([string]$Message) {
    Microsoft.PowerShell.Utility\Write-Debug "$((Get-Date).ToLongTimeString()) $Message"
}

<##
    Aim:        To retrieve a setting from the file stored on the file system.
    Returns:    [System.String] - the setting
                [System.Boolean] - $false if the setting is not found
##>
function Get-Setting([string]$Setting) {
    $ret = $false
    if (Test-Path -Path $script:SettingsFile) {
        $json = ConvertFrom-Json -JSONString (Get-Content -Path $script:SettingsFile)
        if ($json.ContainsKey($Setting)) {
            $ret = $json.$Setting
        }
    }
    return $ret
}

<##
    Aim:        To replace the PowerShell ConvertTo-Json cmdlet with one that provides
                greater flexibility over depth of JSON objects and cleanup.
    Notes:      The variable is removed and garbage collection forced
##>
function ConvertTo-Json($InputObject) {
    Add-Type -AssemblyName System.Web.Extensions
    $objJSON = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
    $objJSON.MaxJsonLength = [System.Int32]::MaxValue
    $ret = $objJSON.Serialize($InputObject)
    Remove-Variable -Name objJSON
    [GC]::Collect()
    return $ret
}

<##
    Aim:        To replace the PowerShell ConvertFrom-Json cmdlet with one that provides
                greater flexibility over depth of JSON objects and cleanup.
    Notes:      The variable is removed and garbage collection forced
##>
function ConvertFrom-Json([string]$JsonString) {
    # we need to fallback to the .NET methods here so that we can convert the entire stream
    # precedence rules will call a function before cmdlet
    Add-Type -AssemblyName System.Web.Extensions
    $objJSON = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
    $objJSON.MaxJsonLength = [System.Int32]::MaxValue #set the json length to its maximum
    $ret = $objJSON.DeserializeObject($JSONString)
    Remove-Variable -Name objJSON
    [GC]::Collect()
    return $ret
}

<##
    Aim:        To retrieve the stored access token and make it avilable for use in comms with the Discovery Server.
    Returns:    [System.String] - the access token to be used when communicating with the Discovery Server
##>
function Initialize-OAuthAccessToken() {
    $accessToken = Get-Setting -Setting 'access_token'
    if (-not $accessToken) { throw 'Invalid OAuth Access Token' }

    $accessToken = $accessToken | ConvertTo-SecureString
    $ret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($accessToken))
    return $ret
}

<##
    Aim:        To request the specified URI.
    Notes:      Will attempt parse the response into a JSON object
    Returns:    [System.Collections.Generic.Dictionary] - The parsed response
##>
function Invoke-DSRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreCertificate
    )

    Begin {
        Write-Debug -Message "Begin $($MyInvocation.MyCommand.Name)"
    }
    Process {
        $accessToken = Initialize-OAuthAccessToken
        if (-not $accessToken) { throw $Error[0].Exception }

        try {
            Write-Verbose -Message "Retrieving $Uri"
            $objWebRequest = [System.Net.HttpWebRequest]::Create($Uri)
            if ($IgnoreCertificate) {
                $spm_scvc = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
            $objWebRequest.Headers.Add("Authorization: $(Get-Setting -Setting 'token_type') $accessToken")
            [System.Net.WebResponse]$result = $objWebRequest.GetResponse()
            [System.IO.StreamReader]$strm = $result.GetResponseStream()
            $jsonString = $strm.ReadToEnd()
            Write-Debug -Message "Parsing response"
            $ret = ConvertFrom-Json -JsonString $jsonString
            Write-Debug -Message "Parsed response"
            Write-Verbose -Message "Retrieved $Uri"
        } catch [System.Net.WebException] {
            throw $_
        }
    }
    End {
        Write-Debug -Message "End $($MyInvocation.MyCommand.Name)"
        return $ret
    }
}

<##
    Aim:        To determine if the provided server is the one that the script is running on.
    Notes:      localhost and the loopback address are considered special cases and always return $true.
                All other possibilities follow the pattern: -
                    Attempt to retrieve all IP addresses for $Server
                    Look for commonality between addresses of the device running the script and $Server
    Returns:    [System.Boolean] - $true if the script is running on the server else $false
##>
function Test-DSServerIsMe([string]$Server) {
    Begin {
        Write-Debug -Message "Begin $($MyInvocation.MyCommand.Name)"
        $ret = $false
    }
    Process {
        try {
            if ($Server.ToLower() -eq 'localhost' -or $Server -eq '127.0.0.1') {
                $ret = $true
            } else {
                Write-Debug "Getting local IP addresses"
                $localAddresses = ([System.Net.DNS]::GetHostAddresses([System.Net.DNS]::GetHostName()) | Where AddressFamily -eq 'InterNetwork').IPAddressToString
                Write-Debug "Local addresses: $localAddresses"
                Write-Debug "Getting server IP addresses"
                $serverAddresses = ([System.Net.DNS]::GetHostAddresses($Server) | Where AddressFamily -eq 'InterNetwork').IPAddressToString
                Write-Debug "Server addresses: $serverAddresses"
                Write-Debug "Checking for at least a single common address"
                if (($serverAddresses | Where { $localAddresses -contains $_ }).length -gt 0) {
                    $ret = $true
                }
            }
        } catch {
            $ret = $false
        }
    }
    End {
        Write-Debug "$($MyInvocation.MyCommand.Name): $ret"
        Write-Debug -Message "End $($MyInvocation.MyCommand.Name)"
        return $ret
    }
}

<##
    Aim:        To test if $Server can be successfully reached and authenticated against.
    Notes:      Will attempt to use the ping endpoint of the Discovery Server
    Returns:    [System.Boolean] - $true if able to successfully communicate the Discovery Server
##>
function Test-DS {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreCertificate
    )

    Begin {
        Write-Debug -Message "Begin $($MyInvocation.MyCommand.Name)"
        $ret = $false
    }
    Process {
        try {
            Get-DiscoveryServicesItem -Server $Server -Index 'ping' -IgnoreCertificate:$IgnoreCertificate.IsPresent | Out-Null
            $ret = $true
        } catch {
            $ret = $false
        }
    }
    End {
        Write-Debug "$($MyInvocation.MyCommand.Name): $ret"
        Write-Debug -Message "End $($MyInvocation.MyCommand.Name)"
        return $ret
    }
}

<#
    .Synopsis
    Checks to see if there is an OAuth2.0 token stored and is valid

    .Description
    The Test-DiscoveryServices cmdlet checks to see if there is an OAuth2.0 token stored and is valid

    .Parameter Server
    The IP Address, hostname or FQDN of the server hosting Ivanti Discovery Services

    .Parameter IgnoreCertificate
    When provided the certificate chain will for the Discovery Server will not be validated

    .Outputs
    [System.Boolean]
    $true if there is an OAuth2.0 token stored; $false otherwise
#>
function Test-DiscoveryServices {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreCertificate
    )

    Begin {
        Write-Debug -Message "Begin $($MyInvocation.MyCommand.Name)"
        $ret = $false
    }
    Process {
        $accessToken = Get-Setting -Setting 'access_token'
        if ($accessToken) {
            $ret = Test-DS -Server $Server -IgnoreCertificate:$IgnoreCertificate.IsPresent
        }
    }
    End {
        Write-Debug "$($MyInvocation.MyCommand.Name): $ret"
        Write-Debug -Message "End $($MyInvocation.MyCommand.Name)"
        return $ret
    }
}

<#
    .Synopsis
    Requests an OAuth2.0 access token for the specified instance of Ivanti Discovery Services and stores it on the filesystem

    .Description
    The Get-DiscoveryServicesOAuthAccessToken cmdlet requests an OAuth2.0 access token for the specified instance of Ivanti Discovery Services and stores it on the filesystem

    .Parameter Server
    The IP Address, hostname or FQDN of the server hosting Ivanti Discovery Services

    .Parameter ClientId
    The client ID to present to the Ivanti Discovery Services server in order to gain an access token

    .Parameter ClientSecret
    The client secret to present to the Ivanti Discovery Services server in order to gain an access token

    .Parameter IgnoreCertificate
    When provided the certificate chain will for the Discovery Server will not be validated

    .Outputs
    [System.Boolean]
    $true if the cmdlet completed successfully
#>
function Get-DiscoveryServicesOAuthAccessToken {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$true)]
        [string]$ClientId,

        [Parameter(Mandatory=$true)]
        [string]$ClientSecret,

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreCertificate
    )

    $accessTokenURL = "https://$Server/my.identityserver/identity/connect/token"
    $grantType = 'client_credentials'
    $scopeId = 'discovery'

    if ($IgnoreCertificate) {
        $spm = [Net.ServicePointManager]::ServerCertificateValidationCallback
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
    $auth = "$clientId`:$ClientSecret"
    $auth = "Basic $([Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($auth)))"
    $result = Invoke-WebRequest -Uri $accessTokenURL -Method Post -Body "grant_type=$grantType&scope=$scopeId" -Headers @{Authorization=$auth} -ContentType "application/x-www-form-urlencoded"
    if ($IgnoreCertificate) {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $spm
    }
    $res = ConvertFrom-Json -JSONString $result.Content
    [string]$res.access_token = $res.access_token | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
    $res.requested = [int] (Get-Date -UFormat '%s')
    ConvertTo-Json -InputObject $res | Out-File -FilePath $script:SettingsFile
    return $true
}

<#
    .Synopsis
    Returns the count of records available in the specified instance of Ivanti Discovery Services

    .Description
    The Measure-DiscoveryServicesRecord cmdlet returns the count of records available in the specified instance of Ivanti Discovery Services

    .Parameter Server
    The IP Address, hostname or FQDN of the server hosting Ivanti Discovery Services

    .Parameter Index
    The endpoint to query data for.  This parameter is not typically required.

    .Parameter IgnoreCertificate
    When provided the certificate chain will for the Discovery Server will not be validated
#>
function Measure-DiscoveryServicesRecord {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [string]$Index = 'device',

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreCertificate
    )

    Begin {
        Write-Debug -Message "Begin $($MyInvocation.MyCommand.Name)"
    }
    Process {
        $QueryURL = "https://$Server/discovery/api/v1/$Index/`$count"
        $ret = Invoke-DSRequest -Uri $QueryURL -IgnoreCertificate:$IgnoreCertificate.IsPresent
    }
    End {
        Write-Debug -Message "End $($MyInvocation.MyCommand.Name)"
        return $ret
    }
}

<#
    .Synopsis
    Returns records that meet the given criteria for the specified Ivanti Discovery Server

    .Description
    The Get-DiscoveryServicesItem cmdlet returns records that meet the given criteria for the specified Ivanti Discovery Server

    .Parameter Server
    The IP Address, hostname or FQDN of the server hosting Ivanti Discovery Services

    .Parameter Index
    The endpoint to query data for.  This parameter is not typically required

    .Parameter QueryParameters
    Additional filter and select parameters to send to the Discovery Server

    .Parameter IgnoreCertificate
    When provided the certificate chain will for the Discovery Server will not be validated

    .Outputs
    [System.Collections.Generic.Dictionary]
#>
function Get-DiscoveryServicesItem {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [string]$Index = 'device',

        [Parameter(Mandatory=$false)]
        [string]$QueryParameters = [string]::Empty,

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreCertificate
    )

    Begin {
        Write-Debug -Message "Begin $($MyInvocation.MyCommand.Name)"
    }
    Process {
        try {
            $QueryURL = "https://$Server/discovery/api/v1/$Index{0}" -f $(if ($QueryParameters) { "?$QueryParameters" } else { "" } )
            $ret = Invoke-DSRequest -Uri $QueryURL -IgnoreCertificate:$IgnoreCertificate.IsPresent
        } catch {
            throw $_
        }
    }
    End {
        Write-Debug -Message "End $($MyInvocation.MyCommand.Name)"
        return $ret
    }
}

<#
    .Synopsis
    Returns the next page of records available in the specified instance of Ivanti Discovery Services

    .Description
    The Step-DiscoveryServicesItem cmdlet returns the next page of records available in the specified instance of Ivanti Discovery Services.

    .Parameter StepLink
    This is the URI provided by the previous call to Get-DiscoveryServicesItem

    .Parameter IgnoreCertificate
    When provided the certificate chain will for the Discovery Server will not be validated

    .Outputs
    [System.Collections.Generic.Dictionary]
#>
function Step-DiscoveryServicesItem {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$StepLink,

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreCertificate
    )

    Begin {
        Write-Debug -Message "Begin $($MyInvocation.MyCommand.Name)"
    }
    Process {
        try {
            $ret = Invoke-DSRequest -Uri $StepLink -IgnoreCertificate:$IgnoreCertificate.IsPresent
        } catch [System.Net.WebException] {
            throw $_
        } catch {
            $ret = $false
        }
    }
    End {
        Write-Debug -Message "End $($MyInvocation.MyCommand.Name)"
        return $ret
    }
}

<#
    .Synopsis
    Retrieves results that match the given criteria on specified Ivanti Discovery Services server and creates a JSON file on the fie system

    .Description
    The Export-DiscoveryServicesItem cmdlet retrieves results that match the given criteria on specified Ivanti Discovery Services server and creates a JSON file on the fie system

    .Parameter Server
    The IP Address, hostname or FQDN of the server hosting Ivanti Discovery Services

    .Parameter FilePrefix
    The prefix to write files out with

    .Parameter OutputFile
    The full path to the consolidate file of results

    .Parameter OutputFolder
    The path to the folder that should contain all files created from the pages of results

    .Parameter Query
    Additional filter and select parameters to send to the Discovery Server

    .Parameter Paged
    When provided the results will not be consolidated into one file

    .Parameter IgnoreCertificate
    When provided the certificate chain will for the Discovery Server will not be validated

    .Outputs
    [System.Boolean]
    $true if the cmdlet completed successfully
#>
function Export-DiscoveryServicesItem {
    [CmdletBinding(DefaultParameterSetName='NotPaged')]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [string]$FilePrefix = 'results',

        [Parameter(Mandatory=$false)]
        [string]$Query = '$colset=all',

        [Parameter(Mandatory=$true, ParameterSetName='NotPaged')]
        [string]$OutputFile,

        [Parameter(Mandatory=$true, ParameterSetName='Paged')]
        [string]$OutputFolder,

        [Parameter(Mandatory=$false, ParameterSetName='Paged')]
        [switch]$Paged,

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreCertificate
    )

    Begin {
        Write-Debug -Message "Begin $($MyInvocation.MyCommand.Name)"
        $i = 1
        $total = 0
        $running_total = 0
        $progressId = 1
        $progressActivity = "Exporting Discovery Services items from $Server"
        [int]$percentComplete = 0
    }
    Process {
        try {
            New-Item -ItemType Directory -Path $script:TempPath -Force | Out-Null
            Write-Progress -Id $progressId -Activity $progressActivity -Status "Retrieving page $i" -PercentComplete $percentComplete -CurrentOperation "$percentComplete% complete"
            do {
                if ($i -eq 1) {
                    $res = Get-DiscoveryServicesItem -Server $Server -QueryParameters $Query -IgnoreCertificate:$IgnoreCertificate.IsPresent
                    if (-not $res) { throw $Error[0].Exception }
                    $total = $res."@odata.count"
                } else {
                    $res = Step-DiscoveryServicesItem -StepLink $nextURL -IgnoreCertificate:$IgnoreCertificate.IsPresent
                    if (-not $res) { throw $Error[0].Exception }
                }
                ConvertTo-Json -InputObject $res.value | Out-File -FilePath "$script:TempPath\$FilePrefix$i.json"
                $running_total += $res.value.length
                if ($res."@odata.nextLink") {
                    $nextURL = $res."@odata.nextLink"
                } else {
                    $nextURL = $null
                }
                $res = $null
                [GC]::Collect()
                $i++
                $percentComplete = ($running_total/$total)*100
                if (-not $Paged.IsPresent) {
                    $percentComplete = $percentComplete / 2
                }
                Write-Progress -Id $progressId -Activity $progressActivity -Status "Retrieving page $i" -PercentComplete $percentComplete -CurrentOperation "$percentComplete% complete"
            } until (-not $nextURL)
            if (-not $Paged.IsPresent) {
                $percentComplete = 50
                Write-Progress -Id $progressId -Activity $progressActivity -PercentComplete $percentComplete
            }

            # merge and cleanup
            if ($PSCmdlet.ParameterSetName -eq 'NotPaged') {
                Write-Progress -Id $progressId -Activity $progressActivity -Status "Cleaning up intermediary files" -PercentComplete $percentComplete
                $obj = @()
                Get-ChildItem $script:TempPath | Where { $_.Name.StartsWith($FilePrefix) -and $_.Name.EndsWith('.json') } | % { $obj += New-Object -TypeName PSObject -Property @{'FullName'=$_.FullName; 'SortKey'=[int] [regex]::Match($_.Name, "$FilePrefix(.*)\.json").Groups[1].Value} }
                $results = $obj | Sort -Property SortKey | Select -ExpandProperty FullName
                if ($results -is [string]) {
                    $results = @($results)
                }
                $obj = $null
                $i = 1
                Write-Progress -Id $progressId -Activity $progressActivity -Status "Cleaning up intermediary files" -PercentComplete $percentComplete -CurrentOperation "$percentComplete% complete"
                foreach ($r in $results) {
                    Write-Progress -Id $progressId -Activity $progressActivity -Status "Cleaning up intermediary files" -CurrentOperation $r -PercentComplete $percentComplete
                    if ($i -eq 1) {
                        if ($i -ne $results.length) {
                            $contents = (Get-Content $r) -replace ".{1}$", ","
                            [IO.File]::WriteAllText($OutputFile, $contents)
                        } else {
                            Copy-Item -Path $r -Destination $OutputFile -Force | Out-Null
                        }
                    } elseif ($i -eq $results.length) {
                        $contents = (Get-Content $r) -replace ".{1}$", "]"
                        $contents = $contents.Substring(1)
                        [IO.File]::AppendAllText($OutputFile, $contents)
                    } else {
                        $contents = (Get-Content $r) -replace ".{1}$", ","
                        $contents = $contents.Substring(1)
                        [IO.File]::AppendAllText($OutputFile, $contents)
                    }
                    $i++
                    Remove-Item -Path $r -Force | Out-Null
                    $percentComplete = ((($i/$results.length)*100) /2) + 50
                    if ($percentComplete -gt 100) {
                        $percentComplete = 100
                    }
                    Write-Progress -Id $progressId -Activity $progressActivity -Status "Cleaning up intermediary files" -CurrentOperation $r -PercentComplete $percentComplete
                }
            } elseif ($PSCmdlet.ParameterSetName -eq 'Paged') {
                New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
                Move-Item -Path "$script:TempPath\$FilePrefix*.json" -Destination $OutputFolder -Force | Out-Null
            }
            $ret = $true
        } catch [System.Net.WebException] {
            throw $_
        } catch {
            Write-Host $_.Exception
            $ret = $false
        } finally {
            Write-Progress -Id $progressId -Activity $progressActivity -Completed
        }
    }
    End {
        Write-Debug -Message "End $($MyInvocation.MyCommand.Name)"
        return $ret
    }
}

<#
    .Synopsis
    Retrieves the client ID that should be used for when requesting the OAuth2.0 access token

    .Description
    The Get-DiscoveryServicesClientId cmdlet retrieves the client ID that should be used for when requesting the OAuth2.0 access token

    .Parameter Server
    The IP Address, hostname or FQDN of the server hosting Ivanti Discovery Services

    .Notes
    This functionality is only available if the module is being used on the Discovery Services server itself.  It will error if not.

    .Outputs
    [System.String]
    The client ID for the Ivanti Discovery Server
#>
function Get-DiscoveryServicesClientId {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Server
    )

    Begin {
        Write-Debug -Message "Begin $($MyInvocation.MyCommand.Name)"
    }
    Process {
        if (-not (Test-DSServerIsMe -Server $Server)) { throw 'Cannot get the client ID for a remote server' }

        $IdentityPath = "$env:ProgramData\LANDesk\ServiceDesk\My.IdentityServer\IdentityServer3.Core.Models.Client.json"
        if (-not (Test-Path $IdentityPath)) { throw 'Cannot find the identity file for Discovery Services' }

        $json = ConvertFrom-Json (Get-Content -Raw -Path $IdentityPath)
        $json = $json | Where ClientName -eq 'Discovery'
        $ret = $json.ClientId
    }
    End {
        Write-Debug -Message "End $($MyInvocation.MyCommand.Name)"
        return $ret
    }
}

<#
    .Synopsis
    Retrieves the client secret that should be used for when requesting the OAuth2.0 access token

    .Description
    The Get-DiscoveryServicesClientSecret cmdlet retrieves the client secret that should be used for when requesting the OAuth2.0 access token

    .Parameter Server
    The IP Address, hostname or FQDN of the server hosting Ivanti Discovery Services

    .Notes
    This functionality is only available if the module is being used on the Discovery Services server itself.  It will error if not.

    .Outputs
    [System.String]
    The client secret for the Ivanti Discovery Server
#>
function Get-DiscoveryServicesClientSecret {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Server
    )

    Begin {
        Write-Debug -Message "Begin $($MyInvocation.MyCommand.Name)"
    }
    Process {
        if (-not (Test-DSServerIsMe -Server $Server)) { throw 'Cannot get the client secret for a remote server' }

        $IdentityPath = "$env:ProgramData\LANDesk\ServiceDesk\My.IdentityServer\IdentityServer3.Core.Models.Client.json"
        if (-not (Test-Path $IdentityPath)) { throw 'Cannot find the identity file for Discovery Services' }

        $json = ConvertFrom-Json (Get-Content -Raw -Path $IdentityPath)
        $json = $json | Where ClientName -eq 'Discovery'
        $json = $json.ClientSecrets
        $ret = ($json | Where { $_.Type.ToLower() -eq 'sharedsecret' -and $_.Description.ToLower() -eq 'discovery client secret' }).Value
    }
    End {
        Write-Debug -Message "End $($MyInvocation.MyCommand.Name)"
        return $ret
    }
}

Export-ModuleMember -Function *-DiscoveryServices*