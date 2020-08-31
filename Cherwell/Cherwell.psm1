function Test-Run {    
    Write-Host "Hello World"
}
function Verb-Noun {
    [CmdletBinding()]
    param ()
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
}

#Region BoilerPlate
function Set-CherwellConfig {
    [CmdletBinding()]
    param (     
        # Parameter help description
        [switch]
        $Create
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    Write-Verbose "Checking if CherwellConfig already defined"
    if (-not ($script:CherwellConfig)) {
        Write-Verbose "CherwellConfig not defined, creating CherwellConfig"
        $script:CherwellConfig = [hashtable]@{
            'Connected' = $false
        }
        return $script:CherwellConfig
    }
    else {
        Write-Verbose "CherwellConfig already defined"
        return $script:CherwellConfig
    }
}
function Get-CherwellConfig {
    [CmdletBinding()]
    param ()
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    Write-Verbose "Checking if CherwellConfig already defined"
    if (-not ($script:CherwellConfig)) {
        Write-Verbose "CherwellConfig not defined, calling Set-Config"
        return Set-Config -Create
    }
    else {
        Write-Verbose "CherwellConfig already defined"
        return $script:CherwellConfig
    }
}
function Set-CherwellHostName {
    [CmdletBinding()]
    param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Hostname
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $script:CherwellConfig.Hostname = $Hostname.Trim()
    return $script:CherwellConfig.Hostname
}
function Get-CherwellHostname {
    [CmdletBinding()]
    [OutputType([string])]
    param ()
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    if ($null -eq $script:CherwellConfig.Hostname) {
        throw "Cherwell Hostname is not set! You may set it with: Set-CherwellHostname -Hostname 'hostname.domain.tld'"
    }
    else {
        return $script:CherwellConfig.Hostname
    }
}
function Set-CherwellUsername {
    [CmdletBinding()]
    param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Username
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $script:CherwellConfig.Username = $Username.Trim()
    return $script:CherwellConfig.Username
}
function Get-CherwellUsername {
    [CmdletBinding()]
    [OutputType([string])]
    param ()
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    if (-not $script:CherwellConfig.Username) {
        throw "Cherwell Hostname is not set! You may set it with: Set-CherwellUsername -Username 'user'"
    }
    else {
        return $script:CherwellConfig.Username
    }
}
function Set-CherwellPassword {
    [CmdletBinding()]
    param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Password
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $script:CherwellConfig.Password = $Password
    return $script:CherwellConfig.Hostname
}
function Get-CherwellPassword {
    [CmdletBinding()]
    [OutputType([string])]
    param ()
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    if (-not $script:CherwellConfig.Password) {
        throw "Cherwell Password is not set! You may set it with: Set-CherwellPassword -Password 'password1'"
    }
    else {
        return $script:CherwellConfig.Password
    }
}
function Set-CherwellAuthenticationSource {
    [CmdletBinding()]
    param (
        # Parameter help description
        [ValidateSet('Internal', 'LDAP', IgnoreCase = $true)]
        [string]$AuthenticationSource = 'LDAP'
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $script:CherwellConfig.AuthenticationSource = $AuthenticationSource	
    return $script:CherwellConfig.AuthenticationSource
}
function Get-CherwellAuthenticationSource {
    [CmdletBinding()]
    [OutputType([string])]
    param ()
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    if (-not $script:CherwellConfig.AuthenticationSource) {
        throw "Cherwell Authentication Source not set! You may set with Set-CherwellAuthenticationSource -AuthenticationSource 'Internal'"
    }
    else {
        return $script:CherwellConfig.AuthenticationSource
    }
}
function Set-CherwellAPIKey {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $APIKey
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $script:CherwellConfig.APIKey = $APIKey.Trim()
    return $script:CherwellConfig.APIKey
}
function Get-CherwellAPIKey {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    if (-not $script:CherwellConfig.APIKey) {
        throw "Cherwell APIKey Source not set! You may set with Set-CherwellAPIKey"
    }
    else {
        return $script:CherwellConfig.APIKey
    }
}
function Set-CherwellToken {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [pscustomobject]$Token
    )	
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"	
    <# Typical token response
		{
		  "access_token": "REALLYLONGSTRING",
		  "token_type": "bearer",
		  "expires_in": 1199,
		  "refresh_token": "string",
		  "as:client_id": "client-id",
		  "username": "username",
		  ".issued": "Mon, 01 May 2017 15:33:19 GMT",
		  ".expires": "Mon, 01 May 2017 15:53:19 GMT"
		}
	#>
	
    # Convert some values to better types for easier manipulation
    Write-Verbose "Setting and converting token values to PS types"
    $script:CherwellConfig.Token = [pscustomobject]@{
        'AccessToken'  = $Token.access_token
        'TokenType'    = $Token.token_type
        'ExpiresIn'    = $Token.expires_in
        'RefreshToken' = $Token.refresh_token
        'AsClientId'   = $Token.'as:client_id'
        'Username'     = $Token.Username
        'Issued'       = [datetime]$Token.'.issued'
        'Expires'      = [datetime]$Token.'.expires'		
    }
    return $script:CherwellConfig.Token
}
function Get-CherwellToken {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ()
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    if (-not $script:CherwellConfig.Token) {
        throw "Cherwell Token not set! You must connect to a Cherwell API to set the token!"
    }
    else {        
        return $script:CherwellConfig.Token
    }
}
function Build-URI {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [string]
        $Hostname,
        
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [uint16]
        $Port = 443,
        
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [string[]]
        $Segments,
        
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable]
        $Parameters,
        
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [boolean]
        $HTTPS = $true,
        
        # Parameter help description
        [Parameter(Mandatory = $false)]
        [switch]
        $RequestToken = $false,
        
        # Parameter help description
        [switch]
        $V2,

        # Parameter help description
        [switch]
        $V3
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"

    if (-not $Hostname) {
        $Hostname = Get-CherwellHostname
    }
    
    if (-not $HTTPS) {
        Write-Warning "Using HTTP is insecure and credentials are passed in clear text. Please consider utilizing HTTPS."
    }

    # Begin a URI builder with HTTP/HTTPS and the provided hostname
    $uriBuilder = [System.UriBuilder]::new($(if ($HTTPS) { 'https' } else { 'http' }), $Hostname, $port)

    if ($RequestToken) {
        # Requesting a token uses a different path from the regular API
        $uriBuilder.Path = "CherwellAPI/token"
        Write-Verbose "This is a token URI using: $($uriBuilder.Path)"
    }
    else {
        # Generate the path by trimming excess slashes and whitespace from the $segments[] and joining together
        $uriBuilder.Path = "CherwellAPI/api/{0}/{1}" -f $(if ($V2) { 'v2' } elseif ($V3) { 'v3' } else { 'v1' }), ($Segments.ForEach( { $_.trim('/').trim() }) -join '/')
        Write-Verbose "This is a normal URI using: $($uriBuilder.Path)"
    }
    
    if ($parameters) {
        Write-Verbose "Adding parameters to URIBuilder"
        # Loop through the parameters and use the HttpUtility to create a Query string
        $URIParams = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
		
        foreach ($param in $Parameters.GetEnumerator()) {
            $URIParams[$param.Key] = $param.Value
            Write-Verbose "Added $($param.Key):$($param.Value)"
        }
		
        $uriBuilder.Query = $URIParams.ToString()
    }

    return $uriBuilder
}
function Invoke-CherwellRequest {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [System.UriBuilder]
        $URI,
    
        # Parameter help description
        [Hashtable]
        $Headers = @{ },

        # Parameter help description
        [hashtable]
        $Body = $null,
    
        # Parameter help description
        [AllowNull()]
        [System.Nullable[int32]]
        $Timeout,
    
        # Parameter help description
        [ValidateSet('GET', 'PATCH', 'PUT', 'POST', 'DELETE', IgnoreCase = $true)]
        [string]
        $Method = 'GET',
    
        # Parameter help description
        [ValidateSet('application/json', 'application/x-www-form-urlencoded', IgnoreCase = $true)]
        [string]
        $ContentType = "application/json",
    
        # Parameter help description
        [switch]
        $BypassAuthorizationHeader,
    
        # Parameter help description
        [switch]
        $RequestToken
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    Write-Verbose "Building request invocation"
    # Determine if we need to obtain the timeout value or set it to maximum
    if ($Timeout -eq $null) {
        $Timeout = 120
        Write-Verbose "Timeout not provided.. Setting timeout to default: 120"
    } 
    elseif ($Timeout -eq 0) {
        Write-Warning "Timeout value set to maximum!"
        $Timeout = [int32]::MaxValue
    }

    if ($RequestToken) {
        Write-Verbose "Skipping authorization header check, as this is a request to get authorization"
    } 
    else {
        if (-not $BypassAuthorizationHeader) {
            # We are NOT bypassing the authorization header check
            if (-not $Headers.Authorization) {
                # Add the Authorization header if it does not exist
                Write-Verbose 'Authorization headers missing, Adding authorization to headers'
                if ($script:CherwellConfig.Token.Expires -lt (Get-Date)) {
                    Write-Verbose "The token has expired, sending for refresh"
                    Set-CherwellToken -Token (Request-Token)                    
                }
                $Headers.Add('Authorization', ("Bearer {0}" -f (Get-CherwellToken).AccessToken))
            }
        }
    }

    $splat = @{
        'Method'      = $Method
        'Uri'         = $URI.Uri.AbsoluteUri # This property auto generates the scheme, hostname, path, and query
        'Headers'     = $Headers
        'TimeoutSec'  = $Timeout
        'ContentType' = $ContentType
        'ErrorAction' = 'Stop'
        'Verbose'     = $VerbosePreference
    }

    if ($Body) {
        if ($ContentType -eq 'application/json') {
            Write-Verbose "Converting body to JSON"
            $null = $splat.Add('Body', ($Body | ConvertTo-Json -Compress))
            Write-Verbose "JSON Body: $($splat.Body)"
        } 
        else {
            Write-Verbose "Using x-www-form-urlencoded body"
            $null = $splat.Add('Body', $Body)
        }
		
        # Pretty hashtable verbose output
        $columnWidth = $body.Keys.length | Sort-Object | Select-Object -Last 1
        Write-Verbose "Body hashtable:"
        $Body.GetEnumerator() | ForEach-Object {
            if ($_.Key -eq 'password') {
                Write-Verbose ("  {0,-$columnWidth} : {1}" -F $_.Key, '***HIDDEN***')
            } 
            else {
                Write-Verbose ("  {0,-$columnWidth} : {1}" -F $_.Key, $_.Value)
            }
        }
    }

    if (($Method -eq 'POST') -and $Body) {
        Write-Verbose "A -1-byte payload is expected in the verbose output below!"
    }
	
    $timestamp = (Get-Date)
    $results = Invoke-RestMethod @splat

    # TODO Add some Error Handling to give the user an idea what is broke?

    Write-Verbose "Response received and parsed in $((Get-Date) - $timestamp)"
	
    return $results
}
function Request-Token {
    [CmdletBinding()]
    param (
        # Parameter help description
        [switch]
        $Refresh
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $uri = Build-URI -RequestToken -Parameters @{
        'api_key'   = (Get-CherwellAPIKey)
        'auth_mode' = (Get-CherwellAuthenticationSource)
    }    
    $header = @{
        "Accept"       = "application/json"
        "Content-Type" = "application/x-www-form-urlencoded"
    }
    if (-not $Refresh) {
        $body = @{
            "grant_type" = "password"
            "client_id"  = (Get-CherwellAPIKey)
            "username"   = (Get-CherwellUserName)
            "password"   = (Get-CherwellPassword)
        }
    }
    else {
        $body = @{
            "grant_type"    = "refresh_token"
            "client_id"     = (Get-CherwellAPIKey)
            "refresh_token" = (Get-CherwellToken).RefreshToken
        }
    }
    
    return Invoke-CherwellRequest -URI $uri -Headers $header -Body $body -Method POST -RequestToken -ContentType application/x-www-form-urlencoded
}
function Connect-CherwellAPI {
    [OutputType([boolean])]
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $Hostname,
    
        # Parameter help description
        [ValidateSet('Internal', 'LDAP', IgnoreCase = $true)]
        [string]
        $AuthenticationSource = 'LDAP',
    
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $APIKey,
    
        # Parameter help description
        #[boolean]
        #$AutoRefreshToken = $true,
    
        # Parameter help description
        [int32]
        $Timeout = 60,

        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $Username,

        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $Password
    
        # Parameter help description
        #[boolean]
        #$InstantiateCache = $true

        # Add Parameter for HTTPS and Port overrides
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"

    Write-Progress -Id 1 -Activity "Connecting to CherwellAPI at $Hostname" -PercentComplete 10 -CurrentOperation "Configuring Environment"

    $null = Set-CherwellConfig -Create
    $null = Set-CherwellHostName -Hostname $Hostname
    $null = Set-CherwellAuthenticationSource -AuthenticationSource $AuthenticationSource
    $null = Set-CherwellUsername -Username $Username
    $null = Set-CherwellPassword -Password $Password
    $null = Set-CherwellAPIKey -APIKey $APIKey

    Write-Progress -Id 1 -Activity "Connecting to CherwellAPI at $Hostname" -PercentComplete 50 -CurrentOperation "Obtaining Token"

    # Try to obtain a token from the service
    try {		
        $token = Request-Token -ErrorAction Stop
        $null = Set-CherwellToken -Token $token
		
        Write-Progress -Id 1 -Activity "Connecting to CherwellAPI at $Hostname" -Completed
		
        $script:CherwellConfig.Connected = $true
        return $script:CherwellConfig.Connected
    } 
    catch {
        if ($_.Response) {
            try {
                $result = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($result)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd() | ConvertFrom-Json
				
                switch ($responseBody.error) {
                    'invalid_grant' {
                        throw "Invalid username/password provided"
                        break
                    }
					
                    'invalid_client_id' {
                        throw $responseBody.error_description
                        break
                    }
					
                    default {
                        throw $_
                    }
                }
            } 
            catch {
                throw $_
            }
        } 
        else {
            throw $_
        }
    }
}
#EndRegion BoilerPlate

#Region HelperFunctions
function Set-FieldValue {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [pscustomobject]
        $Field,

        # Parameter help description
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $Value,

        # Parameter help description
        [Parameter(Mandatory = $false, Position = 2)]
        [nullable[bool]]
        $HTML = $false
    )
    Begin {
        Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    }
    Process {
        # Check there is a value and dirty property in the field object, without these the field won't work anyways.
        if (-not ($Field.psobject.properties.name -contains 'value')) {
            throw "'Value' property missing from field object"
        }
        elseif (-not ($Field.psobject.properties.name -contains 'dirty')) {
            throw "'Dirty' property missing from field object"
        }

        if ($Field.value -ne $Value) {
            Write-Verbose "Updating value to: $Value"
            $Field.value = $Value
            $Field.dirty = $true
        }
        else {
            Write-Verbose "Value not changed, it is already set to: $($Field.value)"
        }

        #Implement HTML support
        if ($HTML -eq $true) {
            $Field.html = $true
        }
        elseif ($HTML -eq $false) {
            $Field.html = $false
        }
        elseif ($HTML -eq $null -and $Value -match '<\S.*>') {
            $Field.html = $true
        }
        else {
            $Field.html = $false
        }
    }
    End {

    }    
}
#Get-FieldValue?
function New-Field {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $DisplayName,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $FieldId,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $Name,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $Value,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [bool]
        $Dirty,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [bool]
        $HTML
    )

    return @{
        'dirty'       = $Dirty
        'displayName' = $DisplayName
        'fieldId'     = $FieldId
        'name'        = $Name
        'value'       = $Value
        'html'        = $HTML
    }
}
#EndRegion HelperFunctions

#Region BusinessObject
function Get-BusinessObjectSummariesByType {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'Major', 'Supporting', 'Lookup', 'Groups', IgnoreCase = $true)]
        [string]
        $Type,
        # Parameter help description
        [switch]
        $Force
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"    
    $uri = Build-URI -Segments 'getbusinessobjectsummaries', 'type', $Type
    # Create some caching here, use force parameter to override using cache
    return Invoke-CherwellRequest -uri $uri
}
function Get-BusinessObjectSummary {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(ParameterSetName = 'ById', Mandatory = $true)]
        [Alias('BusObId')]
        [string]
        $BusinessObjectId,

        # Parameter help description
        [Parameter(ParameterSetName = 'ByName', Mandatory = $true)]
        [Alias('BusObName')]
        [string]
        $BusinessObjectName    
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    switch ($PsCmdlet.ParameterSetName) {
        'ById' {
            $uri = Build-URI -Segments 'getbusinessobjectsummary', 'busobid', $BusinessObjectId
            return Invoke-CherwellRequest -uri $uri
        }
        'ByName' {
            $uri = Build-URI -Segments 'getbusinessobjectsummary', 'busobname', $BusinessObjectName
            return Invoke-CherwellRequest -uri $uri
        }
    }
}
function Get-BusinessObjectSummaryById {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [Alias('BusObId')]
        [string]
        $BusinessObjectId
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $uri = Build-URI -Segments 'getbusinessobjectsummary', 'busobid', $BusinessObjectId

    return Invoke-CherwellRequest -uri $uri
}
function Get-BusinessObjectSummaryByName {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [Alias('BusObName')]
        [string]
        $BusinessObjectName        
    )    
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $uri = Build-URI -Segments 'getbusinessobjectsummary', 'busobname', $BusinessObjectName
    return Invoke-CherwellRequest -uri $uri
}
function Get-BusinessObjectSchema {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(ParameterSetName = 'ById', Mandatory = $true)]
        [Alias('BusObId')]
        [string]
        $BusinessObjectId,
        
        # Parameter help description
        [Parameter(ParameterSetName = 'ByName', Mandatory = $true)]
        [Alias('BusObName')]
        [string]
        $BusinessObjectName    
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"

    if ($IncludeRelationships) {
        $uriParameters = @{
            'includerelationships' = $true
        }
    }
    switch ($PsCmdlet.ParameterSetName) {
        'ById' {
            $uri = Build-URI -Segments @('getbusinessobjectschema', 'busobid', $BusinessObjectId) -Parameters $uriParameters
            return Invoke-CherwellRequest -uri $uri
        }
        'ByName' {
            $BusOb = Get-BusinessObjectSummary -BusObName $BusinessObjectName
            $uri = Build-URI -Segments @('getbusinessobjectschema', 'busobid', $BusOb.BusObId) -Parameters $uriParameters
            return Invoke-CherwellRequest -uri $uri
        }
    }
}
function Get-BusinessObjectSchemaById {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [Alias('BusObId')]
        [string]
        $BusinessObjectId,
        # Parameter help description
        [switch]
        $IncludeRelationships
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    if ($IncludeRelationships) {
        $uriParameters = @{
            'includerelationships' = $true
        }
    }
    $uri = Build-URI -Segments @('getbusinessobjectschema', 'busobid', $BusinessObjectId) -Parameters $uriParameters
    return Invoke-CherwellRequest -URI $uri
}
function Get-BusinessObjectSchemaByName {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [Alias('BusObName')]
        [string]
        $BusinessObjectName,

        # Parameter help description
        [switch]
        $IncludeRelationships
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    if ($IncludeRelationships) {
        $uriParameters = @{
            'includerelationships' = $true
        }
    }
    $BusOb = Get-BusinessObjectSummaryByName -BusObName $BusinessObjectName
    $uri = Build-URI -Segments @('getbusinessobjectschema', 'busobid', $BusOb.BusObId) -Parameters $uriParameters
    return Invoke-CherwellRequest -URI $uri
}
function Get-BusinessObjectTemplate {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true, ParameterSetName = 'SpecificFieldsById')]
        [Parameter(Mandatory = $true, ParameterSetName = 'AllFieldsById')]
        [Parameter(Mandatory = $true, ParameterSetName = 'RequiredFieldsById')]
        [Alias('BusObId')]
        [string]
        $BusinessObjectId,

        # Parameter help description
        [Parameter(Mandatory = $true, ParameterSetName = 'SpecificFieldsByName')]
        [Parameter(Mandatory = $true, ParameterSetName = 'AllFieldsByName')]
        [Parameter(Mandatory = $true, ParameterSetName = 'RequiredFieldsByName')]
        [Alias('BusObName')]
        [string]
        $BusinessObjectName,
        
        # Parameter help description
        [Parameter(Mandatory = $true, ParameterSetName = 'SpecificFieldsById')]
        [Parameter(Mandatory = $true, ParameterSetName = 'SpecificFieldsByName')]
        [string[]]
        $FieldNames,
        
        # Parameter help description
        [Parameter(Mandatory = $true, ParameterSetName = 'AllFieldsById')]
        [Parameter(Mandatory = $true, ParameterSetName = 'AllFieldsByName')]
        [switch]
        $IncludeAllFields,
        
        # Parameter help description
        [Parameter(Mandatory = $true, ParameterSetName = 'RequiredFieldsById')]
        [Parameter(Mandatory = $true, ParameterSetName = 'RequiredFieldsByName')]
        [switch]
        $IncludeRequiredFields
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $uri = Build-URI -Segments 'getbusinessobjecttemplate'
    $body = @{}

    Write-Verbose $PsCmdlet.ParameterSetName

    switch ($PsCmdlet.ParameterSetName) {
        'SpecificFieldsById' {
            $body.Add('busObId', $BusinessObjectId)
            $body.Add('fieldNames', [System.Collections.ArrayList]::new($FieldNames))
            break
        }
        'SpecificFieldsByName' {
            $BusOb = Get-BusinessObjectSummary -BusObName $BusinessObjectName
            $body.Add('busObId', $BusOb.BusObId)
            $body.Add('fieldNames', [System.Collections.ArrayList]::new($FieldNames))
            break
        }
        'AllFieldsById' {
            $body.Add('busObId', $BusinessObjectId)
            $body.Add('includeAll', $true)
            break
        }
        'AllFieldsByName' {
            $BusOb = Get-BusinessObjectSummary -BusObName $BusinessObjectName
            $body.Add('busObId', $BusOb.BusObId)
            $body.Add('includeAll', $true)
            break
        }
        'RequiredFieldsById' {
            $body.Add('busObId', $BusinessObjectId)
            $body.Add('includeRequired', $true)
            break
        }
        'RequiredFieldsByName' {
            $BusOb = Get-BusinessObjectSummary -BusObName $BusinessObjectName
            $body.Add('busObId', $BusOb.BusObId)
            $body.Add('includeRequired', $true)
            break
        }
    }
    Invoke-CherwellRequest -URI $uri -Body $body -Method POST
}
function Get-BusinessObjectTemplateById {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('BusObId')]
        [string]
        $BusinessObjectId,

        # Parameter help description
        [Parameter(Mandatory = $true, ParameterSetName = 'SpecificFields')]
        [string[]]
        $FieldNames,

        # Parameter help description
        [Parameter(Mandatory = $true, ParameterSetName = 'AllFields')]
        [switch]
        $IncludeAllFields,

        # Parameter help description
        [Parameter(Mandatory = $true, ParameterSetName = 'RequiredFields')]
        [switch]
        $IncludeRequiredFields
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $uri = Build-URI -Segments 'getbusinessobjecttemplate'
    $body = @{
        'busObId' = $BusinessObjectId
    }
    switch ($PsCmdlet.ParameterSetName) {
        'SpecificFields' {
            $body.Add('fieldNames', [System.Collections.ArrayList]::new($FieldNames))
            break
        }
        'AllFields' {
            $body.Add('includeAll', $true)
            break
        }
        'RequiredFields' {
            $body.Add('includeRequired', $true)
            break
        }
    }
    Invoke-CherwellRequest -URI $uri -Body $body -Method POST
}
function Get-BusinessObjectById {
    [CmdletBinding(DefaultParameterSetName = 'RecId')]
    [OutputType([pscustomobject], ParameterSetName = 'RecId')]
    [OutputType([pscustomobject], ParameterSetName = 'PublicId')]
    [OutputType([pscustomobject])]

    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        [Alias('BusObId')]
        $BusinessObjectId,

        # Parameter help description
        [Parameter(ParameterSetName = 'RecId', Mandatory = $true)]
        [Alias('RecId', 'BusObRecId')]
        [string]
        $BusinessObjectRecId,

        # Parameter help description
        [Parameter(ParameterSetName = 'PublicId', Mandatory = $true)]
        [Alias('PublicId', 'BusObPublicId')]
        [string]
        $BusinessObjectPublicId
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    switch ($PsCmdlet.ParameterSetName) {
        'RecId' {
            $uri = Build-URI -Segments 'getbusinessobject', 'busobid', $BusinessObjectId, 'busobrecid', $BusinessObjectRecordId
            break
        }
        'PublicId' {
            $uri = Build-URI -Segments 'getbusinessobject', 'busobid', $BusinessObjectId, 'publicid', $BusinessObjectPublicId
            break
        }
    }
    return Invoke-CherwellRequest -uri $uri
}
function New-BusinessObjectById {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('BusObId')]
        [string]        
        $BusinessObjectId,
        
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [pscustomobject[]]
        $Fields
    )
    Begin {
        Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
        $uri = Build-URI -Segments 'savebusinessobject'
    }
    Process {
        $body = @{
            'busObId' = $BusinessObjectId
            'fields'  = $Fields
        }		
        Invoke-CherwellRequest -URI $uri -Body $body -Method POST
    }
    End {

    }
}
function Update-BusinessObjectById {
    [CmdletBinding(DefaultParameterSetName = 'RecId')]
    [OutputType([pscustomobject], ParameterSetName = 'RecId')]
    [OutputType([pscustomobject], ParameterSetName = 'PublicId')]
    [OutputType([pscustomobject])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('BusObId')]
        [string]
        $BusinessObjectId,
        
        # Parameter help description
        [Parameter(Mandatory = $true, ParameterSetName = 'RecId', ValueFromPipelineByPropertyName = $true)]
        [Alias('BusObRecId', 'RecId')]
        [string]
        $BusinessObjectRecordId,
        
        # Parameter help description
        [Parameter(Mandatory = $true, ParameterSetName = 'PublicId', ValueFromPipelineByPropertyName = $true)]
        [Alias('BusObPublicId', 'PublicId')]
        [string]
        $BusinessObjectPublicId,
        
        # Parameter help description
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [pscustomobject[]]
        $Fields
    )
    Begin {
        Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
        $uri = Build-URI -Segments 'savebusinessobject'        
    }
    Process {
        $body = @{
            'busObId' = $BusinessObjectId
            'fields'  = $fields
        }
        switch ($PsCmdlet.ParameterSetName) {
            'RecId' {
                $body.Add('busObRecId', $BusinessObjectRecordId)
                break
            }
            'PublicId' {
                $body.Add('busObPublicId', $BusinessObjectPublicId)
                break
            }
        }		
        return Invoke-CherwellRequest -URI $uri -Body $body -Method POST
    }
    End {

    }
}
#EndRegion BusinessObject

#Region Core
#EndRegion Core

#Region Forms
#EndRegion Form

#Region Queues
#EndRegion Queues

#Region Searches
function Get-SearchItemsAdHoc {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('BusObId')]
        [string]
        $BusinessObjectID,
        
        # Parameter help description
        [string[]]
        $Fields,
        
        # Parameter help description
        [switch]
        $IncludeAllFields,
        
        # Parameter help description
        [uint16]
        $PageSize = [uint16]::MaxValue,
        
        # Parameter help description
        [uint32]
        $PageNumber,
        
        # Parameter help description
        [int32]
        $Timeout,
        
        # A collection of FilterInfo data structures. A FilterInfo contains the full field ID, operator and value. You can specify more than one filter. If you add multiple filters for the same field ID, the result is an OR operation between those fields. If the field IDs are different, the result is an AND operation between those fields
        [hashtable[]]
        $Filters,
        
        # Parameter help description
        [switch]
        $IncludeSchema
    )
    Begin {
        Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
        $uri = Build-URI -Segments 'getsearchresults'
        $body = @{
            'busObId'  = $null
            "pageSize" = $PageSize
        }
        if ($PageSize) {
            $body.Add('pageNumber', $PageNumber)
        }
		
        if ($IncludeAllFields) {
            $body.Add('includeAllFields', $true)
        } 
        elseif ($Fields) {
            $body.Add('fields', [System.Collections.ArrayList]::new())
            foreach ($field in $Fields) {
                $null = $body.Fields.Add($field)
            }
        }
		
        if ($Filters) {
            $body.Add('filters', [System.Collections.ArrayList]::new())
            foreach ($filter in $filters) {
                $null = $body.filters.add($filter)
            }
        }
		
        if ($IncludeSchema) {
            $body.Add('includeSchema', $true)
        }
		
        if (-not $Timeout) {
            $Timeout = 120
        }
    }    
    Process {
        $body.busObId = $BusinessObjectID
			
        try {
            Invoke-CherwellRequest -URI $uri -Body $body -Method POST -Timeout $Timeout
        }
        catch {
            if ($_.ErrorDetails.Message -match "The Business Object is not configured for searching") {
                $eSplat = @{
                    'Message'           = "The Business Object $BusinessObjectID is not configured for searching."
                    'Category'          = $_.CategoryInfo.Category
                    'CategoryActivity'  = $_.CategoryInfo.Activity
                    'CategoryReason'    = $_.CategoryInfo.Reason
                    'TargetObject'      = $_.TargetObject
                    'RecommendedAction' = "Configure the object $BusinessObjectID for searching in Cherwell Administrator"
                }
                Write-Error @eSplat
            }
            else {
                Write-Error -ErrorRecord $_
            }
        }
    }
    End {

    }
}
function Convert-SearchResultsToArray {
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [pscustomobject[]]
        $BusinessObjects
    )	
    BEGIN {
        $list = [System.Collections.ArrayList]::new()
    }	
    PROCESS {
        foreach ($obj in $businessObjects) {
            $listObject = @{}
			
            foreach ($field in $obj.fields) {
                $listObject[$field.Name] = $field.value
            }			
            $null = $list.Add([pscustomobject]$listObject)
        }
    }	
    END {
        , $list # Use comma to force System.Collections.ArrayList
    }
}
function New-SearchFilter {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $FieldId,

        # Parameter help description
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateSet('eq', 'gt', 'lt', 'StartsWith', 'Contains', IgnoreCase = $true)]
        [string]
        $Operator,

        # Parameter help description
        [Parameter(Mandatory = $true, Position = 2)]
        [string]
        $Value
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    return @{
        'fieldId'  = $FieldId
        'operator' = $Operator
        'value'    = $Value
    }
}
#EndRegion Searches

#Region Security
#EndRegion Security

#Region Service
#EndRegion Service

#Region Teams
function Get-Teams {
    [CmdletBinding()]
    param (        
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"
    $uri = Build-URI -Segments 'getteams'
    # Create some caching here, use force parameter to override using cache
    return Invoke-CherwellRequest -uri $uri
}
function Get-TeamByName {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [string]
        $TeamName
    )
    Write-Verbose "$($PSCmdlet.MyInvocation.InvocationName) called"

    $Teams = Get-Teams
    $Team = $Teams.teams | Where-Object { $_.teamName -eq "${TeamName}" }

    $uri = Build-URI -Segments 'getteam', $Team.TeamId
    return Invoke-CherwellRequest -uri $uri
}
#EndRegion Teams

#Region Users
#EndRegion Users

Export-ModuleMember "*"
