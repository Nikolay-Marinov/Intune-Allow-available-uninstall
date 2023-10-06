<#
.SYNOPSIS
    Enables the "Allow available uninstall" application Feature from Intune for all applications within a tenant, using Microsoft Graph API.

.DESCRIPTION
    This script Enables the "Allow available uninstall" application Feature from Intune using Microsoft Graph API. It generates an access token for Microsoft Graph API using a certificate and then uses the access token to authenticate requests to the Microsoft Graph API.

.PARAMETER TenantId
    The ID of the tenant for which the access token is generated.

.PARAMETER ApplicationId
    The ID of the application for which the access token is generated.

.PARAMETER CertificateThumbprint
    The thumbprint of the certificate used to generate the access token.

.EXAMPLE
    PS C:\> .\Intune-Enable-Uninstall-on-Demand.ps1 -TenantId "contoso.onmicrosoft.com" -ApplicationId "00000000-0000-0000-0000-000000000000" -CertificateThumbprint "1234567890abcdef1234567890abcdef12345678"

.NOTES
    This script requires the Azure Active Directory PowerShell module to be installed.
    Author: Nikolay Marinov
    Version: 1.0.0
    Date: 2023-10-06

    DISCLAIMER !!! 
    You running this script/function means you will not blame the author(s) if this breaks your stuff. 
    This script/function is provided AS IS without warranty of any kind. Author(s) disclaim all implied 
    warranties including, without limitation, any implied warranties of merchantability or of fitness for 
    a particular purpose. The entire risk arising out of the use or performance of the sample scripts and
     documentation remains with you. In no event shall author(s) be held liable for any damages whatsoever 
     (including, without limitation, damages for loss of business profits, business interruption, loss of 
     business information, or other pecuniary loss) arising out of the use of or inability to use the script
      or documentation. Neither this script/function, nor any part of it other than those parts that are 
      explicitly copied from others, may be republished without author(s) express written permission. 
      Author(s) retain the right to alter this disclaimer at any time. 
      or the most up to date version of the disclaimer, see https://ucunleashed.com/code-disclaimer.

.LINK
    https://configroar.com/?p=534
#>
[CmdletBinding()]
param (
    [Parameter()]
    $tenantId = "",

    [Parameter()]
    $applicationId = "",

    [Parameter()]
    $certificateThumbprint = ""
)

#region functions
<#
.SYNOPSIS
    Ref: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate
    Generates an access token for Microsoft Graph API using a certificate.

.DESCRIPTION
    This function generates an access token for Microsoft Graph API using a certificate. The access token is used to authenticate requests to the Microsoft Graph API.

.PARAMETER TenantID
    The ID of the tenant for which the access token is generated.

.PARAMETER AppId
    The ID of the application for which the access token is generated.

.PARAMETER CertificateThumbprint
    The thumbprint of the certificate used to generate the access token.

.PARAMETER Scope
    The scope of the access token. The default value is "https://graph.microsoft.com/.default".

.EXAMPLE
    PS C:\> Get-AuthTokenwithCertificate -TenantID "contoso.onmicrosoft.com" -AppId "00000000-0000-0000-0000-000000000000" -CertificateThumbprint "1234567890abcdef1234567890abcdef12345678"

    This example generates an access token for the specified tenant, application, and certificate.

.OUTPUTS
    The function returns an access token that can be used to authenticate requests to the Microsoft Graph API.

.NOTES
    This function requires the Azure Active Directory PowerShell module to be installed.

.LINK
    https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate
#>
Function Get-AuthTokenwithCertificate {

    [CmdletBinding()]
    param (
        [Parameter()]
        $TenantID,

        [Parameter()]
        $AppId,
        
        [Parameter()]
        $CertificateThumbprint,

        [Parameter()]
        $Scope = "https://graph.microsoft.com/.default"
    )

    $Certificate = Get-Item Cert:\CurrentUser\My\$CertificateThumbprint 
  
    # Create base64 hash of certificate  
    $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())  
  
    # Create JWT timestamp for expiration  
    $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()  
    $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds  
    $JWTExpiration = [math]::Round($JWTExpirationTimeSpan, 0)  
  
    # Create JWT validity start timestamp  
    $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds  
    $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan, 0)  
  
    # Create JWT header  
    $JWTHeader = @{  
        alg = "RS256"  
        typ = "JWT"  
        # Use the CertificateBase64Hash and replace/strip to match web encoding of base64  
        x5t = $CertificateBase64Hash -replace '\+', '-' -replace '/', '_' -replace '='  
    }  
  
    # Create JWT payload  
    $JWTPayLoad = @{  
        # What endpoint is allowed to use this JWT  
        aud = "https://login.microsoftonline.com/$TenantID/oauth2/token"  
  
        # Expiration timestamp  
        exp = $JWTExpiration  
  
        # Issuer = your application  
        iss = $AppId  
  
        # JWT ID: random guid  
        jti = [guid]::NewGuid()  
  
        # Not to be used before  
        nbf = $NotBefore  
  
        # JWT Subject  
        sub = $AppId  
    }  
  
    # Convert header and payload to base64  
    $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))  
    $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)  
  
    $JWTPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))  
    $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)  
  
    # Join header and Payload with "." to create a valid (unsigned) JWT  
    $JWT = $EncodedHeader + "." + $EncodedPayload  
  
    # Get the private key object of your certificate  
    $PrivateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate))  
  
    # Define RSA signature and hashing algorithm  
    $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1  
    $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256  
  
  
    # Create a signature of the JWT  
    $Signature = [Convert]::ToBase64String(  
        $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT), $HashAlgorithm, $RSAPadding)  
    ) -replace '\+', '-' -replace '/', '_' -replace '='  
  
    # Join the signature to the JWT with "."  
    $JWT = $JWT + "." + $Signature  
  
    # Create a hash with body parameters  
    $Body = @{  
        client_id             = $AppId  
        client_assertion      = $JWT  
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"  
        scope                 = $Scope  
        grant_type            = "client_credentials"  
  
    }  
  
    $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"  
  
    # Use the self-generated JWT as Authorization  
    $Header = @{  
        Authorization = "Bearer $JWT"  
    }  
  
    # Splat the parameters for Invoke-Restmethod for cleaner code  
    $PostSplat = @{  
        ContentType = 'application/x-www-form-urlencoded'  
        Method      = 'POST'  
        Body        = $Body  
        Uri         = $Url  
        Headers     = $Header  
    }  
  
    $Request = Invoke-RestMethod @PostSplat  

    # View access_token  
    $Request.access_token

    return $Request 
}

<#
.SYNOPSIS
    Gets all Intune Win32 Apps in the tenant.
.DESCRIPTION
    This function retrieves all Intune Win32 Apps in the tenant using the Microsoft Graph API.
.PARAMETER None
.EXAMPLE
    Get-AllIntuneWin32Apps
.NOTES
    Author: Nikolay Marinov
#>
function Get-AllIntuneWin32Apps {
    #Write-Host "Getting all Intune Win32 Apps in the tenant" -ForegroundColor Yellow

    #$graphApiVersion = "beta"
    #$DMS_resource = "deviceAppManagement/mobileApps"
    #Write-Host "Resource: $DMS_resource"

    try {
        $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=(isof('microsoft.graph.win32LobApp'))&`$select=displayName,id"
        write-host $uri
        $objdevmgmtscripts = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get -ContentType "application/json"
        return $objdevmgmtscripts
    }

    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break

    }
}

<#
.SYNOPSIS
    Gets a specific Intune Win32 app in the tenant with the specified ID.
.PARAMETER appid
    The ID of the Intune Win32 app to retrieve.
.EXAMPLE
    Get-IntuneWin32App -appid "12345678-90ab-cdef-ghij-klmnopqrstuv"
#>
function Get-IntuneWin32App {
    param(
        $appid
    )


    #Write-Host "Getting specific Intune Win32 Apps in the tenant with id: $appid" -ForegroundColor Yellow

    $graphApiVersion = "beta"
    $DMS_resource = "deviceAppManagement/mobileApps/$appid"
    #Write-Host "Resource: $DMS_resource"

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$DMS_resource"
        #write-host $uri
        $objdevmgmtscripts = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get -ContentType "application/json"
        return $objdevmgmtscripts
    }

    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break

    }
}

<#
.SYNOPSIS
    Enables the ability to uninstall an IntuneWin32App with the specified id.
.DESCRIPTION
    This function enables the ability to uninstall an IntuneWin32App with the specified id by setting the "allowAvailableUninstall" property to $true.
.PARAMETER appid
    The id of the IntuneWin32App to enable uninstall for.
.EXAMPLE
    Enable-IntuneWin32AppUninstall -appid "12345678-90ab-cdef-ghij-klmnopqrstuv"
    This example enables the ability to uninstall the IntuneWin32App with the id "12345678-90ab-cdef-ghij-klmnopqrstuv".
#>
function Enable-IntuneWin32AppUninstall {

    param(
        $appid
    )
    
    Write-host "Enabling IntuneWin32App with id: $appid to allow uninstall" -ForegroundColor Yellow

    $graphApiVersion = "beta"
    $DMS_resource = "deviceAppManagement/mobileApps/$appid"

    $body = @{
        "@odata.type"             = "#microsoft.graph.win32LobApp"
        "allowAvailableUninstall" = $true
    }

    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$DMS_resource"
        #write-host $uri
        $objdevmgmtscripts = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -ContentType "application/json" -Body ($body | ConvertTo-Json)
        return $objdevmgmtscripts
    }

    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break

    }
}
#endregion


Add-Type -AssemblyName System.Web
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#$err = 0

$connectionDetails = @{
    'TenantId'              = "$($tenantid)"
    'AppId'                 = "$($applicationid)"
    'certificateThumbprint' = "$($certificateThumbprint)"
}

$acctoken = Get-AuthTokenwithCertificate @connectionDetails

$token = $acctoken.access_token
$tokenexp = $acctoken.expires_in 
$global:authToken = @{ "Content-Type" = "application/json"; "Authorization" = "Bearer $($token)" ; "ExpiresOn" = $tokenexp }
#Write-Host "Token: $($token)"
#$token | out-file C:\tmp\token.txt
    
Write-Host "Token expires: $($tokenexp)"

$IntuneWin32Apps = Get-AllIntuneWin32Apps

$IntuneAppIDs = $IntuneWin32Apps.value.id

foreach ($IntuneAppID in $IntuneAppIDs) {
    $intuneappobj = Get-IntuneWin32App -appid $IntuneAppID
    start-sleep -seconds 1
    if (($intuneappobj.'@odata.type' -eq '#microsoft.graph.win32LobApp' ) -AND ($intuneappobj.allowAvailableUninstall -eq $false)) {
        write-host "Found IntuneWin32App with Name: $($intuneappobj.DisplayName) and allowAvailableUninstall is set to: $($intuneappobj.allowAvailableUninstall)" -ForegroundColor Yellow
        Enable-IntuneWin32AppUninstall -appid $intuneappobj.id
        write-host "IntuneWin32App with id: $($intuneappobj.id) has been enabled to allow uninstall" -ForegroundColor Green
    }
}

write-host "All Apps have been enabled to allow uninstall" -ForegroundColor Green
    
