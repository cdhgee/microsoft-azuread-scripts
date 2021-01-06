<#
  .SYNOPSIS
    Gets consented service principal permissions.

  .EXAMPLE
    Get-AADServicePrincipalConsents.ps1 -ObjectId 0abc46f-5fa7-4ae7-9e65-0753c8426527

  .DESCRIPTION
    Summarizes the API permissions that have been consented for a service
    principal. Delegated and application permissions are listed separately.
    Permissions are summarized by resource and scope; individual user consents
    are not listed unless the -Detailed switch is specified.

#>

[CmdletBinding()]
Param(
  # Object Id of the service principal in Azure Active Directory (unique in this tenant only)
  [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "SPObjectId")]
  [ValidateNotNullOrEmpty()]
  $ObjectId,
  # App Id of the service principal in Azure Active Directory (unique across all tenants)
  [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "AppId")]
  [ValidateNotNullOrEmpty()]
  $AppId
)



Begin {
}

Process {

  Function Get-AADPrincipalDetails {

    [CmdletBinding()]
    Param(
      [Parameter(Mandatory = $false)]
      [string]$PrincipalId
    )

    If ($null -ne $PrincipalId -and $PrincipalId.Length -gt 0) {

      $user = Get-AzureADObjectByObjectId -ObjectIds $PrincipalId -ErrorAction SilentlyContinue

    }

    If ($null -ne $user) {

      $user.UserPrincipalName.ToLower()

    }
    Else {

      ""

    }


  }

  Function Get-Permissions {

    [CmdletBinding()]
    Param(
      [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
      [Object[]]$App
    )

    Process {

      $app

      Foreach ($a in $App) {

        # Delegated permissions

        $a `
        | Get-AzureADServicePrincipalOauth2PermissionGrant -All $true -PipelineVariable grant `
        | Foreach-Object -PipelineVariable scope { $grant.Scope -split " " } `
        | Foreach-Object {

          $resource = Get-AzureADServicePrincipal -ObjectId $grant.ResourceId
          If ($grant.ConsentType -eq "Principal") {
            $consentType = "User consent"
            $consentPrincipal = Get-AADPrincipalDetails -PrincipalId $grant.PrincipalId
          }
          Else {
            $consentType = "Admin consent"
            $consentPrincipal = "An administrator"
          }

          [PSCustomObject]@{
            AppId            = $a.AppId
            App              = $a.DisplayName
            ResourceId       = $grant.ResourceId
            Resource         = $resource.DisplayName
            Type             = "Delegated"
            Scope            = $scope
            Description      = ($resource.Oauth2Permissions | Where-Object { $_.Value -eq $scope }).AdminConsentDescription
            ConsentType      = $consentType
            ConsentPrincipal = $consentPrincipal
          }

          # Application permissions

          $a `
        | Get-AzureADServiceAppRoleAssignedTo -PipelineVariable grant `
        | Where-Object { $grant.PrincipalType -eq "ServicePrincipal" } `
        | Foreach-Object {

            $resource = Get-AzureADServicePrincipal -ObjectId $grant.ResourceId
            $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $grant.Id }

            [PSCustomObject]@{
              AppId            = $a.AppId
              App              = $a.DisplayName
              ResourceId       = $grant.ResourceId
              Resource         = $resource.DisplayName
              Type             = "Application"
              Scope            = $appRole.Value
              Description      = $appRole.Description
              ConsentType      = "Admin consent"
              ConsentPrincipal = "An administrator"

            }

          }

        }
      }
    }

    Switch ($PSCmdlet.ParameterSetName) {

      "SPObjectId" {

        Foreach ($ItemObjectId in $ObjectId) {

          Get-AzureADServicePrincipal -ObjectId $ItemObjectId `
        | Get-Permissions

        }

      }

      "AppId" {

        Foreach ($ItemAppId in $AppId) {

          Get-AzureADServicePrincipal -Filter "AppId eq '$ItemAppId'" `
        | Get-Permissions

        }

      }
    }

  }

  End {
  }





