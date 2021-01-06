Function Get-AADServicePrincipal {

  [CmdletBinding()]
  [OutputType([Microsoft.Open.AzureAD.Model.ServicePrincipal[]])]
  Param(
    # Object Id of the service principal in Azure Active Directory (unique in this tenant only)
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "SPObjectId")]
    [ValidateNotNullOrEmpty()]
    [string[]]$ObjectId,
    # App Id of the service principal in Azure Active Directory (unique across all tenants)
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "AppId")]
    [ValidateNotNullOrEmpty()]
    [string[]]$AppId
  )

  Process {

    Switch ($PSCmdlet.ParameterSetName) {

      "SPObjectId" {

        Foreach ($ItemObjectId in $ObjectId) {

          Get-AzureADServicePrincipal -ObjectId $ItemObjectId

        }

      }

      "AppId" {

        Foreach ($ItemAppId in $AppId) {
          Get-AzureADServicePrincipal -Filter "AppId eq '$ItemAppId'"
        }

      }
    }

  }

}

Function Get-AADServicePrincipalPermissions {


  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [Microsoft.Open.AzureAD.Model.ServicePrincipal[]]$App
  )

  Process {

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


}
