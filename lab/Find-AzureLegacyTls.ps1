<#
.SYNOPSIS
    Read-only inventory of Azure resources whose minimum TLS version is below 1.2.

.DESCRIPTION
    Checks three common services:
      - Storage accounts (Azure Resource Graph, property minimumTlsVersion)
      - Azure SQL logical servers (Azure Resource Graph, property minimalTlsVersion)
      - App Service, Functions and Logic Apps Standard (Get-AzWebApp per app, because
        Resource Graph and list calls do not return siteConfig)

    It changes nothing. For continuous control, assign the built-in Azure Policy audit definitions.

.EXAMPLE
    Connect-AzAccount
    .\Find-AzureLegacyTls.ps1 | Format-Table -AutoSize

.EXAMPLE
    .\Find-AzureLegacyTls.ps1 -SkipWebApps | Export-Csv .\legacy-tls.csv -NoTypeInformation

.NOTES
    Requires the Az.Accounts, Az.ResourceGraph and Az.Websites modules and Reader access.
    Resource Graph covers the subscriptions visible in your current context.
#>
[CmdletBinding()]
param(
    [switch]$SkipWebApps
)

$ok = 'TLS1_2', 'TLS1_3', '1.2', '1.3'

# Storage accounts
$storage = Search-AzGraph -First 1000 -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
| project subscriptionId, resourceGroup, name, minTls = tostring(properties.minimumTlsVersion)
"@
foreach ($s in $storage) {
    [pscustomobject]@{
        Service       = 'Storage account'
        Subscription  = $s.subscriptionId
        ResourceGroup = $s.resourceGroup
        Name          = $s.name
        MinTls        = if ($s.minTls) { $s.minTls } else { 'Not set' }
        Compliant     = $s.minTls -in $ok
    }
}

# Azure SQL logical servers
$sql = Search-AzGraph -First 1000 -Query @"
resources
| where type =~ 'microsoft.sql/servers'
| project subscriptionId, resourceGroup, name, minTls = tostring(properties.minimalTlsVersion)
"@
foreach ($s in $sql) {
    [pscustomobject]@{
        Service       = 'Azure SQL server'
        Subscription  = $s.subscriptionId
        ResourceGroup = $s.resourceGroup
        Name          = $s.name
        MinTls        = if ($s.minTls) { $s.minTls } else { 'Not set' }
        Compliant     = $s.minTls -in $ok
    }
}

# App Service, Functions, Logic Apps Standard (current subscription)
if (-not $SkipWebApps) {
    foreach ($app in Get-AzWebApp) {
        $full = Get-AzWebApp -ResourceGroupName $app.ResourceGroup -Name $app.Name
        $site = $full.SiteConfig.MinTlsVersion
        $scm = $null
        if ($full.SiteConfig.PSObject.Properties['ScmMinTlsVersion']) { $scm = $full.SiteConfig.ScmMinTlsVersion }
        [pscustomobject]@{
            Service       = 'App Service (site / SCM)'
            Subscription  = (Get-AzContext).Subscription.Id
            ResourceGroup = $app.ResourceGroup
            Name          = $app.Name
            MinTls        = "$site / $(if ($scm) { $scm } else { 'n/a' })"
            Compliant     = ($site -in $ok) -and ((-not $scm) -or ($scm -in $ok))
        }
    }
}
