<#
.SYNOPSIS
    Read-only audit of the TLS settings of a Windows server (Schannel and .NET Framework).

.DESCRIPTION
    Reports, for SSL 2.0 to TLS 1.3, the Client and Server registry values under
    HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols,
    the .NET Framework values SystemDefaultTlsVersions and SchUseStrongCrypto,
    and the TLS 1.3 cipher suites currently enabled.

    Useful before and after hardening a Microsoft Entra Connect, AD FS or Exchange server.
    It changes nothing. "Not set" means the operating system default applies.

.EXAMPLE
    .\Get-SchannelTlsConfig.ps1

.EXAMPLE
    Invoke-Command -ComputerName SRV-ENTRACONNECT01 -FilePath .\Get-SchannelTlsConfig.ps1

.NOTES
    Written by Olivier Lumeau
    https://github.com/Solisys-Cloud/tls13-explained

    Run as administrator on Windows. For Microsoft Entra Connect, Microsoft also ships
    Get-ADSyncToolsTls12 and Set-ADSyncToolsTls12 in the ADSyncTools module.
#>
[CmdletBinding()]
param()

$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$protocols = 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return 'Not set' }
    return $item.$Name
}

Write-Host "`n== Schannel protocols ==" -ForegroundColor Cyan
$protocols | ForEach-Object {
    $p = $_
    foreach ($role in 'Client', 'Server') {
        $path = Join-Path $base "$p\$role"
        [pscustomobject]@{
            Protocol          = $p
            Role              = $role
            Enabled           = Get-RegValue -Path $path -Name 'Enabled'
            DisabledByDefault = Get-RegValue -Path $path -Name 'DisabledByDefault'
        }
    }
} | Format-Table -AutoSize

Write-Host "== .NET Framework strong crypto ==" -ForegroundColor Cyan
$netPaths = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319',
            'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727'
$netPaths | ForEach-Object {
    [pscustomobject]@{
        Path                     = $_ -replace '^HKLM:\\SOFTWARE\\', ''
        SystemDefaultTlsVersions = Get-RegValue -Path $_ -Name 'SystemDefaultTlsVersions'
        SchUseStrongCrypto       = Get-RegValue -Path $_ -Name 'SchUseStrongCrypto'
    }
} | Format-Table -AutoSize

Write-Host "== TLS 1.3 cipher suites enabled ==" -ForegroundColor Cyan
if (Get-Command Get-TlsCipherSuite -ErrorAction SilentlyContinue) {
    Get-TlsCipherSuite | Where-Object { $_.Name -in 'TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256' } |
        Select-Object Name, CipherLength, Hash | Format-Table -AutoSize
}
else {
    Write-Host 'Get-TlsCipherSuite not available on this system.'
}
