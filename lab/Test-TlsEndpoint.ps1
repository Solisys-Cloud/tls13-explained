<#
.SYNOPSIS
    Shows the TLS version, cipher suite and certificate negotiated with a TLS endpoint.

.DESCRIPTION
    Opens a TCP connection, performs a TLS handshake with SslStream and reports what was
    negotiated. With -TestAllProtocols it tries TLS 1.0, 1.1, 1.2 and 1.3 one by one so you
    can see which versions the server still accepts.

    Read-only: it only connects and reads, it changes nothing.

.PARAMETER HostName
    DNS name of the endpoint, for example www.solisys.be or mystorage.blob.core.windows.net.

.PARAMETER Port
    TCP port. Default 443.

.PARAMETER TestAllProtocols
    Try each TLS version separately instead of letting the OS pick the best one.

.EXAMPLE
    .\Test-TlsEndpoint.ps1 -HostName www.solisys.be

.EXAMPLE
    .\Test-TlsEndpoint.ps1 -HostName mystorage.blob.core.windows.net -TestAllProtocols

.NOTES
    PowerShell 7+ recommended: it also shows the negotiated cipher suite.
    TLS 1.3 needs Windows 11 or Windows Server 2022 and later (or a recent OpenSSL on Linux and macOS).
    A "Refused" result can come from the server OR from your own client if that version is disabled locally.
    The ECDHE group (X25519, X25519MLKEM768...) is not exposed by SslStream: use openssl-lab.sh for that.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HostName,
    [int]$Port = 443,
    [switch]$TestAllProtocols,
    [int]$TimeoutMs = 5000
)

Set-StrictMode -Version Latest

function Get-SanDnsName {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $san = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    if (-not $san) { return @() }
    # The label is localized: "DNS Name=x" (English Windows), "Nom DNS=x" (French Windows), "DNS:x" (Linux, macOS)
    [regex]::Matches($san.Format($false), 'DNS[^=:,]*[=:]\s*([^,\s]+)') | ForEach-Object { $_.Groups[1].Value }
}

function Test-NameMatch {
    param([string]$HostName, [string[]]$Names)
    foreach ($n in $Names) {
        if ($n -ieq $HostName) { return $true }
        if ($n.StartsWith('*.')) {
            $suffix = $n.Substring(1)
            $label = $HostName.Split('.')[0]
            if ($HostName -ilike "*$suffix" -and ($label + $suffix) -ieq $HostName) { return $true }
        }
    }
    return $false
}

function Invoke-TlsHandshake {
    param(
        [string]$HostName,
        [int]$Port,
        [System.Security.Authentication.SslProtocols]$Protocol,
        [int]$TimeoutMs
    )
    $tcp = [System.Net.Sockets.TcpClient]::new()
    try {
        if (-not $tcp.ConnectAsync($HostName, $Port).Wait($TimeoutMs)) {
            throw "TCP connection to ${HostName}:$Port timed out"
        }
        # Accept any certificate during the handshake: we inspect it ourselves afterwards
        $accept = [System.Net.Security.RemoteCertificateValidationCallback] { $true }
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $accept)
        try {
            $ssl.AuthenticateAsClient($HostName, $null, $Protocol, $false)

            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
            $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
            $chainOk = $chain.Build($cert)
            $names = @(Get-SanDnsName -Certificate $cert)

            $cipher = 'n/a (use PowerShell 7+)'
            if ($ssl.PSObject.Properties['NegotiatedCipherSuite']) { $cipher = [string]$ssl.NegotiatedCipherSuite }

            [pscustomobject]@{
                Host         = $HostName
                Protocol     = [string]$ssl.SslProtocol
                CipherSuite  = $cipher
                Subject      = $cert.Subject
                Issuer       = $cert.Issuer
                ValidUntil   = $cert.NotAfter
                DaysLeft     = [int]($cert.NotAfter - (Get-Date)).TotalDays
                NameMatches  = Test-NameMatch -HostName $HostName -Names $names
                ChainTrusted = $chainOk
                Chain        = ($chain.ChainElements | ForEach-Object { $_.Certificate.GetNameInfo('SimpleName', $false) }) -join '  ->  '
                SanDnsNames  = $names -join ', '
            }
        }
        finally { $ssl.Dispose() }
    }
    finally { $tcp.Dispose() }
}

if ($TestAllProtocols) {
    $versions = [ordered]@{
        'TLS 1.0' = [System.Security.Authentication.SslProtocols]::Tls
        'TLS 1.1' = [System.Security.Authentication.SslProtocols]::Tls11
        'TLS 1.2' = [System.Security.Authentication.SslProtocols]::Tls12
        'TLS 1.3' = [System.Security.Authentication.SslProtocols]::Tls13
    }
    foreach ($v in $versions.GetEnumerator()) {
        try {
            $r = Invoke-TlsHandshake -HostName $HostName -Port $Port -Protocol $v.Value -TimeoutMs $TimeoutMs
            [pscustomobject]@{ Version = $v.Key; Result = 'Accepted'; CipherSuite = $r.CipherSuite }
        }
        catch {
            $msg = $_.Exception.GetBaseException().Message
            [pscustomobject]@{ Version = $v.Key; Result = 'Refused'; CipherSuite = "$msg (refused by the server or disabled on this client)" }
        }
    }
}
else {
    # SslProtocols.None = let the operating system choose the best version it supports
    Invoke-TlsHandshake -HostName $HostName -Port $Port -Protocol ([System.Security.Authentication.SslProtocols]::None) -TimeoutMs $TimeoutMs
}
