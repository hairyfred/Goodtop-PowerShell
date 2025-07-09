# Parameters
param(
    # Switches for differnt functions
    [Parameter(ParameterSetName = 'port')]
    [switch]$port,
    [Parameter(ParameterSetName = 'poe')]
    [switch]$poe,
    [Parameter(ParameterSetName = 'sysinfo')]
    [switch]$sysinfo,
    # Global Information
    [Parameter(Mandatory)] 
    [string]$username = "admin",
    [Parameter(Mandatory)] 
    [string]$password = "admin",
    [Parameter(Mandatory)] 
    [string]$url,
    [Parameter()]
    [int]$interface='-1',
    [Parameter()]
    [int]$enabled='-1',
    # Port Settings Information
    [Parameter(Mandatory, ParameterSetName = 'port')]
    [string]$speed,
    [Parameter(Mandatory, ParameterSetName = 'port')]
    [int]$flow
)
# Info needed for each page
$pages = [pscustomobject]@{
    info = @{
        url = "info.cgi"
    }
    port = @{
        url = "port.cgi"
        body = @{
            submit = "+++Apply+++"
            cmd = "port"
        }
    }
    poe = @{
        url = "pse_port.cgi"
        body = @{
            language = "EN"
            submit = "apply"
            cmd = "poe"
        }
    }
}
# Adds param data
switch ($PSCmdlet.ParameterSetName) {
    'port' {
        if ($interface -eq -1) {
            $interface = Read-Host "Interface Number"
        }
        if ($enabled -eq -1)  {
            $enabled = Read-Host "Enabled"
        }
        $speedMap = @{
            "auto"     = 0
            "10HD"     = 1
            "10FD"     = 2
            "100HD"    = 3
            "100FD"    = 4
            "1000FD"   = 5
            "2500FD"   = 6
            "5000FD"   = 7  # May be unsupported on your switch
            "10000FD"  = 8
        }
        if ($speedMap.ContainsKey($speed)) {
            $speed = $speedMap[$speed]
        }
        $pages.port.body.speed_duplex = "$speed"
        $pages.port.body.flow = $flow
        $pages.port.body.state = $enabled
        $pages.port.body.portid = $interface
        $selectedbody = $pages.port.body
        $selectedpage = $pages.port.url
        Send-Requst()
    }
    'poe' {
        if ($interface -eq -1) {
            $interface = Read-Host "Interface Number:"
        }
        if ($enabled -eq -1)  {
            $enabled = Read-Host "Enabled"
        }
        $pages.poe.body.state = $enabled
        $pages.poe.body.portid = $interface
        $selectedbody = $pages.poe.body
        $selectedpage = $pages.poe.url
        Send-Request()
    }
    'sysinfo' {
        Write-Host "TEMP"
    }
}

function Get-LoginCookie {
    # Get Login Cookie
    # Combine username and password
    $logincombo = "$username$password"

    # Hash with MD5
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($logincombo)
    $hashBytes = $md5.ComputeHash($bytes)
    $hashedlogin = (-join ($hashBytes | ForEach-Object { $_.ToString("x2") }))
    return "$hashedlogin"
}

function Send-Request {
    # Headers, some of these are likley not needed and will trim out later
    $headers = @{
        "Host" = "$url"
        "Connection" = "keep-alive"
        "Cache-Control" = "max-age=0"
        "Upgrade-Insecure-Requests" = "1"
        "Origin" = "http://$url"
        "Content-Type" = "application/x-www-form-urlencoded"
        "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        "Referer" = "http://$url/$page"
        "Accept-Encoding" = "gzip, deflate"
    }
    # Add Login Cookie
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $cookie = New-Object System.Net.Cookie("admin", (Get-LoginCookie), "/", "$url")
    $session.Cookies.Add($cookie)

    # Run the command
    $response = Invoke-RestMethod -Uri "$url/$selectedpage" `
        -Method POST `
        -Body $selectedbody `
        -WebSession $session `
        -Headers $headers `
        -ContentType "application/x-www-form-urlencoded" `
        -UseBasicParsing
    }