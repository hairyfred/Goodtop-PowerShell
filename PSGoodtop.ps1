# Parameters
param(
    # Switches for differnt functions
    [Parameter(ParameterSetName = 'port')]
    [switch]$port,
    [Parameter(ParameterSetName = 'poe')]
    [switch]$poe,
    [Parameter(ParameterSetName = 'sysinfo')]
    [switch]$sysinfo,
    [Parameter(ParameterSetName = 'backup')]
    [switch]$backup,
    [Parameter(ParameterSetName = 'saveconfig')]
    [switch]$saveconfig,
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
    [Parameter()]
    [int]$save='0',
    # Port Settings Information
    [Parameter(Mandatory, ParameterSetName = 'port')]
    [string]$speed,
    [Parameter(Mandatory, ParameterSetName = 'port')]
    [int]$flow
)
Set-Variable -Name save -Option AllScope
$rootdir = Get-Location
# Info needed for each page
$pages = [pscustomobject]@{
    sysinfo = @{
        url = "info.cgi"
        body = @{
            language = "EN"
        }
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
    save = @{
        url = "save.cgi"
        body = @{
            language = "EN"
            cmd = "save"
        }
    }
    backup = @{
        url = "config_back.cgi"
        body = @{
            cmd = "conf_backup"
        }
    }
}
function Get-LoginCookie {
    param (
        [string]$username,
        [string]$password
    )

    $logincombo = "$username$password"

    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($logincombo)
    $hashBytes = $md5.ComputeHash($bytes)
    $hashedlogin = (-join ($hashBytes | ForEach-Object { $_.ToString("x2") }))

    Write-Debug "[DEBUG] Hashed login = $hashedlogin"
    return $hashedlogin
}
function Save-Settings {
    $selectedbody = $pages.save.body
    $selectedpage = $pages.save.url
    Send-Request -url $url -username $username -password $password -selectedpage $pages.save.url -selectedbody $pages.save.body -selectedmethod 'POST'
    Write-Host "[INFO] Settings Saved"
}

function Send-Request {
    param (
        [string]$url,
        [string]$username,
        [string]$password,
        [string]$selectedpage,
        [string]$selectedmethod,
        [hashtable]$selectedbody
    )

    $cookieValue = Get-LoginCookie -username $username -password $password

    $headers = @{
        "Host"              = "$url"
        "Connection"        = "keep-alive"
        "Cache-Control"     = "max-age=0"
        "Upgrade-Insecure-Requests" = "1"
        "Origin"            = "http://$url"
        "Content-Type"      = "application/x-www-form-urlencoded"
        "Accept"            = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        "Referer"           = "http://$url/$selectedpage"
        "Accept-Encoding"   = "gzip, deflate"
    }

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $cookie = New-Object System.Net.Cookie("admin", $cookieValue, "/", "$url")
    $session.Cookies.Add($cookie)
    try {
        $response = Invoke-RestMethod -Uri "http://$url/$selectedpage" `
            -Method $selectedmethod `
            -Body $selectedbody `
            -WebSession $session `
            -Headers $headers `
            -ContentType "application/x-www-form-urlencoded" `
            -UseBasicParsing
        Write-Debug "[DEBUG] $request"
        return $response
    }
    catch {
        Write-Host "[ERROR] Failed to get response: $_"
        exit
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
            "5000FD"   = 7  # May be unsupported, educated guess of what this value is meant to be
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
        Send-Request -url $url -username $username -password $password -selectedpage $pages.port.url -selectedbody $pages.port.body -selectedmethod 'POST'
        Write-Host "[INFO] Settings applied"
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
        Send-Request -url $url -username $username -password $password -selectedpage $pages.poe.url -selectedbody $pages.poe.body -selectedmethod 'POST'
        Write-Host "[INFO] Settings applied"
    }
    'sysinfo' {
        $selectedbody = $pages.sysinfo.body
        $selectedpage = $pages.sysinfo.url
        $html = Send-Request -url $url -username $username -password $password -selectedpage $pages.sysinfo.url -selectedbody $pages.sysinfo.body -selectedmethod 'GET'
        $propBag = @{}
        $pattern = '<tr>\s*<th[^>]*>(.*?)</th>\s*<td[^>]*>(.*?)</td>'   # captures TH / TD pairs
        [regex]::Matches($html, $pattern, 'IgnoreCase') | ForEach-Object {
        $name, $value = $_.Groups[1].Value.Trim(), $_.Groups[2].Value.Trim()
        $propBag[$name] = $value
        }
        # Cast to a nicely typed object
        $systeminfo = [pscustomobject]@{
            DeviceModel     = $propBag['Device Model']
            MACAddress      = $propBag['MAC Address']
            IPAddress       = $propBag['IP Address']
            Netmask         = $propBag['Netmask']
            Gateway         = $propBag['Gateway']
            FirmwareVersion = $propBag['Firmware Version']
            FirmwareDate    = [datetime]$propBag['Firmware Date']
            HardwareVersion = $propBag['Hardware Version']
        }
        $systeminfo
        $save = 2 #As no need to save
    }
    'saveconfig' {
        $save = 1
        Save-Settings
        $save = 2
    }
    'backup' {
        $selectedbody = $pages.sysinfo.body
        $selectedpage = $pages.sysinfo.url
    }
}
if ($save -eq 1) {
    Save-Settings
    $save = 2
}
if ($save -eq 2) {
    Write-Debug "[DEBUG] Skipping saving again"
}
else {
    $confirmsave = Read-Host "Do you want to save these settings? y/n"
    if (("yes","ye","y" -contains ($confirmsave.ToLower())) -eq $true) {
        $save = 1
        Save-Settings
    }
}