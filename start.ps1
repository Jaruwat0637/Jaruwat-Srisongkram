$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$dbPassword = Read-Host "MariaDB password for netmon" -AsSecureString
$routerCredential = Get-Credential -UserName "netmon" -Message "SSH credentials for R1"

$env:DB_HOST = "192.168.91.131"
$env:DB_PORT = "3306"
$env:DB_USER = "netmon"
$env:DB_NAME = "network_monitor"
$env:DB_PASSWORD = [System.Net.NetworkCredential]::new("", $dbPassword).Password
$env:ROUTER_SSH_HOST = "192.168.91.130"
$env:ROUTER_SSH_USER = $routerCredential.UserName
$env:ROUTER_SSH_PASS = $routerCredential.GetNetworkCredential().Password

try {
    py .\app.py
}
finally {
    Remove-Item Env:DB_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:ROUTER_SSH_PASS -ErrorAction SilentlyContinue
    Remove-Variable dbPassword, routerCredential -ErrorAction SilentlyContinue
}
