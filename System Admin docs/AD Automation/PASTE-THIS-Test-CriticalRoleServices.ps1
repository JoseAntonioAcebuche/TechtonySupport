$scriptContent = @'
<#
.SYNOPSIS
    Checks critical services grouped by common server role (AD, DNS, DHCP,
    File Server, IIS, SQL Server, Print Server, Remote Desktop).

.DESCRIPTION
    Unlike a flat critical-services list, this groups checks by role and
    only evaluates roles that are actually present on the server - so a
    file server won't get flagged for a missing DHCP service. Shows which
    roles were detected, and the Running/Stopped state of each service
    within that role.

.PARAMETER ComputerName
    One or more server hostnames.

.PARAMETER ComputerListPath
    Path to a plain text file, one hostname per line.

.PARAMETER Roles
    Optional - limit the check to specific roles. Default: all roles below.
    Valid values: ActiveDirectory, DNS, DHCP, FileServer, IIS, SQLServer,
    PrintServer, RemoteDesktop, GroupPolicy

.PARAMETER OutputFolder
    Folder for CSV/HTML output.

.EXAMPLE
    .\Test-CriticalRoleServices.ps1 -ComputerName SERVERLAB

.EXAMPLE
    .\Test-CriticalRoleServices.ps1 -ComputerName SQLSRV01 -Roles SQLServer,FileServer

.NOTES
    Requires remote admin rights on target servers (CIM).
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$ComputerListPath,

    [ValidateSet('ActiveDirectory','DNS','DHCP','FileServer','IIS','SQLServer','PrintServer','RemoteDesktop','GroupPolicy')]
    [string[]]$Roles,

    [string]$OutputFolder = ".\RoleServiceCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

if ($ComputerListPath) {
    $ComputerName = Get-Content -Path $ComputerListPath | Where-Object { $_.Trim() -ne '' }
}
if (-not $ComputerName) {
    throw "Provide -ComputerName or -ComputerListPath"
}

if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }

# --- Role definitions: RoleName -> list of service names ---
$roleDefinitions = [ordered]@{
    'ActiveDirectory' = @('NTDS','Netlogon','Kdc','ADWS')
    'DNS'             = @('DNS')
    'DHCP'            = @('DHCPServer')
    'GroupPolicy'     = @('gpsvc','W32Time')
    'FileServer'      = @('LanmanServer','LanmanWorkstation')
    'IIS'             = @('W3SVC','WAS')
    'SQLServer'       = @('MSSQLSERVER','SQLSERVERAGENT','SQLBrowser')
    'PrintServer'     = @('Spooler')
    'RemoteDesktop'   = @('TermService','SessionEnv','UmRdpService')
}

$rolesToCheck = if ($Roles) { $Roles } else { $roleDefinitions.Keys }

$results = [System.Collections.Generic.List[object]]::new()

foreach ($server in $ComputerName) {
    Write-Host "Checking roles on $server..." -ForegroundColor Cyan

    if (-not (Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Warning "$server is unreachable, skipping."
        continue
    }

    foreach ($roleName in $rolesToCheck) {
        $serviceNames = $roleDefinitions[$roleName]
        $anyInstalled = $false

        foreach ($svcName in $serviceNames) {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$svcName'" -ComputerName $server -ErrorAction SilentlyContinue

            if ($svc) {
                $anyInstalled = $true
                $status = if ($svc.State -eq 'Running') { 'OK' } else { 'ISSUE' }
                $results.Add([PSCustomObject]@{
                    Server      = $server
                    Role        = $roleName
                    ServiceName = $svcName
                    DisplayName = $svc.DisplayName
                    State       = $svc.State
                    StartMode   = $svc.StartMode
                    Status      = $status
                })
            }
        }

        if (-not $anyInstalled) {
            $results.Add([PSCustomObject]@{
                Server      = $server
                Role        = $roleName
                ServiceName = ''
                DisplayName = ''
                State       = 'Not Installed'
                StartMode   = ''
                Status      = 'N/A'
            })
        }
    }
}

$csvPath = "$OutputFolder\RoleServiceCheck.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# --- Build HTML, grouped by server then role ---
$serverGroups = $results | Group-Object Server

$sections = foreach ($sg in $serverGroups) {
    $roleGroups = $sg.Group | Group-Object Role
    $roleBlocks = foreach ($rg in $roleGroups) {
        $detected = ($rg.Group | Where-Object State -ne 'Not Installed').Count -gt 0
        $roleLabel = if ($detected) { "$($rg.Name) (detected)" } else { "$($rg.Name) (not present)" }

        $rows = foreach ($item in $rg.Group) {
            $color = switch ($item.Status) {
                'OK'    { '#2e7d32' }
                'ISSUE' { '#b00020' }
                default { '#999999' }
            }
            if ($item.State -eq 'Not Installed') {
                "<tr><td colspan='4' style='color:#999999'>Role not present on this server</td></tr>"
            } else {
                "<tr>
                    <td>$($item.DisplayName)</td>
                    <td style='color:$color;font-weight:bold'>$($item.State)</td>
                    <td>$($item.StartMode)</td>
                    <td style='color:$color;font-weight:bold'>$($item.Status)</td>
                </tr>"
            }
        }

        "<h3>$roleLabel</h3>
        <table>
        <tr><th>Service</th><th>State</th><th>Start Mode</th><th>Status</th></tr>
        $($rows -join "`n")
        </table>"
    }

    "<h2>Server: $($sg.Name)</h2>
    $($roleBlocks -join "`n")"
}

$issueCount = ($results | Where-Object Status -eq 'ISSUE').Count

$html = @"
<html><head><style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #222; }
table { border-collapse: collapse; width: 100%; margin-bottom: 16px; }
th, td { border: 1px solid #ddd; padding: 6px 10px; font-size: 13px; text-align: left; }
th { background-color: #f2f2f2; }
h1 { font-size: 20px; }
h2 { font-size: 17px; margin-top: 28px; border-bottom: 2px solid #333; padding-bottom: 4px; }
h3 { font-size: 14px; margin-top: 16px; color: #444; }
.summary-box { background: #f7f7f7; padding: 12px; border-radius: 6px; margin-bottom: 16px; }
.bad { color: #b00020; font-weight: bold; }
</style></head><body>
<h1>Role-Based Service Check - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h1>
<div class='summary-box'>
<b>Servers checked:</b> $($ComputerName.Count) &nbsp;|&nbsp;
<b class='bad'>Issues found:</b> $issueCount
</div>
$($sections -join "`n")
</body></html>
"@
$htmlPath = "$OutputFolder\RoleServiceCheck.html"
$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host "`nDone. Files written to: $OutputFolder" -ForegroundColor Green
Write-Host "Issues found: $issueCount" -ForegroundColor $(if ($issueCount -gt 0) { 'Red' } else { 'Green' })

if ($issueCount -gt 0) {
    $results | Where-Object Status -eq 'ISSUE' | Format-Table Server, Role, ServiceName, State -AutoSize
}

'@

Set-Content -Path C:\scripts\Test-CriticalRoleServices.ps1 -Value $scriptContent -Encoding UTF8

Write-Host 'File written successfully.' -ForegroundColor Green
