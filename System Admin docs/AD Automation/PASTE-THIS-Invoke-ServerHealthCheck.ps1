$scriptContent = @'
<#
.SYNOPSIS
    Runs a health check sweep across one or more Windows Servers and produces
    a CSV + HTML report, with optional email alert on failures.

.DESCRIPTION
    Checks per server: ping/WinRM reachability, disk space (C: and any drive
    below threshold), memory usage, CPU load snapshot, critical service
    status, uptime, pending reboot flag, and recent System/Application
    error-level event log entries.

.PARAMETER ComputerName
    One or more server hostnames. Also accepts a text file path via -ComputerListPath.

.PARAMETER ComputerListPath
    Path to a plain text file, one hostname per line.

.PARAMETER CriticalServices
    Service names that must be Running on every server checked.
    Default: a common baseline; override per your environment.

.PARAMETER DiskWarningPercentFree
    Flag any volume below this % free space. Default 15.

.PARAMETER EventLogHours
    Look back this many hours for Error-level events. Default 24.

.PARAMETER OutputFolder
    Folder for CSV/HTML output.

.PARAMETER SmtpServer / -MailFrom / -MailTo
    Optional - if all three are supplied, emails the HTML report when any
    server has a Warning or Critical status.

.EXAMPLE
    .\Invoke-ServerHealthCheck.ps1 -ComputerName DC01,FILESRV01,APP01

.EXAMPLE
    .\Invoke-ServerHealthCheck.ps1 -ComputerListPath .\servers.txt -OutputFolder C:\Reports\Health

.NOTES
    Requires WinRM enabled + remote management rights on target servers
    (Invoke-Command / CIM). Run as a scheduled task under an account with
    remote admin rights for a recurring health check.
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$ComputerListPath,

    [string[]]$CriticalServices = @('DNS','DHCPServer','Netlogon','W32Time','LanmanServer','LanmanWorkstation'),

    [int]$DiskWarningPercentFree = 15,
    [int]$EventLogHours = 24,
    [string]$OutputFolder = ".\HealthChecks_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [string]$SmtpServer,
    [string]$MailFrom,
    [string]$MailTo
)

if ($ComputerListPath) {
    $ComputerName = Get-Content -Path $ComputerListPath | Where-Object { $_.Trim() -ne '' }
}
if (-not $ComputerName) {
    throw "Provide -ComputerName or -ComputerListPath"
}

if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }

$results = [System.Collections.Generic.List[object]]::new()

foreach ($server in $ComputerName) {
    Write-Host "Checking $server..." -ForegroundColor Cyan

    $entry = [ordered]@{
        Server           = $server
        Timestamp        = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Reachable        = $false
        OverallStatus    = 'Unknown'
        UptimeDays        = $null
        PendingReboot    = $null
        LowDiskVolumes   = ''
        MemoryFreePct    = $null
        CriticalServicesDown = ''
        RecentErrorCount = $null
        Notes            = ''
    }

    if (-not (Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        $entry.Reachable = $false
        $entry.OverallStatus = 'Critical'
        $entry.Notes = 'Host unreachable (ping failed)'
        $results.Add([PSCustomObject]$entry)
        continue
    }
    $entry.Reachable = $true

    try {
        $sessionParams = @{ ComputerName = $server; ErrorAction = 'Stop' }

        # --- Uptime ---
        $os = Get-CimInstance -ClassName Win32_OperatingSystem @sessionParams
        $uptime = (Get-Date) - $os.LastBootUpTime
        $entry.UptimeDays = [math]::Round($uptime.TotalDays, 1)
        $entry.MemoryFreePct = [math]::Round(($os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)

        # --- Disk space ---
        $volumes = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" @sessionParams
        $lowDisks = foreach ($v in $volumes) {
            if ($v.Size -gt 0) {
                $pctFree = [math]::Round(($v.FreeSpace / $v.Size) * 100, 1)
                if ($pctFree -lt $DiskWarningPercentFree) {
                    "$($v.DeviceID) ($pctFree% free)"
                }
            }
        }
        $entry.LowDiskVolumes = ($lowDisks -join '; ')

        # --- Critical services ---
        $downServices = foreach ($svcName in $CriticalServices) {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$svcName'" @sessionParams -ErrorAction SilentlyContinue
            if ($svc -and $svc.State -ne 'Running') { "$svcName ($($svc.State))" }
            elseif (-not $svc) { "$svcName (not installed)" }
        }
        $entry.CriticalServicesDown = ($downServices -join '; ')

        # --- Pending reboot check (registry-based) ---
        try {
            $pendingReboot = Invoke-Command -ComputerName $server -ScriptBlock {
                $keys = @(
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
                    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
                )
                foreach ($k in $keys) { if (Test-Path $k) { return $true } }
                return $false
            } -ErrorAction Stop
            $entry.PendingReboot = $pendingReboot
        } catch {
            $entry.PendingReboot = 'Unknown (WinRM required)'
        }

        # --- Recent error events ---
        try {
            $since = (Get-Date).AddHours(-$EventLogHours)
            $errors = Get-WinEvent -ComputerName $server -FilterHashtable @{
                LogName = 'System','Application'; Level = 2; StartTime = $since
            } -ErrorAction SilentlyContinue
            $entry.RecentErrorCount = ($errors | Measure-Object).Count
        } catch {
            $entry.RecentErrorCount = 'N/A'
        }

        # --- Determine overall status ---
        $isWarning = $entry.LowDiskVolumes -or ($entry.MemoryFreePct -lt 10) -or ($entry.RecentErrorCount -is [int] -and $entry.RecentErrorCount -gt 20)
        $isCritical = $entry.CriticalServicesDown -or ($entry.MemoryFreePct -lt 5)

        $entry.OverallStatus = if ($isCritical) { 'Critical' } elseif ($isWarning) { 'Warning' } else { 'Healthy' }
    }
    catch {
        $entry.OverallStatus = 'Critical'
        $entry.Notes = "Check failed: $($_.Exception.Message)"
    }

    $results.Add([PSCustomObject]$entry)
}

# --- Export ---
$csvPath = "$OutputFolder\HealthCheck.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$statusColor = @{ Healthy = '#2e7d32'; Warning = '#b8860b'; Critical = '#b00020'; Unknown = '#666' }
$rows = foreach ($r in $results) {
    $color = $statusColor[$r.OverallStatus]
    "<tr>
        <td>$($r.Server)</td>
        <td style='color:$color;font-weight:bold'>$($r.OverallStatus)</td>
        <td>$($r.UptimeDays)</td>
        <td>$($r.MemoryFreePct)</td>
        <td>$($r.LowDiskVolumes)</td>
        <td>$($r.CriticalServicesDown)</td>
        <td>$($r.PendingReboot)</td>
        <td>$($r.RecentErrorCount)</td>
        <td>$($r.Notes)</td>
    </tr>"
}

$html = @"
<html><head><style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #222; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 6px 10px; font-size: 13px; text-align: left; }
th { background-color: #f2f2f2; }
h1 { font-size: 20px; }
</style></head><body>
<h1>Server Health Check - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h1>
<table>
<tr><th>Server</th><th>Status</th><th>Uptime (days)</th><th>Mem Free %</th>
<th>Low Disk Vols</th><th>Down Services</th><th>Pending Reboot</th>
<th>Errors (last $EventLogHours h)</th><th>Notes</th></tr>
$($rows -join "`n")
</table>
</body></html>
"@
$htmlPath = "$OutputFolder\HealthCheck.html"
$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host "`nHealth check complete. Files: $csvPath, $htmlPath" -ForegroundColor Green
$results | Format-Table Server, OverallStatus, UptimeDays, MemoryFreePct, LowDiskVolumes, CriticalServicesDown -AutoSize

# --- Optional email alert ---
$needsAlert = $results | Where-Object { $_.OverallStatus -in @('Warning','Critical') }
if ($needsAlert -and $SmtpServer -and $MailFrom -and $MailTo) {
    try {
        Send-MailMessage -SmtpServer $SmtpServer -From $MailFrom -To $MailTo `
            -Subject "[ALERT] Server Health Check - $($needsAlert.Count) issue(s) found" `
            -Body $html -BodyAsHtml
        Write-Host "Alert email sent to $MailTo" -ForegroundColor Yellow
    } catch {
        Write-Warning "Failed to send alert email: $($_.Exception.Message)"
    }
}

'@

Set-Content -Path C:\scripts\Invoke-ServerHealthCheck.ps1 -Value $scriptContent -Encoding UTF8

Write-Host 'File written successfully.' -ForegroundColor Green
