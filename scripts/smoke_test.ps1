param(
    [string]$BaseUrl = "http://127.0.0.1:8000"
)

$ErrorActionPreference = "Stop"
$health = Invoke-RestMethod "$BaseUrl/health"
if ($health.status -ne "ok") {
    throw "Health check did not return status=ok."
}

$mode = Invoke-RestMethod "$BaseUrl/api/v1/runtime/mode"
$alerts = Invoke-RestMethod "$BaseUrl/api/v1/alerts"
$events = Invoke-RestMethod "$BaseUrl/api/v1/events"

Write-Output "health=$($health.status) mode=$($mode.mode) alerts=$($alerts.Count) events=$($events.Count)"
