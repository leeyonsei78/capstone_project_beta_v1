$ErrorActionPreference = 'Stop'
$labUrl = 'http://127.0.0.1:8765'
try {
    $response = Invoke-WebRequest -Uri "$labUrl/api/health" -UseBasicParsing -TimeoutSec 3
    $alreadyRunning = $response.StatusCode -eq 200
} catch {
    $alreadyRunning = $false
}
if (-not $alreadyRunning) {
    $pythonExe = (Get-Command python -ErrorAction Stop).Source
    Start-Process -FilePath $pythonExe -ArgumentList ('"{0}"' -f (Join-Path $PSScriptRoot 'app.py')) -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $PSScriptRoot 'server.log') -RedirectStandardError (Join-Path $PSScriptRoot 'server-error.log')
}
$ready = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    try {
        $response = Invoke-WebRequest -Uri $labUrl -UseBasicParsing -TimeoutSec 2
        if ($response.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
    Start-Sleep -Milliseconds 500
}
if (-not $ready) { throw 'Server failed to start. See server-error.log.' }
Write-Host "Qwen Security Lab: $labUrl"
try { Start-Process $labUrl } catch { Write-Host "Open this address in your browser: $labUrl" }
