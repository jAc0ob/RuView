# RuView — start sensing server + HTTPS dashboard in two windows
# Usage: .\scripts\start-ruview.ps1
# Optional: .\scripts\start-ruview.ps1 -Port 8443 -WsPort 8765 -SensingPort 8765

param(
    [int]$Port        = 8443,
    [int]$WsPort      = 8765,
    [int]$SensingPort = 8765
)

$Root = Split-Path $PSScriptRoot -Parent

# Resolve local IPv4 (same logic as serve-https.js)
$LocalIP = (
    Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notmatch '^169' } |
    Select-Object -First 1
).IPAddress

if (-not $LocalIP) { $LocalIP = '127.0.0.1' }

Write-Host ""
Write-Host "  Starting RuView on $LocalIP" -ForegroundColor Cyan
Write-Host ""

# ── Window 1: sensing server (Rust) ──────────────────────────────────────────
$sensingCmd = "cd '$Root\v2'; " +
    "cargo run -p wifi-densepose-sensing-server -- " +
    "--bind-addr 0.0.0.0 --allowed-host $LocalIP; pause"

Start-Process powershell -ArgumentList "-NoExit", "-Command", $sensingCmd -WindowStyle Normal

# Give cargo a moment to start compiling before opening the browser window
Start-Sleep -Milliseconds 600

# ── Window 2: HTTPS static + WS proxy ────────────────────────────────────────
$httpsCmd = "cd '$Root'; " +
    "node scripts/serve-https.js --port $Port --ws-port $WsPort; pause"

Start-Process powershell -ArgumentList "-NoExit", "-Command", $httpsCmd -WindowStyle Normal

Write-Host "  Two windows opened:" -ForegroundColor Green
Write-Host "    Window 1 — Rust sensing server (compiling first run may take ~1 min)"
Write-Host "    Window 2 — HTTPS dashboard server"
Write-Host ""
Write-Host "  Dashboard URL (open on iPhone after cert install):" -ForegroundColor Yellow
Write-Host "    https://$LocalIP`:$Port" -ForegroundColor White
Write-Host ""
Write-Host "  Cert install URL (open this first in iPhone Safari):" -ForegroundColor Yellow
Write-Host "    https://$LocalIP`:$Port/certs/ruview-local.crt" -ForegroundColor White
Write-Host ""
