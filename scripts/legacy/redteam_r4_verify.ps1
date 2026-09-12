# R4: NDJSON event stream must not leak ?token=... query strings unless
# --ndjson-include-query is explicitly passed.
$ErrorActionPreference = 'Continue'
$exe = "D:\dev\Nullock\Build\Src\App\Release\NullockApp.exe"

function Run-Round($flagsExtra, $tag, $token) {
    $projDir = Join-Path $env:TEMP "nl-r4-$tag-$(Get-Random)"
    New-Item -ItemType Directory -Force -Path $projDir | Out-Null
    $proxyPort = Get-Random -Minimum 19600 -Maximum 19999
    $ctlPort   = $proxyPort + 1
    $logFile = Join-Path $projDir "ndjson.log"
    $args = @("--headless","--ndjson","--proxy-port=$proxyPort","--control-port=$ctlPort","--project=$projDir") + $flagsExtra
    $proc = Start-Process -FilePath $exe -ArgumentList $args -RedirectStandardOutput $logFile -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2
    & curl.exe -s -x "http://127.0.0.1:$proxyPort" "http://example.com/api/me?session_token=$token" -o $null --max-time 10 2>$null | Out-Null
    Start-Sleep -Seconds 1
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    $lines = Get-Content $logFile -ErrorAction SilentlyContinue
    return ($lines | Where-Object { $_ -match '"event":"response"' } | Select-Object -First 1)
}

Write-Host "=== R4: NDJSON default redacts query strings ===" -ForegroundColor Cyan

$defaultLine = Run-Round @() "default" "SECRET_AAA_111"
Write-Host "  event: $defaultLine"
if (-not $defaultLine) {
    Write-Host "X No response event captured for default run" -ForegroundColor Red; exit 1
}
if ($defaultLine -match "SECRET_AAA_111") {
    Write-Host "X DEFAULT LEAKED TOKEN" -ForegroundColor Red; exit 1
}
Write-Host "+ default mode: token not in NDJSON" -ForegroundColor Green

$optInLine = Run-Round @("--ndjson-include-query") "optin" "OPTIN_BBB_222"
Write-Host "  event: $optInLine"
if (-not $optInLine) {
    Write-Host "X No response event captured for opt-in run" -ForegroundColor Red; exit 1
}
if ($optInLine -notmatch "OPTIN_BBB_222") {
    Write-Host "X --ndjson-include-query FLAG BROKEN -- token not present when explicitly requested" -ForegroundColor Red; exit 1
}
Write-Host "+ --ndjson-include-query opt-in restores query string" -ForegroundColor Green

Write-Host ""
Write-Host "R4 verified." -ForegroundColor Green
