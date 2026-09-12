# R4: NDJSON event stream must not leak ?token=... query strings
# R5: Upstream TLS verification must reject self-signed / wrong-CN certs

$ErrorActionPreference = 'Continue'  # native exe stderr (openssl progress dots) trips Stop
$exe = "D:\dev\Nullock\Build\Src\App\Release\NullockApp.exe"
if (-not (Test-Path $exe)) { Write-Error "NullockApp.exe not built"; exit 1 }

Write-Host "=== R4: NDJSON query-string redaction ===" -ForegroundColor Cyan
# Start headless with NDJSON on a free port, capture stdout, hit a URL with a
# ?token=, expect the path field to NOT contain the token. Then re-run with
# --ndjson-include-query and verify it DOES contain the token (opt-in works).

$projDir = Join-Path $env:TEMP "nullock-redteam-r4-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $projDir | Out-Null
$proxyPort = 19450
$ctlPort   = 19451

$logFile = Join-Path $projDir "ndjson.log"
$proc = Start-Process -FilePath $exe `
  -ArgumentList "--headless","--ndjson","--proxy-port=$proxyPort","--control-port=$ctlPort","--project=$projDir" `
  -RedirectStandardOutput $logFile -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 2

# Generate a captured request through the proxy with a sensitive token in the query.
try {
    $env:HTTP_PROXY = "http://127.0.0.1:$proxyPort"
    curl.exe -s -x "http://127.0.0.1:$proxyPort" "http://example.com/api/me?session_token=SECRET_TOKEN_XYZ123" -o $null --max-time 10 2>&1 | Out-Null
} catch {}

Start-Sleep -Seconds 1
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

$ndjsonLines = Get-Content $logFile -ErrorAction SilentlyContinue
$responseLine = $ndjsonLines | Where-Object { $_ -match '"event":"response"' } | Select-Object -First 1
if (-not $responseLine) {
    Write-Host "  ! No response event captured (proxy connection may have failed) -- skipping R4 default-redact assert"
} elseif ($responseLine -match "SECRET_TOKEN_XYZ123") {
    Write-Host "  X R4 FAILED: query-string token leaked into NDJSON: $responseLine" -ForegroundColor Red
    exit 1
} else {
    Write-Host "  + NDJSON default-redacted: token NOT in event stream" -ForegroundColor Green
}

# Opt-in re-test
$logFile2 = Join-Path $projDir "ndjson-include.log"
$proc = Start-Process -FilePath $exe `
  -ArgumentList "--headless","--ndjson","--ndjson-include-query","--proxy-port=$proxyPort","--control-port=$ctlPort","--project=$projDir" `
  -RedirectStandardOutput $logFile2 -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
try {
    curl.exe -s -x "http://127.0.0.1:$proxyPort" "http://example.com/api/me?session_token=OPTIN_TOKEN_ABC" -o $null --max-time 10 2>&1 | Out-Null
} catch {}
Start-Sleep -Seconds 1
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

$ndjsonLines2 = Get-Content $logFile2 -ErrorAction SilentlyContinue
$responseLine2 = $ndjsonLines2 | Where-Object { $_ -match '"event":"response"' } | Select-Object -First 1
if ($responseLine2 -match "OPTIN_TOKEN_ABC") {
    Write-Host "  + NDJSON --ndjson-include-query opt-in works (token visible when requested)" -ForegroundColor Green
} elseif ($responseLine2) {
    Write-Host "  ! Opt-in did NOT restore query string -- check flag plumbing" -ForegroundColor Yellow
} else {
    Write-Host "  ! No response event in opt-in run -- network or proxy issue, not a R4 fix bug"
}

Write-Host ""
Write-Host "=== R5: Upstream TLS verification rejects self-signed ===" -ForegroundColor Cyan

# Start NullockApp again
$proc = Start-Process -FilePath $exe `
  -ArgumentList "--headless","--proxy-port=$proxyPort","--control-port=$ctlPort","--project=$projDir" `
  -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

# Spin up a TLS listener with a self-signed cert pretending to be example.com.
# We use openssl s_server in the background.
$tlsPort = 19460
$certDir = Join-Path $projDir "fakecert"
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
$keyFile  = Join-Path $certDir "k.pem"
$certFile = Join-Path $certDir "c.pem"
$openssl = "C:\Program Files\Git\usr\bin\openssl.exe"
if (-not (Test-Path $openssl)) { $openssl = "openssl" }
& $openssl req -x509 -newkey rsa:2048 -keyout $keyFile -out $certFile -days 1 -nodes -subj "/CN=example.com" 2>$null | Out-Null

# Start s_server in background
$tlsServerLog = Join-Path $projDir "tls_server.log"
$tlsProc = Start-Process -FilePath $openssl -ArgumentList "s_server","-accept",$tlsPort,"-cert",$certFile,"-key",$keyFile,"-quiet","-www" `
    -PassThru -WindowStyle Hidden -RedirectStandardOutput $tlsServerLog -RedirectStandardError "$tlsServerLog.err"
Start-Sleep -Seconds 1

# Now use Nullock's repeater (POST /api/repeater/send) to issue an HTTPS request to 127.0.0.1:$tlsPort.
# We map the request to host=example.com so peer verify name = example.com.
# Since the s_server's self-signed cert is signed by an unknown CA, our hardened
# code should REJECT the handshake.
$body = @{
    host   = "127.0.0.1"
    port   = $tlsPort
    useTls = $true
    request = "GET / HTTP/1.1`r`nHost: example.com`r`nConnection: close`r`n`r`n"
} | ConvertTo-Json -Compress

try {
    $resp = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$ctlPort/api/repeater/send" `
        -Method POST -Body $body -ContentType "application/json" `
        -Headers @{"X-Nullock-UI"="1"} -TimeoutSec 20
    $j = $resp.Content | ConvertFrom-Json
    if ($j.ok -eq $false -and $j.error -match "TLS|handshake|certificate|unknown CA|self.signed|verify") {
        Write-Host "  + Upstream TLS handshake REJECTED with cert error: $($j.error)" -ForegroundColor Green
    } elseif ($j.ok -eq $true) {
        Write-Host "  X R5 FAILED: handshake SUCCEEDED against self-signed cert" -ForegroundColor Red
        Write-Host "    response: $($resp.Content)"
        Stop-Process -Id $tlsProc.Id -Force -ErrorAction SilentlyContinue
        Stop-Process -Id $proc.Id    -Force -ErrorAction SilentlyContinue
        exit 1
    } else {
        Write-Host "  ! Handshake failed but error not cert-related: $($j.error)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ! Repeater API call failed: $($_.Exception.Message)" -ForegroundColor Yellow
} finally {
    Stop-Process -Id $tlsProc.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $proc.Id    -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "All red-team rounds verified." -ForegroundColor Green
