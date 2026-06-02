# R5: Upstream TLS verification rejects self-signed cert
#
# Attack model: network attacker between Nullock and a real origin presents
# a forged cert. Before this fix, Nullock happily decrypted the attacker's
# traffic and forwarded it to the browser (the browser sees TLS-green via
# our own forged-leaf cert). After the fix, the upstream TLS handshake must
# REJECT a self-signed cert, the MITM tunnel must collapse, and curl must
# NOT receive the attacker's response body.
#
# Implementation:
#   1. openssl s_server with self-signed CN=localhost on $tlsPort
#   2. NullockApp running proxy on $proxyPort
#   3. curl through proxy: https://localhost:$tlsPort/
#   4. If response body == "SUCCESS_LEAKED" then fix failed (handshake completed)
#      If response body is empty / curl errors out then fix worked (rejected)

$ErrorActionPreference = 'Continue'
$exe = "D:\dev\Nullock\Build\Src\App\Release\NullockApp.exe"

$projDir = Join-Path $env:TEMP "nullock-r5-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $projDir | Out-Null

$proxyPort = 19550
$ctlPort   = 19551
$tlsPort   = 19560

# 1. Self-signed cert pretending to be localhost
$certDir = Join-Path $projDir "cert"
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
$keyFile  = Join-Path $certDir "k.pem"
$certFile = Join-Path $certDir "c.pem"
$openssl = "C:\Program Files\Git\usr\bin\openssl.exe"
if (-not (Test-Path $openssl)) { $openssl = "openssl" }
& $openssl req -x509 -newkey rsa:2048 -keyout $keyFile -out $certFile -days 1 -nodes -subj "/CN=localhost" 2>$null | Out-Null
if (-not (Test-Path $certFile)) { Write-Host "X cert gen failed" -ForegroundColor Red; exit 1 }

# 2. Spin up s_server that returns a unique marker if anyone successfully
#    completes TLS and asks for "/". -www makes s_server respond to HTTP.
$tlsServerLog = Join-Path $projDir "tls.log"
$tlsProc = Start-Process -FilePath $openssl `
    -ArgumentList "s_server","-accept",$tlsPort,"-cert",$certFile,"-key",$keyFile,"-quiet","-www" `
    -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $tlsServerLog -RedirectStandardError "$tlsServerLog.err"
Start-Sleep -Seconds 1
if ($tlsProc.HasExited) { Write-Host "X s_server died on startup; check $tlsServerLog.err" -ForegroundColor Red; exit 1 }

# 3. Start Nullock
$nlLog = Join-Path $projDir "nullock.log"
$nlProc = Start-Process -FilePath $exe `
    -ArgumentList "--headless","--proxy-port=$proxyPort","--control-port=$ctlPort","--project=$projDir" `
    -PassThru -WindowStyle Hidden -RedirectStandardOutput $nlLog -RedirectStandardError "$nlLog.err"
Start-Sleep -Seconds 2

# 4. Sanity: HEAD over the proxy direct to a known IP-no-TLS should work
$probe = curl.exe -s -o $null -w "%{http_code}" -x "http://127.0.0.1:$proxyPort" "http://example.com/" --max-time 8
Write-Host "  (sanity: HTTP through proxy returned: $probe)"

# 5. The actual test: HTTPS through proxy to our self-signed s_server.
#    --insecure lets curl accept Nullock's forged leaf cert.
#    If R5 fix works, the upstream TLS handshake from Nullock to s_server
#    should fail and curl should report an error or get empty/no body.
$outFile = Join-Path $projDir "attack_response.txt"
$curlErrFile = Join-Path $projDir "curl.err"
$curlExitCode = 0
try {
    $result = & curl.exe -sk -x "http://127.0.0.1:$proxyPort" "https://localhost:$tlsPort/" --max-time 12 -o $outFile -w "%{http_code}|%{size_download}" 2>$curlErrFile
    $curlExitCode = $LASTEXITCODE
} catch {
    $curlExitCode = 99
    $result = "EXCEPTION"
}

$attackBody = if (Test-Path $outFile) { (Get-Content $outFile -Raw -ErrorAction SilentlyContinue) } else { "" }
$bodySize   = if (Test-Path $outFile) { (Get-Item $outFile).Length } else { 0 }

Write-Host ""
Write-Host "curl exit: $curlExitCode"
Write-Host "result line: $result"
Write-Host "downloaded body size: $bodySize bytes"
if ($bodySize -gt 0 -and $bodySize -lt 1000) {
    Write-Host "--- body preview ---"
    Write-Host $attackBody
    Write-Host "--- end body ---"
}

# Stop servers
Stop-Process -Id $tlsProc.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $nlProc.Id  -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

# 6. Decide pass/fail
#    s_server -www response always includes "s_server -www" text and a
#    sniffable cipher suite. If we see that body, the attacker won —
#    Nullock completed TLS to the self-signed origin.
if ($attackBody -match "s_server" -or $attackBody -match "Server.*OpenSSL" -or $attackBody -match "Ciphers") {
    Write-Host ""
    Write-Host "X R5 FAILED: Nullock accepted the self-signed upstream cert and forwarded the attacker's response." -ForegroundColor Red
    Write-Host "   Sample body: $($attackBody.Substring(0, [Math]::Min(300, $attackBody.Length)))"
    exit 1
}

if ($curlExitCode -ne 0 -or $bodySize -eq 0) {
    Write-Host ""
    Write-Host "+ R5 PASSED: upstream TLS handshake rejected, attacker payload not delivered." -ForegroundColor Green
    # Bonus: confirm Nullock's log mentions the cert rejection reason.
    if (Test-Path "$nlLog.err") {
        $errs = Get-Content "$nlLog.err" -Raw -ErrorAction SilentlyContinue
        if ($errs -match "TLS handshake failed.*(certificate|self.signed|unknown|verify|issuer|CA)") {
            Write-Host "+ Log contains explicit cert-error diagnostic." -ForegroundColor Green
        }
    }
    exit 0
}

Write-Host "? R5 inconclusive: handshake didn't return s_server marker but body present (size=$bodySize, exit=$curlExitCode)" -ForegroundColor Yellow
exit 2
