# v3 validation: hits the endpoints I shipped but never actually tested.
# Spins up a fresh NullockApp instance, fires real HTTP calls at the
# endpoints, asserts the responses are shaped correctly. Doesn't depend
# on httpbin -- only loopback.
#
# Pass = endpoint returns a real JSON shape, not 404 / 500 / empty.

$ErrorActionPreference = 'Continue'
$exe = "D:\dev\Nullock\Build\Src\App\Release\NullockApp.exe"

$projDir = Join-Path $env:TEMP "nullock-v3val-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $projDir | Out-Null
$proxyPort = 19770
$ctlPort   = 19771

$nl = Start-Process -FilePath $exe `
    -ArgumentList "--headless","--proxy-port=$proxyPort","--control-port=$ctlPort","--project=$projDir","--no-update-check" `
    -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

$pass = 0; $fail = 0
function Test-Endpoint($name, [scriptblock]$block) {
    try {
        $r = & $block
        if ($r) { Write-Host "  PASS $name" -ForegroundColor Green; $script:pass++ }
        else    { Write-Host "  FAIL $name (empty result)" -ForegroundColor Red; $script:fail++ }
    } catch {
        Write-Host "  FAIL $name : $($_.Exception.Message)" -ForegroundColor Red; $script:fail++
    }
}

$base = "http://127.0.0.1:$ctlPort"
$hdr  = @{ "Origin"="http://127.0.0.1:$ctlPort"; "X-Nullock-UI"="1" }

Write-Host "=== /api/snapshot baseline ===" -ForegroundColor Cyan
Test-Endpoint "snapshot returns JSON with bootInfo" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/snapshot" -Headers $hdr -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return ($null -ne $j.bootInfo)
}

Test-Endpoint "snapshot has .update field" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/snapshot" -Headers $hdr -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return $j.PSObject.Properties.Name -contains 'update'
}

Test-Endpoint "snapshot has .oast field with port" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/snapshot" -Headers $hdr -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return ($j.oast -and $j.oast.port -gt 0)
}

Write-Host "`n=== /api/project/templates ===" -ForegroundColor Cyan
Test-Endpoint "templates endpoint lists templates" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/project/templates" -Headers $hdr -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    # May be empty depending on path resolution; the endpoint itself returning a shape is the test.
    return $j.PSObject.Properties.Name -contains 'templates'
}

Write-Host "`n=== /api/report/build ===" -ForegroundColor Cyan
Test-Endpoint "report build returns markdown" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/report/build" -Method POST -Headers $hdr -TimeoutSec 10
    return ($r.Content -like "*# Nullock engagement report*")
}

Write-Host "`n=== /api/openapi/export ===" -ForegroundColor Cyan
Test-Endpoint "openapi export returns 3.1 spec shape" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/openapi/export" -Headers $hdr -TimeoutSec 10
    $j = $r.Content | ConvertFrom-Json
    return ($j.openapi -eq "3.1.0")
}

Write-Host "`n=== /api/cookies ===" -ForegroundColor Cyan
Test-Endpoint "cookies endpoint returns hosts array" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/cookies" -Headers $hdr -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return $j.PSObject.Properties.Name -contains 'hosts'
}

Write-Host "`n=== /api/h2/streams ===" -ForegroundColor Cyan
Test-Endpoint "h2 streams endpoint returns streams array" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/h2/streams" -Headers $hdr -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return $j.PSObject.Properties.Name -contains 'streams'
}

Write-Host "`n=== /api/ws/sessions ===" -ForegroundColor Cyan
Test-Endpoint "ws sessions endpoint returns sessions array" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/ws/sessions" -Headers $hdr -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return $j.PSObject.Properties.Name -contains 'sessions'
}

Write-Host "`n=== /api/oast/poll ===" -ForegroundColor Cyan
Test-Endpoint "oast poll returns hits array" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/oast/poll" -Headers $hdr -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return ($j.PSObject.Properties.Name -contains 'hits' -and $j.PSObject.Properties.Name -contains 'running')
}

Test-Endpoint "oast mint returns token + URL" {
    $body = '{}'
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/oast/mint" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return ($j.token -and $j.pathUrl)
}

Write-Host "`n=== /api/oast end-to-end callback ===" -ForegroundColor Cyan
Test-Endpoint "OAST sink actually receives a hit when we curl it" {
    # Mint a token, then directly curl the callback URL on the OAST port.
    $body = '{}'
    $mint = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/oast/mint" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
    $mintJ = $mint.Content | ConvertFrom-Json
    $cbUrl = $mintJ.pathUrl
    # Fire a real HTTP GET at the callback URL.
    try {
        $cb = Invoke-WebRequest -UseBasicParsing -Uri $cbUrl -TimeoutSec 5
        if (-not ($cb.Content -like "*nullock-oast: callback received*")) { return $false }
    } catch {
        return $false
    }
    Start-Sleep -Milliseconds 500
    # Poll for the hit.
    $poll = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/oast/poll" -Headers $hdr -TimeoutSec 5
    $pollJ = $poll.Content | ConvertFrom-Json
    foreach ($h in $pollJ.hits) {
        if ($h.token -eq $mintJ.token) { return $true }
    }
    return $false
}

Write-Host "`n=== OAST auto-correlation (confirmed SSRF) ===" -ForegroundColor Cyan
Test-Endpoint "registered token + callback auto-emits a confirmed finding" {
    # Mint a token registered with an origin, then fire the callback at
    # the sink. The correlator should turn it into a confirmed finding.
    $mintBody = @{ register=$true; host="victim.internal"; param="image_url"; note="v3-correlate" } | ConvertTo-Json
    $mint = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/oast/mint" -Method POST -Headers $hdr -Body $mintBody -ContentType "application/json" -TimeoutSec 5
    $mintJ = $mint.Content | ConvertFrom-Json
    if (-not $mintJ.token -or -not $mintJ.pathUrl) { return $false }
    try { Invoke-WebRequest -UseBasicParsing -Uri $mintJ.pathUrl -TimeoutSec 5 | Out-Null } catch { return $false }
    Start-Sleep -Milliseconds 800
    $snap = (Invoke-WebRequest -UseBasicParsing -Uri "$base/api/snapshot" -Headers $hdr -TimeoutSec 5).Content | ConvertFrom-Json
    $confirmed = @($snap.findings | Where-Object { $_.kind -eq "ssrf-oast-confirmed" })
    return ($snap.oast.confirmed -ge 1) -and ($confirmed.Count -ge 1) -and ($confirmed[0].severity -eq "high")
}

Write-Host "`n=== /api/h2/events shape ===" -ForegroundColor Cyan
Test-Endpoint "h2 events endpoint returns events array" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/h2/events?since=0" -Headers $hdr -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return $j.PSObject.Properties.Name -contains 'events'
}

Write-Host "`n=== /api/history/find shape ===" -ForegroundColor Cyan
Test-Endpoint "history find accepts POST and returns count" {
    $body = '{"limit":5}'
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/history/find" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return $j.PSObject.Properties.Name -contains 'count'
}

Write-Host "`n=== Crawler endpoints ===" -ForegroundColor Cyan
Test-Endpoint "crawler accepts start request (refuses since no proxy)" {
    $body = '{"seed":"http://127.0.0.1:65432/","maxPages":1}'
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/crawler/start" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
    # We just want the endpoint to be reachable (200 with ok flag); ok=true or false both prove plumbing.
    $j = $r.Content | ConvertFrom-Json
    return $j.PSObject.Properties.Name -contains 'ok'
}

Test-Endpoint "crawler stop accepts request" {
    $body = '{}'
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/crawler/stop" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
    return $r.StatusCode -eq 200
}

Write-Host "`n=== Session rules ===" -ForegroundColor Cyan
Test-Endpoint "session-rules set accepts rules" {
    $body = '{"rules":[{"name":"test","enabled":true,"hostGlob":"*","pathGlob":"*","extractFrom":0,"extractKey":"X-Test","variable":"v","injectInto":0,"injectKey":"X-Inject"}]}'
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/session-rules/set" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
    return $r.StatusCode -eq 200
}

Test-Endpoint "snapshot reflects added session rule" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/snapshot" -Headers $hdr -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    foreach ($rule in $j.sessionRules.rules) {
        if ($rule.name -eq 'test') { return $true }
    }
    return $false
}

Write-Host "`n=== Extensions ===" -ForegroundColor Cyan
Test-Endpoint "extensions install-builtins responds" {
    $body = '{}'
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/extensions/install-builtins" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 10
    return $r.StatusCode -eq 200
}

Write-Host "`n=== Sequencer ===" -ForegroundColor Cyan
Test-Endpoint "sequencer rejects empty input gracefully" {
    $body = '{"tokens":[]}'
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/sequencer/analyze" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return $j.verdict -eq "no-data"
}

Test-Endpoint "sequencer flags sequential counter tokens as predictable" {
    # 100, 101, 102, ... -- obviously predictable
    $tokens = (100..120) | ForEach-Object { '"' + ($_.ToString()) + '"' }
    $body = '{"tokens":[' + ($tokens -join ',') + ']}'
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/sequencer/analyze" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return ($j.sequential.looksSequential -eq $true) -and ($j.verdict -eq "predictable")
}

Test-Endpoint "sequencer flags high-entropy tokens as looks-random" {
    # 20 random 32-char hex tokens
    $rng = [System.Random]::new()
    $tokens = @()
    for ($i = 0; $i -lt 20; $i++) {
        $b = New-Object byte[] 16
        $rng.NextBytes($b)
        $hex = ($b | ForEach-Object { $_.ToString('x2') }) -join ''
        $tokens += '"' + $hex + '"'
    }
    $body = '{"tokens":[' + ($tokens -join ',') + ']}'
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/sequencer/analyze" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return $j.verdict -eq "looks-random"
}

Write-Host "`n=== GraphQL active probe ===" -ForegroundColor Cyan
Test-Endpoint "graphql probe rejects empty url" {
    $body = '{}'
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/graphql/probe" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
        $j = $r.Content | ConvertFrom-Json
        return $j.ok -eq $false
    } catch { return $false }
}

Test-Endpoint "graphql probe queues 5 attack probes for a real target" {
    # We don't care if example.com actually has GraphQL; we just want
    # the endpoint to accept the work and report 5 queued.
    $body = '{"url":"https://example.com/graphql"}'
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/graphql/probe" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 5
    $j = $r.Content | ConvertFrom-Json
    return ($j.ok -eq $true) -and ($j.queued -eq 5)
}

Write-Host "`n=== Repeater chains ===" -ForegroundColor Cyan
Test-Endpoint "chain run rejects empty steps" {
    $body = '{"steps":[]}'
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/chain/run" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 10
        $j = $r.Content | ConvertFrom-Json
        return $j.ok -eq $false
    } catch { return $false }
}

Test-Endpoint "chain threads a token from step1 json into step2 header" {
    # Self-contained loopback origin: /login returns {token:...}; /me echoes
    # the Authorization header it received. The chain must extract token from
    # step1 and substitute it into step2's Authorization. (We don't target
    # the control server itself -- that would deadlock, since the control
    # handler blocks until the chain completes.)
    $oport = 19799
    $job = Start-Job -ScriptBlock {
        param($port)
        $l = [System.Net.HttpListener]::new()
        $l.Prefixes.Add("http://127.0.0.1:$port/")
        $l.Start()
        1..4 | ForEach-Object {
            try {
                $ctx = $l.GetContext()
                if ($ctx.Request.Url.AbsolutePath -eq "/login") {
                    $b = '{"token":"chainTok9"}'
                } else {
                    $b = '{"seen":"' + $ctx.Request.Headers["Authorization"] + '"}'
                }
                $ctx.Response.ContentType = "application/json"
                $buf = [System.Text.Encoding]::UTF8.GetBytes($b)
                $ctx.Response.OutputStream.Write($buf, 0, $buf.Length)
                $ctx.Response.Close()
            } catch {}
        }
        $l.Stop()
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 600
    try {
        $req1 = "POST /login HTTP/1.1`r`nHost: 127.0.0.1`r`nContent-Type: application/json`r`nContent-Length: 2`r`nConnection: close`r`n`r`n{}"
        $req2 = "GET /me HTTP/1.1`r`nHost: 127.0.0.1`r`nAuthorization: Bearer {{token}}`r`nConnection: close`r`n`r`n"
        $chain = @{
            steps = @(
                @{ name="login"; host="127.0.0.1"; port=$oport; tls=$false; request=$req1;
                   extract=@( @{ var="token"; from="json"; key="token" } ) },
                @{ name="use"; host="127.0.0.1"; port=$oport; tls=$false; request=$req2;
                   extract=@( @{ var="echoed"; from="json"; key="seen" } ) }
            )
        } | ConvertTo-Json -Depth 8
        $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/chain/run" -Method POST -Headers $hdr -Body $chain -ContentType "application/json" -TimeoutSec 20
        $j = $r.Content | ConvertFrom-Json
        return ($j.ran -eq 2) -and ($j.vars.token -eq "chainTok9") -and ($j.vars.echoed -eq "Bearer chainTok9")
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== JWT attack toolkit ===" -ForegroundColor Cyan
# Mint a token at runtime (HS256, secret 'letmein', admin claim, no exp)
# so we never commit a JWT fixture and the test is self-verifying.
function New-B64Url([byte[]]$b){ [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }
$jwtSecret = 'letmein'
$jwtHb = New-B64Url([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
$jwtPb = New-B64Url([Text.Encoding]::UTF8.GetBytes('{"sub":"42","name":"Jane","admin":true,"iat":1516239022}'))
$jwtSi = "$jwtHb.$jwtPb"
$jwtHmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($jwtSecret))
$jwtSig = New-B64Url($jwtHmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($jwtSi)))
$jwt = "$jwtSi.$jwtSig"

Test-Endpoint "jwt analyze decodes + flags no-exp and priv-claim" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/jwt/analyze" -Method POST -Headers $hdr -Body (@{token=$jwt} | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 10
    $j = $r.Content | ConvertFrom-Json
    $ids = @($j.weaknesses | ForEach-Object { $_.id })
    return ($j.alg -eq "HS256") -and ($j.payload.admin -eq $true) -and ($ids -contains "jwt-no-exp") -and ($ids -contains "jwt-priv-claim")
}

Test-Endpoint "jwt analyze brute-forces a weak HS256 secret" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/jwt/analyze" -Method POST -Headers $hdr -Body (@{token=$jwt; wordlist=@("admin","wrong","letmein","123456")} | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 10
    $j = $r.Content | ConvertFrom-Json
    return ($j.secretRecovered -eq $true) -and ($j.secret -eq "letmein")
}

Test-Endpoint "jwt forge none strips signature (alg:none bypass)" {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/jwt/forge" -Method POST -Headers $hdr -Body (@{token=$jwt; attack="none"; claims=@{admin=$true}} | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 10
    $j = $r.Content | ConvertFrom-Json
    return ($j.ok -eq $true) -and ($j.token.EndsWith("."))
}

Test-Endpoint "jwt forge hs256 produces a token that re-validates" {
    $f = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/jwt/forge" -Method POST -Headers $hdr -Body (@{token=$jwt; attack="hs256"; secret=$jwtSecret; claims=@{role="superadmin"}} | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 10
    $fj = $f.Content | ConvertFrom-Json
    if (-not $fj.token) { return $false }
    $v = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/jwt/analyze" -Method POST -Headers $hdr -Body (@{token=$fj.token; wordlist=@($jwtSecret)} | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 10
    $vj = $v.Content | ConvertFrom-Json
    return ($vj.secretRecovered -eq $true) -and ($vj.payload.role -eq "superadmin")
}

# Cleanup
Stop-Process -Id $nl.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

Write-Host ""
Write-Host ("=" * 60)
Write-Host "v3 validation: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Yellow' })
Write-Host ("=" * 60)
exit $(if ($fail -eq 0) { 0 } else { 1 })
