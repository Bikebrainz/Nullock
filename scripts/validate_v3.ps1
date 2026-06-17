# v3 validation: hits the endpoints I shipped but never actually tested.
# Spins up a fresh NullockApp instance, fires real HTTP calls at the
# endpoints, asserts the responses are shaped correctly. Doesn't depend
# on httpbin -- only loopback.
#
# Pass = endpoint returns a real JSON shape, not 404 / 500 / empty.

$ErrorActionPreference = 'Continue'
$exe = "D:\dev\Nullock\Build\Src\App\Release\NullockApp.exe"

# Clean slate: a stray NullockApp from a prior/overlapping run holding the
# control port (or in TIME_WAIT), or leftover mock-listener jobs, is the main
# cause of the suite hanging. Kill both before we start, and randomize ports so
# we never collide with a port still winding down.
Get-Process NullockApp -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Job -ErrorAction SilentlyContinue | Stop-Job -ErrorAction SilentlyContinue
Get-Job -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$projDir = Join-Path $env:TEMP "nullock-v3val-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $projDir | Out-Null
$proxyPort = Get-Random -Minimum 20000 -Maximum 45000
$ctlPort   = Get-Random -Minimum 20000 -Maximum 45000

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

Write-Host "`n=== ScopeGuard ===" -ForegroundColor Cyan
Test-Endpoint "active tests + scans refuse out-of-scope hosts, run again once back in scope" {
    function Sc($p,$g){ Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/$p" -Headers $hdr -Body (@{glob=$g}|ConvertTo-Json) -ContentType "application/json" -TimeoutSec 10 | Out-Null }
    function Sqli { (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/sqli/test" -Headers $hdr -Body (@{url="http://127.0.0.1:59999/x";param="id"}|ConvertTo-Json) -ContentType "application/json" -TimeoutSec 15).Content | ConvertFrom-Json }
    function Psn { (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/portscan/start" -Headers $hdr -Body (@{host="127.0.0.1";preset="discovery"}|ConvertTo-Json) -ContentType "application/json" -TimeoutSec 15).Content | ConvertFrom-Json }
    try {
        $allow = Sqli                                  # no scope -> allowed (runs, fails to connect)
        Sc "scope/out/add" "127.0.0.1"; Start-Sleep -Milliseconds 400
        $blkSqli = Sqli
        $blkPsn  = Psn
        return ($allow.scopeBlocked -ne $true) -and ($blkSqli.scopeBlocked -eq $true) -and ($blkPsn.scopeBlocked -eq $true)
    } finally {
        # MUST restore -- every other test targets 127.0.0.1.
        Sc "scope/out/remove" "127.0.0.1"; Start-Sleep -Milliseconds 300
    }
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

Test-Endpoint "oast blast fires SSRF+XXE vectors and a callback confirms by class" {
    # Blast a dead target -- sends fail fast but every token is registered.
    # Then fire the XXE vector's callback ourselves and assert a confirmed
    # finding of the right class appears.
    $blast = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/oast/blast" -Method POST -Headers $hdr -Body (@{ url="http://127.0.0.1:9/api/fetch" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 15
    $bj = $blast.Content | ConvertFrom-Json
    if ($bj.fired -lt 2) { return $false }
    $kinds = @($bj.vectors | ForEach-Object { $_.kind } | Sort-Object -Unique)
    if (-not ($kinds -contains "ssrf-oast") -or -not ($kinds -contains "xxe-oast")) { return $false }
    $xxe = $bj.vectors | Where-Object { $_.kind -eq "xxe-oast" } | Select-Object -First 1
    if (-not $xxe) { return $false }
    try { Invoke-WebRequest -UseBasicParsing -Uri $xxe.callbackUrl -TimeoutSec 5 | Out-Null } catch { return $false }
    Start-Sleep -Milliseconds 800
    $snap = (Invoke-WebRequest -UseBasicParsing -Uri "$base/api/snapshot" -Headers $hdr -TimeoutSec 5).Content | ConvertFrom-Json
    $f = @($snap.findings | Where-Object { $_.kind -eq "xxe-oast-confirmed" })
    return ($f.Count -ge 1) -and ($f[0].cwe -eq "CWE-611")
}

Test-Endpoint "DNS sink: a name-only callback auto-confirms" {
    # The HTTP sink can't see OOB that only does a DNS lookup (Log4Shell,
    # blind-SQLi DNS exfil). Mint a registered token, then send a raw DNS
    # A-query for <token>.oast to the UDP sink and assert it correlates.
    $snap0 = (Invoke-WebRequest -UseBasicParsing -Uri "$base/api/snapshot" -Headers $hdr -TimeoutSec 5).Content | ConvertFrom-Json
    if (-not $snap0.oast.dnsRunning) { return $false }
    $dnsPort = [int]$snap0.oast.dnsPort
    $m = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/oast/mint" -Headers $hdr -Body (@{register=$true; host="victim.corp"; param="dns"; note="v3-dns"} | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 5).Content | ConvertFrom-Json
    if (-not $m.token) { return $false }
    # Build a minimal DNS A-query for <token>.oast.
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    $bw.Write([byte[]]@(0x13,0x37, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00))
    foreach ($lbl in @($m.token, "oast")) {
        $b = [Text.Encoding]::ASCII.GetBytes($lbl); $bw.Write([byte]$b.Length); $bw.Write($b)
    }
    $bw.Write([byte]0); $bw.Write([byte[]]@(0x00,0x01, 0x00,0x01)); $bw.Flush()
    $pkt = $ms.ToArray()
    $udp = New-Object System.Net.Sockets.UdpClient
    [void]$udp.Send($pkt, $pkt.Length, "127.0.0.1", $dnsPort)
    $udp.Close()
    Start-Sleep -Milliseconds 900
    $snap1 = (Invoke-WebRequest -UseBasicParsing -Uri "$base/api/snapshot" -Headers $hdr -TimeoutSec 5).Content | ConvertFrom-Json
    $f = @($snap1.findings | Where-Object { $_.kind -eq "ssrf-oast-confirmed" -and $_.evidence -like "*DNS*" })
    return ($snap1.oast.dnsHits -ge 1) -and ($f.Count -ge 1)
}

Write-Host "`n=== Parameter mining ===" -ForegroundColor Cyan
Test-Endpoint "paramminer finds a reflected param and a status-flip param" {
    # Local origin: reflects ?q= in the body, returns 500 when ?debug present.
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 400; $i++) {
            try {
                $c=$l.GetContext(); $qs=$c.Request.QueryString
                $status=200; $body="<html>baseline</html>"
                if ($qs["q"]) { $body="<html>echo:" + $qs["q"] + "</html>" }
                if ($null -ne $qs["debug"]) { $status=500 }
                $c.Response.StatusCode=$status
                $buf=[Text.Encoding]::UTF8.GetBytes($body)
                $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $r = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/paramminer" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/app" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 60).Content | ConvertFrom-Json
        $reflected = @($r.found | Where-Object { $_.name -eq "q" -and $_.signal -eq "reflected" })
        $flip      = @($r.found | Where-Object { $_.name -eq "debug" -and $_.signal -eq "status-change" })
        return ($r.ok -eq $true) -and ($reflected.Count -ge 1) -and ($flip.Count -ge 1)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Test-Endpoint "paramminer guards against targets that flip on any param" {
    # A target that 500s on ANY query param must NOT flood every candidate
    # as a hidden param -- the control probe should disable the status
    # signal and report zero status-change findings.
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 400; $i++) {
            try {
                $c=$l.GetContext()
                $st = 200; if ($c.Request.Url.Query.Length -gt 0) { $st = 500 }
                $c.Response.StatusCode=$st
                $buf=[Text.Encoding]::UTF8.GetBytes("x")
                $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $r = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/paramminer" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/app" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 60).Content | ConvertFrom-Json
        $statusFinds = @($r.found | Where-Object { $_.signal -eq "status-change" })
        return ($r.statusSignalUsable -eq $false) -and ($statusFinds.Count -eq 0)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Deep-scan orchestrator ===" -ForegroundColor Cyan
Test-Endpoint "audit runs the battery and aggregates findings from multiple testers" {
    # One multi-vuln endpoint: distinct object per id (IDOR), reflects ?q
    # (param mining), reflects Origin+creds (CORS). One /api/audit/run call
    # should surface findings from all three.
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 400; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $q=$c.Request.QueryString; $o=$c.Request.Headers["Origin"]; $m=$c.Request.HttpMethod
                if ($o) { $c.Response.Headers.Add("Access-Control-Allow-Origin",$o); $c.Response.Headers.Add("Access-Control-Allow-Credentials","true") }
                $st=200; $b="default"
                if ($p -match '/api/orders/(\d+)') {
                    $idn=[int]$Matches[1]
                    if ($idn -le 100) { $b="order #$idn FULL RECORD owner=user$idn balance=10000 confidential-$idn"; if ($q["q"]) { $b+=" echo:"+$q["q"] } } else { $st=404; $b="nf" }
                }
                $c.Response.StatusCode=$st
                if ($m -ne 'HEAD') { $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.OutputStream.Write($buf,0,$buf.Length) }
                $c.Response.Close()
            } catch { try { $c.Response.Abort() } catch {} }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $a = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/audit/run" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/api/orders/5"; include=@("params","idor","cors") } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 90).Content | ConvertFrom-Json
        $bt=@{}; $a.testers | ForEach-Object { $bt[$_.tester]=$_.items }
        return ($a.totalFindings -ge 3) -and ($bt['param-mining'] -ge 1) -and ($bt['idor'] -ge 1) -and ($bt['cors'] -ge 1)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Test-Endpoint "audit battery now includes open-redirect and SSTI testers" {
    # /page: redirects ?next to a sentinel host (open redirect) and evaluates
    # a Jinja-style {{int*int}} in ?name (SSTI). One audit/run surfaces both.
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 800; $i++) {
            try {
                $c=$l.GetContext(); $req=$c.Request; $p=$req.Url.AbsolutePath
                $next=$req.QueryString["next"]; $name=$req.QueryString["name"]; if ($null -eq $name) { $name="" }
                if ($p -eq "/page" -and $next -and ($next -match 'nullock-oob\.test')) {
                    $c.Response.StatusCode=302; try { $c.Response.RedirectLocation=$next } catch { $c.Response.StatusCode=400 }; $c.Response.Close()
                } elseif ($p -eq "/page") {
                    $out=[regex]::Replace($name,'\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}',{ param($m) [string]([int64]$m.Groups[1].Value*[int64]$m.Groups[2].Value) })
                    $b=[Text.Encoding]::UTF8.GetBytes("Hi $out"); $c.Response.StatusCode=200; $c.Response.OutputStream.Write($b,0,$b.Length); $c.Response.Close()
                } else { $b=[Text.Encoding]::UTF8.GetBytes("ok"); $c.Response.StatusCode=200; $c.Response.OutputStream.Write($b,0,$b.Length); $c.Response.Close() }
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $a = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/audit/run" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/page?next=/home&name=guest"; include=@("openredirect","ssti","cache") } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 90).Content | ConvertFrom-Json
        $bt=@{}; $a.testers | ForEach-Object { $bt[$_.tester]=$_.items }
        return ($bt['open-redirect'] -ge 1) -and ($bt['ssti'] -ge 1) -and ($a.testers.tester -contains 'cache-poisoning')
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Test-Endpoint "audit all queues URLs and lands findings async" {
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 800; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $q=$c.Request.QueryString; $o=$c.Request.Headers["Origin"]; $m=$c.Request.HttpMethod
                if ($o) { $c.Response.Headers.Add("Access-Control-Allow-Origin",$o); $c.Response.Headers.Add("Access-Control-Allow-Credentials","true") }
                $st=200; $b="default"
                if ($p -match '/api/orders/(\d+)') { $idn=[int]$Matches[1]
                    if ($idn -le 100) { $b="order #$idn FULL RECORD owner=user$idn confidential-$idn"; if ($q["q"]) { $b+=" echo:"+$q["q"] } } else { $st=404; $b="nf" } }
                $c.Response.StatusCode=$st
                if ($m -ne 'HEAD') { $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.OutputStream.Write($buf,0,$buf.Length) }
                $c.Response.Close()
            } catch { try { $c.Response.Abort() } catch {} }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $urls = @("http://127.0.0.1:$oport/api/orders/5","http://127.0.0.1:$oport/api/orders/7")
        $a = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/audit/all" -Headers $hdr -Body (@{ urls=$urls; include=@("params","idor","cors") } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        if ($a.queued -ne 2) { return $false }
        Start-Sleep -Seconds 12
        $snap=(Invoke-WebRequest -UseBasicParsing -Uri "$base/api/snapshot" -Headers $hdr -TimeoutSec 5).Content | ConvertFrom-Json
        $af = @($snap.findings | Where-Object { $_.evidence -like '*deep audit*' })
        return $af.Count -ge 4
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Verb-tampering auth bypass ===" -ForegroundColor Cyan
Test-Endpoint "verbtamper flags a HEAD/override bypass, clean when all denied" {
    # vuln: GET /admin -> 403 but HEAD -> 200 and X-HTTP-Method-Override:GET -> 200.
    # secure: every method -> 403.
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 200; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $m=$c.Request.HttpMethod
                $ov=$c.Request.Headers["X-HTTP-Method-Override"]
                $st=403; $body="DENIED-403-PAGE"
                if ($p -like '*vuln*') {
                    if ($m -eq 'HEAD' -or $ov) { $st=200; $body="SECRET-PROTECTED-DATA" }
                }
                $c.Response.StatusCode=$st
                if ($m -ne 'HEAD') { $buf=[Text.Encoding]::UTF8.GetBytes($body); $c.Response.OutputStream.Write($buf,0,$buf.Length) }
                $c.Response.Close()
            } catch { try { $c.Response.Abort() } catch {} }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/verbtamper/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/admin/vuln" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/verbtamper/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/admin/secure" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        return ($v.baselineDenied -eq $true) -and ($v.bypassCount -ge 1) -and ($s.bypassCount -eq 0)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Server-side template injection ===" -ForegroundColor Cyan
Test-Endpoint "ssti confirms an evaluated polyglot + fingerprints engine, ignores literal reflection" {
    # vuln /greet: Jinja2-style -- evaluates {{ int*int }} only.
    # safe /safe: reflects the raw value verbatim (no evaluation).
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 200; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $name=$c.Request.QueryString["name"]; if ($null -eq $name) { $name="" }
                if ($p -like '*greet*') {
                    $out=[regex]::Replace($name,'\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}',{ param($m) [string]([int64]$m.Groups[1].Value*[int64]$m.Groups[2].Value) }); $out="Hello, $out!"
                } else { $out="Hello, $name!" }
                $buf=[Text.Encoding]::UTF8.GetBytes($out); $c.Response.StatusCode=200; $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/ssti/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/greet?name=x"; param="name" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 40).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/ssti/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/safe?name=x"; param="name" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 40).Content | ConvertFrom-Json
        return ($v.confirmed -eq $true) -and ($v.engines -match 'Jinja2') -and ($s.injected -eq $true) -and ($s.confirmed -eq $false)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Web cache poisoning ===" -ForegroundColor Cyan
Test-Endpoint "cache poisoning confirms a keyed-cache hit, refuses to inject on an unkeyed cache" {
    # /vuln: cache keyed on the ncb buster, reflects X-Forwarded-Host (safe to test, confirmable).
    # /unkeyed: cache IGNORES ncb -> injecting would hit the real key -> tester must abort.
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        $cache=@{}
        for ($i=0; $i -lt 400; $i++) {
            try {
                $c=$l.GetContext(); $req=$c.Request; $p=$req.Url.AbsolutePath
                $xfh=$req.Headers["X-Forwarded-Host"]; $ncb=$req.QueryString["ncb"]
                $body=""; $xcache="MISS"; $cc="public, max-age=60"
                $key = if ($p -eq '/unkeyed') { 'unkeyed' } else { "$p|$ncb" }   # /unkeyed ignores the buster
                if ($cache.ContainsKey($key)) { $body=$cache[$key]; $xcache="HIT" }
                else { $h = if ($xfh) { $xfh } else { $req.UserHostName }; $body="<a href='http://$h/x'>x</a>"; $cache[$key]=$body }
                $buf=[Text.Encoding]::UTF8.GetBytes($body); $c.Response.StatusCode=200
                $c.Response.Headers["Cache-Control"]=$cc; $c.Response.Headers["X-Cache"]=$xcache
                $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/cache/poison" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/vuln" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 40).Content | ConvertFrom-Json
        $u = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/cache/poison" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/unkeyed" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 40).Content | ConvertFrom-Json
        $vc = ($v.hits | Where-Object { $_.header -eq 'X-Forwarded-Host' }).cacheConfirmed
        return ($v.anyConfirmed -eq $true) -and ($vc -eq $true) -and ($u.hitCount -eq 0) -and ($u.error -match 'unkeyed')
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== TLS / certificate inspection ===" -ForegroundColor Cyan
Test-Endpoint "tls inspect flags a self-signed certificate" {
    $tlsPort = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=nullock.test", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $tmp = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(60))
        $pfx = $tmp.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "pw")
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx, "pw",
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,$port); $l.Start()
        for($i=0;$i -lt 8;$i++){ try{
            $cl=$l.AcceptTcpClient(); $ssl=[System.Net.Security.SslStream]::new($cl.GetStream(),$false)
            try { $ssl.AuthenticateAsServer($cert,$false,[System.Security.Authentication.SslProtocols]::Tls12,$false) } catch {}
            Start-Sleep -Milliseconds 150; try { $ssl.Close() } catch {}; try { $cl.Close() } catch {}
        }catch{break} }
        try{$l.Stop()}catch{}
    } -ArgumentList $tlsPort
    Start-Sleep -Seconds 1
    try {
        $r = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/tls/inspect" -Headers $hdr -Body (@{ host="127.0.0.1"; port=$tlsPort; probeLegacy=$false } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        return ($r.connected -eq $true) -and ($r.selfSigned -eq $true) -and ($r.findings.kind -contains 'tls-self-signed') -and ($r.keyBits -eq 2048)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Service-version CVE matching ===" -ForegroundColor Cyan
Test-Endpoint "vulnscan flags a known-vulnerable service banner, ignores a patched version" {
    # Two raw-TCP banner servers: vulnerable vsftpd 2.3.4 + patched OpenSSH 9.8p1.
    $p1 = Get-Random -Minimum 20000 -Maximum 45000
    $p2 = Get-Random -Minimum 20000 -Maximum 45000
    $mk = {
        param($port,$banner)
        $l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,$port); $l.Start()
        for($i=0;$i -lt 20;$i++){ try{
            $cl=$l.AcceptTcpClient(); $ns=$cl.GetStream()
            $b=[Text.Encoding]::ASCII.GetBytes($banner + "`r`n"); $ns.Write($b,0,$b.Length); $ns.Flush()
            Start-Sleep -Milliseconds 250; $cl.Close()
        }catch{break} }
        try{$l.Stop()}catch{}
    }
    $j1 = Start-Job -ScriptBlock $mk -ArgumentList $p1,"220 (vsFTPd 2.3.4)"
    $j2 = Start-Job -ScriptBlock $mk -ArgumentList $p2,"SSH-2.0-OpenSSH_9.8p1"
    Start-Sleep -Milliseconds 800
    try {
        $r = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/servicevulns/scan" -Headers $hdr -Body (@{ host="127.0.0.1"; ports=@($p1,$p2) } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        return ($r.hits.cveId -contains 'CVE-2011-2523') -and (-not ($r.hits.cveId -contains 'CVE-2024-6387'))
    } finally {
        $j1,$j2 | Stop-Job -ErrorAction SilentlyContinue; $j1,$j2 | Remove-Job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== HTTP request smuggling ===" -ForegroundColor Cyan
Test-Endpoint "smuggling flags a CL.TE desync by reproducible timing, clean on a fast server" {
    # Raw-TCP mock: /clte stalls 6s on the CL.TE desync probe (desync); /safe never stalls.
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $listener=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,$port); $listener.Start()
        for ($i=0; $i -lt 60; $i++) {
            try {
                $cl=$listener.AcceptTcpClient(); $ns=$cl.GetStream(); $ns.ReadTimeout=800
                $buf=New-Object byte[] 8192; $req=""
                try { do { $n=$ns.Read($buf,0,$buf.Length); if($n -le 0){break}; $req+=[Text.Encoding]::ASCII.GetString($buf,0,$n) } until ($req -match "`r`n`r`n") } catch {}
                $path=(($req -split "`r`n")[0] -split ' ')[1]
                $hasTE = $req.ToLower() -match 'transfer-encoding:\s*chunked'
                if ($path -eq "/clte" -and $hasTE -and $req.Contains("1`r`nA")) { Start-Sleep -Seconds 6 }
                $body="ok"; $resp="HTTP/1.1 200 OK`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body"
                $bytes=[Text.Encoding]::ASCII.GetBytes($resp); try { $ns.Write($bytes,0,$bytes.Length); $ns.Flush() } catch {}; $cl.Close()
            } catch { break }
        }
        try { $listener.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/smuggle/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/clte" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 120).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/smuggle/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/safe" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 120).Content | ConvertFrom-Json
        return ($v.vulnerable -eq $true) -and ($v.hits[0].variant -eq 'CL.TE') -and ($s.vulnerable -eq $false)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== NoSQL injection ===" -ForegroundColor Cyan
Test-Endpoint "nosqli confirms operator interpretation, suppresses dynamic + type-confusion + safe" {
    # /vuln: user[$ne] matches everything (long); /safe: never; /dynamic: random length; /typeconf: 500 on any [$.
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        $r=[Random]::new()
        for ($i=0; $i -lt 600; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath
                $q=[System.Uri]::UnescapeDataString($c.Request.Url.Query)
                $code=200; $b="Invalid credentials"
                if ($p -eq "/vuln") { if ($q.Contains('user[$ne]')) { $b="Welcome back, admin! Private dashboard with account details, recent orders, and full settings panel content here." } }
                elseif ($p -eq "/dynamic") { $b="results: " + ("x" * $r.Next(10,400)) }
                elseif ($p -eq "/typeconf") { if ($q.Contains('[$')) { $code=500; $b="TypeError: cannot convert object to string at handler" } }
                $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.StatusCode=$code; $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        function NoSqli($path) { ((Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/nosqli/test" -Headers $hdr -Body (@{ url=("http://127.0.0.1:{0}/{1}?user=admin" -f $oport,$path); param="user" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json).vulnerable }
        return (NoSqli "vuln") -and (-not (NoSqli "safe")) -and (-not (NoSqli "dynamic")) -and (-not (NoSqli "typeconf"))
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== XXE (XML external entity) ===" -ForegroundColor Cyan
Test-Endpoint "xxe confirms external-entity file read by content signature, clean when entities disabled" {
    # /vuln resolves the external entity (returns passwd content); /safe never does.
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 300; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath
                $rd=[System.IO.StreamReader]::new($c.Request.InputStream); $body=$rd.ReadToEnd(); $rd.Close()
                $b="<r>parsed</r>"
                if ($p -eq "/vuln" -and $body -match 'file:///etc/passwd') { $b="<r>root:x:0:0:root:/root:/bin/bash`nbin:x:1:1:bin:/bin:/usr/sbin/nologin</r>" }
                $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.StatusCode=200; $c.Response.ContentType="application/xml"; $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/xxe/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/vuln" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/xxe/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/safe" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        return ($v.vulnerable -eq $true) -and ($v.hits[0].target -eq '/etc/passwd') -and ($s.vulnerable -eq $false)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== SQL injection (error-based) ===" -ForegroundColor Cyan
Test-Endpoint "sqli confirms a DBMS error on an unbalanced quote, clean on parameterized + always-erroring pages" {
    # /vuln errors when the id has an odd number of quotes; /safe never errors; /always errors regardless (baseline guard).
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        $err="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        for ($i=0; $i -lt 400; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $q=$c.Request.QueryString["id"]; if ($null -eq $q) { $q="" }
                $cnt=($q.ToCharArray() | Where-Object {$_ -eq "'"}).Count
                $b="<html>Product results for id $q</html>"
                if ($p -eq "/vuln") { if ($cnt % 2 -eq 1) { $b="<html>DB problem: $err</html>" } }
                elseif ($p -eq "/always") { $b="<html>DB problem: $err</html>" }
                $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.StatusCode=200; $c.Response.ContentType="text/html"; $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        function Sqli($path) { (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/sqli/test" -Headers $hdr -Body (@{ url=("http://127.0.0.1:{0}/{1}?id=5" -f $oport,$path); param="id" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json }
        $v = Sqli "vuln"
        return ($v.vulnerable -eq $true) -and ($v.hits[0].dbms -eq 'MySQL') -and (-not (Sqli "safe").vulnerable) -and (-not (Sqli "always").vulnerable)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Reflected XSS ===" -ForegroundColor Cyan
Test-Endpoint "reflected XSS confirms unencoded element-content reflection, suppresses JSON/comment/attr/encoded" {
    # /vuln reflects raw into element content; /safe encodes; /json is non-HTML; /comment & /attr are non-executing.
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 400; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $f=$c.Request.QueryString["q"]; if ($null -eq $f) { $f="" }
                $ct="text/html"; $b=""
                switch ($p) {
                    "/vuln"    { $b="<html><body><h1>Results for: $f</h1></body></html>" }
                    "/safe"    { $enc=$f -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'; $b="<html><body>$enc</body></html>" }
                    "/json"    { $ct="application/json"; $b="{""query"":""$f""}" }
                    "/comment" { $b="<html><body><!-- $f --></body></html>" }
                    "/attr"    { $b="<html><body><input value=`"$f`"></body></html>" }
                    default    { $b="<html>ok</html>" }
                }
                $c.Response.ContentType=$ct; $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.StatusCode=200; $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        function Vuln($path) { ((Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/xss/test" -Headers $hdr -Body (@{ url=("http://127.0.0.1:{0}/{1}?q=hello" -f $oport,$path); param="q" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json).vulnerable }
        return (Vuln "vuln") -and (-not (Vuln "safe")) -and (-not (Vuln "json")) -and (-not (Vuln "comment")) -and (-not (Vuln "attr"))
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== OS command injection ===" -ForegroundColor Cyan
Test-Endpoint "command injection confirms shell exec via arithmetic, clean on literal reflection" {
    # /vuln expands $((a*b)) like a shell that ran the command; /safe reflects the value literally.
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 300; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $f=$c.Request.QueryString["cmd"]; if ($null -eq $f) { $f="" }
                if ($p -eq "/vuln") {
                    $out=[regex]::Replace($f,'\$\(\((\d+)\*(\d+)\)\)',{ param($m) [string]([int64]$m.Groups[1].Value*[int64]$m.Groups[2].Value) })
                    $b="PING output for: $out"
                } else { $b="result: $f" }
                $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.StatusCode=200; $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/cmdi/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/vuln?cmd=8.8.8.8"; param="cmd" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/cmdi/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/safe?cmd=8.8.8.8"; param="cmd" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        return ($v.vulnerable -eq $true) -and ($v.hits[0].evidence -match 'executed') -and ($s.vulnerable -eq $false)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Path traversal / LFI ===" -ForegroundColor Cyan
Test-Endpoint "path traversal confirms /etc/passwd by content signature, ignores sanitized + prose mentions" {
    # /vuln returns passwd content when ?file traverses; /safe strips ../; /docs prose-mentions root:x:0:0:.
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 300; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $f=$c.Request.QueryString["file"]; if ($null -eq $f) { $f="" }
                $b="file not found"
                if ($p -eq "/vuln") { if ($f -match 'etc/passwd') { $b="root:x:0:0:root:/root:/bin/bash`nbin:x:1:1:bin:/bin:/usr/sbin/nologin" } }
                elseif ($p -eq "/safe") { $clean=$f -replace '\.\./','' -replace '\.\.\\',''; $b="serving: $clean" }
                elseif ($p -eq "/docs") { $b="<p>The line root:x:0:0: defines the root account.</p>" }
                $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.StatusCode=200; $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/pathtraversal/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/vuln?file=home.txt"; param="file" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/pathtraversal/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/safe?file=home.txt"; param="file" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        $d = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/pathtraversal/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/docs?file=home.txt"; param="file" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        return ($v.vulnerable -eq $true) -and ($v.hits[0].target -eq '/etc/passwd') -and ($s.vulnerable -eq $false) -and ($d.vulnerable -eq $false)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== CRLF / response splitting ===" -ForegroundColor Cyan
Test-Endpoint "crlf injection confirms an injected header on a vulnerable param, clean when CR/LF stripped" {
    # Raw TCP mock: reflects the ?redirect value into an X-Echo response header.
    # /vuln writes it unsanitized (CRLF splits a new header in); /clean strips CR/LF.
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $listener=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,$port); $listener.Start()
        for ($i=0; $i -lt 300; $i++) {
            try {
                $cl=$listener.AcceptTcpClient(); $ns=$cl.GetStream()
                $buf=New-Object byte[] 8192; $req=""
                do { $n=$ns.Read($buf,0,$buf.Length); if($n -le 0){break}; $req+=[Text.Encoding]::ASCII.GetString($buf,0,$n) } until ($req -match "`r`n`r`n")
                $line=($req -split "`r`n")[0]; $target=($line -split ' ')[1]
                $pth=$target.Split('?')[0]; $query=if($target.Contains('?')){$target.Split('?',2)[1]}else{""}
                $rv=""
                foreach($pair in $query.Split('&')){ $kv=$pair.Split('=',2); if($kv[0] -eq 'redirect' -and $kv.Count -eq 2){ $rv=[System.Uri]::UnescapeDataString($kv[1]) } }
                if($pth.EndsWith('clean')){ $rv=$rv -replace "`r","" -replace "`n","" }
                $body="ok"
                $resp="HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nX-Echo: $rv`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body"
                $bytes=[Text.Encoding]::ASCII.GetBytes($resp); $ns.Write($bytes,0,$bytes.Length); $ns.Flush(); $cl.Close()
            } catch { break }
        }
        try { $listener.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/crlf/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/vuln?redirect=x"; param="redirect" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/crlf/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/clean?redirect=x"; param="redirect" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        return ($v.vulnerable -eq $true) -and ($v.hitCount -ge 1) -and ($v.hits.param -contains 'redirect') -and ($s.vulnerable -eq $false)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Secret scanning ===" -ForegroundColor Cyan
Test-Endpoint "secret scan finds provider keys across page + JS, excludes placeholders, never leaks cleartext" {
    # Mint fake key shapes at RUNTIME (never commit literal key shapes -- push protection).
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        $UP='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; $AN='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        $aws='AKIA'+(-join((1..16)|%{$UP[(Get-Random -Max $UP.Length)]}))
        $goog='AIza'+(-join((1..35)|%{$AN[(Get-Random -Max $AN.Length)]}))
        $stripe='sk_'+'live_'+(-join((1..24)|%{$AN[(Get-Random -Max $AN.Length)]}))
        $assigned=(-join((1..30)|%{$AN[(Get-Random -Max $AN.Length)]}))
        $js="var cfg={awsKey:'$aws',gKey:'$goog',stripe:'$stripe'};var apiKey = `"$assigned`";var ph='your-api-key-here';"
        for ($i=0; $i -lt 200; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $r=$c.Response; $b=""
                if ($p -eq "/app") { $r.ContentType="text/html"; $b="<html><head><script src='/bundle.js'></script></head><body>x</body></html>" }
                elseif ($p -eq "/bundle.js") { $r.ContentType="application/javascript"; $b=$js }
                else { $b="ok" }
                $buf=[Text.Encoding]::UTF8.GetBytes($b); $r.StatusCode=200; $r.OutputStream.Write($buf,0,$buf.Length); $r.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/secrets/scan" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/app" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 20).Content | ConvertFrom-Json
        $types = $s.hits.type
        $txt = ($s.hits | ForEach-Object { "$($_.context) $($_.masked)" }) -join ' '
        $leak = ($txt -match 'AIza[A-Za-z0-9_\-]{35}') -or ($txt -match 'AKIA[A-Z0-9]{16}')
        return ($types -contains 'aws-access-key-id') -and ($types -contains 'google-api-key') -and ($types -contains 'stripe-secret-key') `
               -and (($types | Where-Object { $_ -eq 'assigned-secret' }).Count -eq 1) -and ($s.resourcesScanned -eq 2) -and (-not $leak)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Security-header / CSP audit ===" -ForegroundColor Cyan
Test-Endpoint "header audit flags a weak CSP + bypassable gadget host, clean on a hardened policy" {
    # /weak: unsafe-inline + ajax.googleapis.com gadget host, no nosniff/XFO, flagless cookie.
    # /strong: nonce + strict-dynamic, object-src/base-uri/frame-ancestors none, nosniff, hardened cookie.
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 200; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $r=$c.Response
                if ($p -eq "/weak") {
                    $r.Headers.Add("Content-Security-Policy","script-src 'self' 'unsafe-inline' ajax.googleapis.com")
                    $r.Headers.Add("Set-Cookie","sid=abc123")
                } elseif ($p -eq "/strong") {
                    $r.Headers.Add("Content-Security-Policy","script-src 'nonce-r4nd' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
                    $r.Headers.Add("X-Content-Type-Options","nosniff")
                    $r.Headers.Add("Referrer-Policy","no-referrer")
                    $r.Headers.Add("Set-Cookie","sid=abc123; HttpOnly; SameSite=Strict")
                }
                $b=[Text.Encoding]::UTF8.GetBytes("ok"); $r.StatusCode=200; $r.OutputStream.Write($b,0,$b.Length); $r.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $w = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/headers/audit" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/weak" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 20).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/headers/audit" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/strong" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 20).Content | ConvertFrom-Json
        $wk = $w.findings.key; $sk = $s.findings.key
        return ($wk -contains 'csp-unsafe-inline') -and ($wk -contains 'csp-bypassable-host') -and ($wk -contains 'clickjacking-missing') -and ($wk -contains 'cookie-insecure') `
               -and (-not ($sk -contains 'csp-unsafe-inline')) -and (-not ($sk -contains 'csp-bypassable-host')) -and ($s.findingCount -eq 0)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Open redirect ===" -ForegroundColor Cyan
Test-Endpoint "open redirect confirms via resolved Location host, ignores reflection + param-independent redirects" {
    # /login: redirects to ?next verbatim (vuln). /reflect: echoes next in a 200 body (no redirect).
    # /always: 302s to the sentinel regardless of param (must be reported inconclusive, not a hit).
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 500; $i++) {
            try {
                $c=$l.GetContext(); $req=$c.Request; $p=$req.Url.AbsolutePath; $next=$req.QueryString["next"]; if ($null -eq $next) { $next="" }
                if ($p -eq "/login") {
                    $c.Response.StatusCode=302; try { $c.Response.RedirectLocation=$next } catch { $c.Response.StatusCode=400 }; $c.Response.Close()
                } elseif ($p -eq "/reflect") {
                    $b=[Text.Encoding]::UTF8.GetBytes("you asked for: $next"); $c.Response.StatusCode=200; $c.Response.OutputStream.Write($b,0,$b.Length); $c.Response.Close()
                } elseif ($p -eq "/always") {
                    $c.Response.StatusCode=302; try { $c.Response.RedirectLocation="https://nullock-oob.test/" } catch {}; $c.Response.Close()
                } else { $b=[Text.Encoding]::UTF8.GetBytes("ok"); $c.Response.StatusCode=200; $c.Response.OutputStream.Write($b,0,$b.Length); $c.Response.Close() }
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v  = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/openredirect/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/login?next=/home" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 40).Content | ConvertFrom-Json
        $rf = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/openredirect/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/reflect?next=/home" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 40).Content | ConvertFrom-Json
        $al = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/openredirect/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/always?next=/home" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 40).Content | ConvertFrom-Json
        $loc = ($v.hits | Where-Object { $_.via -eq 'Location' }).Count
        return ($v.vulnerable -eq $true) -and ($loc -ge 6) -and ($v.testedParam -eq 'next') `
               -and ($rf.vulnerable -eq $false) `
               -and ($al.vulnerable -eq $false) -and ($al.error -match 'inconclusive')
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Race-condition tester ===" -ForegroundColor Cyan
Test-Endpoint "race flags a limited-use op, clean on atomic + idempotent" {
    # Listener with a per-path counter: race3 lets the first 3 succeed,
    # atomic the first 1, idempotent always. Firing 20 concurrent should
    # flag only race3 (1 < successes < count).
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        $n=@{}
        for ($i=0; $i -lt 200; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath
                if (-not $n.ContainsKey($p)) { $n[$p]=0 }; $n[$p]++
                $thr = if ($p -like '*race3*') {3} elseif ($p -like '*atomic*') {1} else {999999}
                $st = if ($n[$p] -le $thr) {200} else {409}
                $c.Response.StatusCode=$st
                $buf=[Text.Encoding]::UTF8.GetBytes("x"); $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $r3 = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/race/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/redeem/race3"; count=20; body='{}' } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 60).Content | ConvertFrom-Json
        $r1 = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/race/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/redeem/atomic"; count=20; body='{}' } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 60).Content | ConvertFrom-Json
        $ri = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/race/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/redeem/idem"; count=20; body='{}' } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 60).Content | ConvertFrom-Json
        return ($r3.raceSuspected -eq $true) -and ($r1.raceSuspected -eq $false) -and ($ri.raceSuspected -eq $false)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== JS recon (endpoints + source maps) ===" -ForegroundColor Cyan
Test-Endpoint "jsrecon mines endpoints + flags an exposed source map" {
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        $html='<html><head><script src="/static/app.js"></script><script src="https://cdn.example/lib.js"></script></head><body>hi</body></html>'
        $js="(function(){ fetch('/api/secret/users'); axios.get('/api/v2/orders'); })();`n//# sourceMappingURL=app.js.map"
        $map='{"version":3,"sources":["src/secret.ts","src/api/client.ts"],"mappings":"AAAA"}'
        for ($i=0; $i -lt 200; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $ct="text/html"; $b=$html
                if ($p -eq '/static/app.js') { $ct="application/javascript"; $b=$js }
                elseif ($p -eq '/static/app.js.map') { $ct="application/json"; $b=$map }
                $c.Response.ContentType=$ct
                $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $r = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/jsrecon/scan" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/app" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        $hasEp = ($r.endpoints -contains '/api/secret/users') -and ($r.endpoints -contains '/api/v2/orders')
        $sm = $r.sourceMaps | Where-Object { $_.accessible } | Select-Object -First 1
        return $hasEp -and ($null -ne $sm) -and ($sm.sources.Count -ge 2)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Active CORS exploitability ===" -ForegroundColor Cyan
Test-Endpoint "cors flags reflected-credentialed origin, clean on fixed allow-list" {
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 200; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $o=$c.Request.Headers["Origin"]
                if ($p -like '*secure*') {
                    $c.Response.Headers.Add("Access-Control-Allow-Origin","https://trusted.example")
                    $c.Response.Headers.Add("Access-Control-Allow-Credentials","true")
                } else {
                    if ($o) { $c.Response.Headers.Add("Access-Control-Allow-Origin",$o) }
                    $c.Response.Headers.Add("Access-Control-Allow-Credentials","true")
                }
                $buf=[Text.Encoding]::UTF8.GetBytes("data"); $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/cors/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/api/data" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/cors/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/api/secure" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 30).Content | ConvertFrom-Json
        $crit = @($v.probes | Where-Object { $_.kind -eq "cors-reflected-credentialed" })
        return ($crit.Count -ge 1) -and ($s.findingCount -eq 0)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Mass assignment (OWASP API #6) ===" -ForegroundColor Cyan
Test-Endpoint "massassign flags over-bound privileged fields, clean on allow-list" {
    # vuln ORM binds a broad set incl privileged fields; secure binds only
    # name/email. Both DROP genuinely-unknown fields (like the junk control).
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        $vulnSet=@('name','email','role','is_admin','admin','verified','is_verified','balance','status','active','plan','owner','user_id','permissions')
        $secSet=@('name','email')
        for ($i=0; $i -lt 600; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath
                $reader=New-Object System.IO.StreamReader($c.Request.InputStream); $raw=$reader.ReadToEnd()
                $allowed = if ($p -like '*secure*') { $secSet } else { $vulnSet }
                $out=@{}
                try { $obj=$raw | ConvertFrom-Json; foreach ($pr in $obj.PSObject.Properties) { if ($allowed -contains $pr.Name) { $out[$pr.Name]=$pr.Value } } } catch {}
                $b=($out | ConvertTo-Json -Compress); if (-not $b) { $b='{}' }
                $c.Response.StatusCode=200; $c.Response.ContentType="application/json"
                $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/massassign/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/api/users"; body='{"name":"alice"}' } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 60).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/massassign/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/api/secure/users"; body='{"name":"bob"}' } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 60).Content | ConvertFrom-Json
        $hasRole = @($v.found | Where-Object { $_.field -eq "role" }).Count -ge 1
        return ($v.reflectionUsable -eq $true) -and ($v.foundCount -ge 2) -and $hasRole -and ($s.foundCount -eq 0)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== IDOR / BOLA detection ===" -ForegroundColor Cyan
Test-Endpoint "idor flags neighboring objects on a vulnerable id, ignores a static page" {
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        for ($i=0; $i -lt 500; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath; $st=200; $b="default"
                if ($p -match '/api/orders/(\d+)') {
                    $idn=[int]$Matches[1]
                    if ($idn -le 100) { $b="order #$idn owner=user$idn unique-$idn" } else { $st=404; $b="not found" }
                } elseif ($p -match '/api/static/(\d+)') { $b="STATIC always identical" }
                $c.Response.StatusCode=$st
                $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/idor/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/api/orders/5" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 60).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/idor/test" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/api/static/5" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 60).Content | ConvertFrom-Json
        return ($v.findingCount -ge 1) -and ($v.findings[0].location -eq "path[3]") -and ($s.findingCount -eq 0)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
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

Write-Host "`n=== GraphQL schema analysis ===" -ForegroundColor Cyan
Test-Endpoint "graphql schema flags dangerous mutations + sensitive fields" {
    $oport = Get-Random -Minimum 20000 -Maximum 45000
    $job = Start-Job -ScriptBlock {
        param($port)
        $l=[System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
        $intro='{"data":{"__schema":{"mutationType":{"name":"Mutation"},"queryType":{"name":"Query"},"types":[{"name":"Query","kind":"OBJECT","fields":[{"name":"user"}]},{"name":"Mutation","kind":"OBJECT","fields":[{"name":"createUser"},{"name":"deleteUser"},{"name":"grantAdmin"}]},{"name":"User","kind":"OBJECT","fields":[{"name":"id"},{"name":"email"},{"name":"password"},{"name":"apiKey"}]}]}}}'
        $disabled='{"errors":[{"message":"introspection is disabled"}]}'
        for ($i=0; $i -lt 100; $i++) {
            try {
                $c=$l.GetContext(); $p=$c.Request.Url.AbsolutePath
                $b = if ($p -like '*secure*') { $disabled } else { $intro }
                $c.Response.StatusCode=200; $c.Response.ContentType="application/json"
                $buf=[Text.Encoding]::UTF8.GetBytes($b); $c.Response.OutputStream.Write($buf,0,$buf.Length); $c.Response.Close()
            } catch { break }
        }
        try { $l.Stop() } catch {}
    } -ArgumentList $oport
    Start-Sleep -Milliseconds 700
    try {
        $v = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/graphql/schema" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/graphql/vuln" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 15).Content | ConvertFrom-Json
        $s = (Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/graphql/schema" -Headers $hdr -Body (@{ url="http://127.0.0.1:$oport/graphql/secure" } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 15).Content | ConvertFrom-Json
        return ($v.introspectionEnabled -eq $true) -and ($v.dangerousMutations -contains "deleteUser") -and ($v.sensitiveFields -contains "User.password") -and ($s.introspectionEnabled -eq $false)
    } finally {
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
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
    $oport = Get-Random -Minimum 20000 -Maximum 45000   # random port avoids TIME_WAIT collisions across runs
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

# Cleanup: the instance plus any mock-listener jobs a test's finally may have
# missed, so a later run starts from a clean slate.
Stop-Process -Id $nl.Id -Force -ErrorAction SilentlyContinue
Get-Job -ErrorAction SilentlyContinue | Stop-Job -ErrorAction SilentlyContinue
Get-Job -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

Write-Host ""
Write-Host ("=" * 60)
Write-Host "v3 validation: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Yellow' })
Write-Host ("=" * 60)
exit $(if ($fail -eq 0) { 0 } else { 1 })
