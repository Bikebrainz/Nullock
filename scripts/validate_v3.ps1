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
    $oport = 19797
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
    $oport = 19796
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

Write-Host "`n=== JS recon (endpoints + source maps) ===" -ForegroundColor Cyan
Test-Endpoint "jsrecon mines endpoints + flags an exposed source map" {
    $oport = 19792
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
    $oport = 19793
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
    $oport = 19794
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
    $oport = 19795
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
