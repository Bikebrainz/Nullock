# Deterministic end-to-end integration smoke test for the analysis + reporting
# pipeline. Unlike validate_v3 (which spins up many Start-Job HttpListener mocks
# and is flaky in PS 5.1), this drives everything through nmap-import + the
# scan->findings bridge -- no mock listeners -- so it is reliable. It exercises
# the whole new surface against ONE instance with accumulated state and checks
# cross-feature consistency (the report bundle must agree with the dedicated
# endpoints, etc.).
$ErrorActionPreference = "Stop"
$exe = "D:\dev\Nullock\Build\Src\App\Release\NullockApp.exe"

Get-Process NullockApp -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$projDir = Join-Path $env:TEMP "nullock-smoke-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $projDir | Out-Null
$proxyPort = Get-Random -Minimum 20000 -Maximum 45000
$ctlPort   = Get-Random -Minimum 20000 -Maximum 45000
$nl = Start-Process -FilePath $exe `
    -ArgumentList "--headless","--proxy-port=$proxyPort","--control-port=$ctlPort","--project=$projDir","--no-update-check" `
    -PassThru -WindowStyle Hidden
$base = "http://127.0.0.1:$ctlPort"
$hdr  = @{ "Origin"="http://127.0.0.1:$ctlPort"; "X-Nullock-UI"="1" }
$ready = $false
for ($i=0; $i -lt 40; $i++) { try { Invoke-RestMethod -Uri "$base/api/snapshot" -Headers $hdr -TimeoutSec 3 | Out-Null; $ready=$true; break } catch { Start-Sleep -Milliseconds 500 } }
if (-not $ready) { throw "control server never came up on $ctlPort" }

$pass = 0; $fail = 0
function Check($name, $cond) {
    if ($cond) { Write-Host "  PASS $name" -ForegroundColor Green; $script:pass++ }
    else       { Write-Host "  FAIL $name" -ForegroundColor Red;   $script:fail++ }
}
function J($obj) { ($obj | ConvertTo-Json -Depth 8) }
function GetJ($p) { (Invoke-WebRequest -UseBasicParsing -Uri "$base$p" -Headers $hdr -TimeoutSec 15).Content | ConvertFrom-Json }
function PostJ($p, $body) { (Invoke-WebRequest -UseBasicParsing -Uri "$base$p" -Method POST -Headers $hdr -Body $body -ContentType "application/json" -TimeoutSec 20).Content | ConvertFrom-Json }
function RawPost($p) { (Invoke-WebRequest -UseBasicParsing -Uri "$base$p" -Method POST -Headers $hdr -TimeoutSec 20) }
function Decode($r) { if ($r.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($r.Content) } else { $r.Content } }

try {
    Write-Host "=== Nullock integration smoke ===" -ForegroundColor Cyan

    # 1) Seed a realistic multi-host scan: DB + cleartext+CVE + RDP + web.
    $xml = @'
<?xml version="1.0"?>
<nmaprun>
  <host><address addr="10.10.0.10" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port>
    <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" banner="220 (vsFTPd 2.3.4)"/></port>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
  </ports></host>
  <host><address addr="10.10.0.20" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="3389"><state state="open"/><service name="ms-wbt-server"/></port>
  </ports></host>
</nmaprun>
'@
    $imp = PostJ "/api/portscan/import-nmap" $xml
    Check "import-nmap (4 ports, 2 hosts)" ($imp.imported -eq 4)

    # 2) CVE feed overlay -- add an Apache CVE, then it must surface on a banner.
    $ov = PostJ "/api/cve/sync" (J @{ entries = @(@{ product="apache"; cveId="CVE-9999-0001"; cvss=9.1; minVer="2.0.0"; maxVer="3.0.0"; summary="smoke overlay"; fix="x" }) })
    Check "cvefeed sync synced 1" ($ov.synced -eq 1)

    # 3) Bridge scan -> findings.
    $sf = PostJ "/api/portscan/to-findings" '{}'
    Check "scan-findings emitted network findings" ($sf.emitted -ge 4)

    # 4) Inventory: 2 hosts, risk-sorted (10.10.0.10 has the critical CVE).
    $inv = GetJ "/api/inventory"
    Check "inventory: 2 hosts" ($inv.hostCount -eq 2)
    Check "inventory: top host is 10.10.0.10 (highest risk)" (@($inv.hosts)[0].host -eq "10.10.0.10")

    # 5) Posture grade.
    $pos = GetJ "/api/posture"
    Check "posture grade present (A-F)" ($pos.grade -match '^[ABCDF]$')

    # 6) Compliance / OWASP coverage.
    $cmp = GetJ "/api/compliance"
    Check "compliance: 10 OWASP categories, some hit" ((@($cmp.owaspTop10).Count -eq 10) -and ($cmp.owaspCategoriesHit -ge 1))

    # 7) Baseline: save then diff -> nothing changed.
    $bs = RawPost "/api/baseline/save"; $bsj = (Decode $bs) | ConvertFrom-Json
    Check "baseline saved" ($bsj.ok -eq $true -and $bsj.saved -ge 4)
    $bd = GetJ "/api/baseline/diff"
    Check "baseline diff: 0 new / 0 fixed right after save" ($bd.newCount -eq 0 -and $bd.fixedCount -eq 0)

    # 8) JSON master report -- consistent with dedicated endpoints.
    $rj = GetJ "/api/report/json"
    Check "report/json bundle ok" ($rj.ok -eq $true)
    Check "bundle.posture == /api/posture" ($rj.posture.grade -eq $pos.grade -and $rj.posture.score -eq $pos.score)
    Check "bundle.inventory == /api/inventory" ($rj.inventory.hostCount -eq $inv.hostCount)
    Check "bundle.coverage == /api/compliance" ($rj.coverage.owaspCategoriesHit -eq $cmp.owaspCategoriesHit)
    Check "bundle.findings count == findingsTotal" (@($rj.findings).Count -eq $rj.findingsTotal)

    # 9) HTML report -- has the grade badge matching posture.
    $html = Decode (RawPost "/api/report/html")
    Check "HTML report grade badge matches posture" ($html -match ('<span class="g">' + $pos.grade + '</span>'))

    # 10) SBOM export -- CycloneDX with the overlay CVE we synced.
    $sbomR = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/export/sbom" -Headers $hdr -TimeoutSec 15
    $sbom = (Decode $sbomR) | ConvertFrom-Json
    Check "SBOM is CycloneDX 1.5" ($sbom.bomFormat -eq "CycloneDX" -and $sbom.specVersion -eq "1.5")

    # 11) SARIF export still valid.
    $sarifR = Invoke-WebRequest -UseBasicParsing -Uri "$base/api/export/sarif" -Headers $hdr -TimeoutSec 15
    $sarif = (Decode $sarifR) | ConvertFrom-Json
    Check "SARIF v2.1.0 export" ($sarif.version -eq "2.1.0")

    # 12) ScopeGuard still enforced (out-of-scope active probe refused).
    Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$base/api/scope/out/add" -Headers $hdr -Body (J @{glob="10.10.0.10"}) -ContentType "application/json" -TimeoutSec 10 | Out-Null
    Start-Sleep -Milliseconds 300
    $blk = PostJ "/api/pipeline/run" (J @{host="10.10.0.10"})
    Check "ScopeGuard refuses out-of-scope pipeline" ($blk.scopeBlocked -eq $true)

    Write-Host ""
    Write-Host "RESULT pass=$pass fail=$fail" -ForegroundColor Cyan
    if ($fail -gt 0) { exit 1 }
}
finally {
    if ($nl) { Stop-Process -Id $nl.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $projDir -ErrorAction SilentlyContinue
}
