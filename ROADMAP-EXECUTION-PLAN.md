# Nullock roadmap execution plan — drive to exceed Burp on every item

> Authorized 2026-08-02: plan the whole climb, execute in autonomous WAVES across as many sessions as it takes. Each wave: pick the next unclosed batch from PARITY-BACKLOG.md / UI-NAVIGABILITY.md, close with REAL verified code, commit incrementally, flip the matching docs/roadmap/parity.json item + regenerate (parity_report.py --check must stay green), never fake a completion, record honest partials. Verification gates by kind: frontend = bundled @babel/standalone 7.29.0 transform + a functional test of the touched logic; backend = Release build + `ctest --test-dir Build -C Release` + `bash scripts/probe_smoke.sh`; site = whole-site link-check (0 broken) + drift --check. Commit as Bikebrainz, push origin Nullock, verify HEAD==origin.

## Wave 0 — register accuracy (no code): 27 already-present items misclassified as gaps
Verify each against live source, then flip absent/partial/stub -> present/exceeds. Cheap, honesty-improving.
#4,#6,#52,#53,#54,#55,#60,#62,#64,#81,#82,#85,#101,#130,#161,#202,#204,#210,#217,#218,#219,#254,#261,#265,#274,#324,#325

## Wave 1 — surface the biggest hidden features (highest user-visible value)
The 97 orphaned endpoints in UI-NAVIGABILITY.md. Start with: an INSPECTOR tab (/api/inspect + inspector_logic, complete backend, no tab); a unified SCAN LAUNCHER exposing the active-test arsenal (audit/assess/gate + the ~26 per-vuln tests); a REPORTING menu (report/build|html|json); CONTENT-DISCOVERY UI (content/discover, crawler, robots). Each: add tab/menu/button -> invoke endpoint -> render result; transform+functional verify; flip parity.

## Wave 2 — frontend closeable (UI wiring of working backends): 76 items
Batch by tab. Transform+functional verified. Most are hidden-feature surfacing.
#0,#1,#2,#3,#5,#7,#8,#9,#10,#11,#14,#15,#20,#23,#48,#51,#61,#63,#66,#67,#69,#70,#71,#74,#75,#76,#77,#99,#102,#131,#145,#206,#209,#211,#223,#224,#229,#241,#247,#267,#268,#269,#270,#277,#280,#296,#298,#302,#306,#313,#315,#323,#326,#327,#332,#341,#342,#347,#348,#351,#352,#353,#354,#358,#359,#362,#368,#370,#371,#376,#387,#392,#396,#398,#400,#401

## Wave 3 — backend-small closeable: 117 items
Group by subsystem (repeater/sequencer/proxy/intruder/extender) into single build+gauntlet cycles. Add a _logic/control_logic lock where the change guards a fail-silent path.
#12,#13,#16,#19,#21,#28,#29,#31,#32,#33,#34,#35,#36,#37,#39,#40,#41,#42,#44,#45,#47,#59,#78,#79,#83,#86,#87,#88,#91,#93,#98,#122,#123,#125,#127,#128,#133,#135,#144,#146,#148,#149,#150,#152,#153,#154,#156,#158,#162,#163,#165,#176,#178,#179,#180,#181,#183,#185,#186,#188,#194,#195,#196,#203,#208,#216,#222,#225,#230,#234,#235,#238,#239,#245,#248,#249,#252,#253,#257,#258,#259,#264,#271,#273,#279,#281,#283,#284,#286,#289,#292,#293,#294,#299,#300,#304,#305,#307,#308,#316,#317,#320,#333,#337,#343,#345,#350,#355,#356,#357,#366,#385,#393,#399,#402,#403,#405

## Wave 4 — Labs as TryHackMe/HackTheBox scenarios (task #122)
Objective/brief + progressive hints + submit-flag/success-check + difficulty/category + walkthrough tying each step to its Nullock probe; per-lab end-to-end exploit test; tracks/XP gamification; wire into docs/labs + in-app.

## Wave 5+ — the large `absent` builds (one substantial feature per wave, fully verified)
From PARITY-BACKLOG.md, ranked by impact: match-and-replace rule engine, WebSockets history tab, HTTP/2 frame log, SOCKS proxy chaining, intercept response-hold, per-host cert generation UI, sequencer manual-load + full FIPS suite, headless-browser DAST (#12), native CLI+Docker+exit codes (#8). Each gets its own wave: design -> build -> gauntlet -> commit -> roadmap.

## Loop contract
Re-entrant: on each wake, `git fetch origin Nullock`; if a wave is mid-flight continue it, else start the next; always leave the tree clean and HEAD==origin; append a one-line progress note here per wave completed.
- Wave 1 (2026-08-02, 86f094c): INSPECTOR tab added, surfacing /api/inspect. Closed #327 request-attributes, #330 cookies, #332 JWT-decode -> present.

- Wave 1 (2026-08-02, 3db8c7f): PROBE tab added (fingerprint / header-audit / waf-detect / secret-scan on-demand per-URL). Surfaces 4 orphaned endpoints (also flow to Issues); underlying passive capabilities were already present so no parity delta. Orphaned endpoints: 97 -> 92.

- Wave 1 (2026-08-02, 3f89564): TESTS tab added — unified launcher for all 26 active /api/<type>/test checks. Orphaned endpoints: 92 -> 66.

- Wave 1 (2026-08-08, c81109e/3607a42): DISCOVER tab added — content/directory discovery (soft-404 calibrated), robots.txt + sitemap recon, crawler start/stop. Closed #368, #401 -> present. Orphaned endpoints re-audited and corrected: 66 -> 63 (previous 66 baseline undercounted by 1 -- `/api/cache/poison` was never actually closed by TESTS, it has a distinct shape outside the uniform `/<type>/test` contract; UI-NAVIGABILITY.md rewritten in full to match live ui-v2 grep, not just this wave's delta).

- Wave 1 (2026-08-08, 557e5f8): REPORTING tab added — Markdown/HTML report download (POST->blob), JSON posture summary, OpenAPI export/import, CycloneDX SBOM download, workspace push/pull. Closed "Reporting: HTML issue report" (partial->present) and "Reporting: reachable from the UI" (stub->present). Orphaned endpoints: 63 -> 55.

- Wave 2 (2026-08-08, 1074f35): Comparer rebuilt — real item list (paste/load-file/remove/clear, lifted into the app reducer), "Send to Comparer" from Proxy history (request/response) and Repeater (request/response panes), the backend's merged diff split into two scroll-synced side-by-side panels, and a Text/Hex result toggle. Also Ctrl+Space to send in Repeater. Closed #351, #352, #353, #354 (absent -> present). No backend change, no new orphaned-endpoint delta (reused existing /api/compare).
