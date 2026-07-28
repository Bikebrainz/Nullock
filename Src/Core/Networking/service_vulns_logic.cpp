// Pure service-version CVE matching, split out of service_vulns.cpp so a unit
// test can link it against Qt6::Core alone -- grabBanner()/scan() and their
// QTcpSocket (Qt Network) stay in service_vulns.cpp. Mirrors the established
// sibling pattern. Everything here is I/O-free: the curated CVE table, the
// version parser/comparator, the banner parser, the version matcher, and the
// thread-safe runtime overlay.

#include "service_vulns.hpp"

#include <QMutex>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>

namespace Nullock::Core::ServiceVulns {

namespace {

// A version-pinned service CVE. `minVer`/`maxVer` bound the affected range
// (min inclusive, max EXCLUSIVE); `exact` means the version must equal minVer.
// Versions are compared component-wise; an OpenSSH "9.3p1" parses as 9.3.1.
struct ServiceCve {
    const char *product;
    const char *cveId;
    double      cvss;
    const char *cvssVector;
    const char *minVer;     // "" = no lower bound
    const char *maxVer;     // "" = no upper bound (exclusive)
    bool        exact;
    const char *affected;
    const char *summary;
    const char *fix;
    const char *reference;
};

const QList<ServiceCve> &table() {
    static const QList<ServiceCve> t = {
        { "vsftpd", "CVE-2011-2523", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "2.3.4", "", true, "2.3.4",
          "vsftpd 2.3.4 ships a backdoor: a ':)' in the username opens a root shell on 6200.",
          "upgrade to a clean 3.x build", "https://nvd.nist.gov/vuln/detail/CVE-2011-2523" },
        { "openssh", "CVE-2024-6387", 8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "8.5", "9.8", false, "8.5p1 - 9.7p1",
          "regreSSHion: signal-handler race in sshd allows unauthenticated RCE as root (glibc Linux).",
          "9.8p1", "https://nvd.nist.gov/vuln/detail/CVE-2024-6387" },
        { "openssh", "CVE-2018-15473", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
          "", "7.7", false, "< 7.7",
          "Username enumeration via differing auth responses for valid vs invalid users.",
          "7.7", "https://nvd.nist.gov/vuln/detail/CVE-2018-15473" },
        // Affected range [1.3.5, 1.3.5a): only the 1.3.5 release is vulnerable;
        // the fix is the lettered build 1.3.5a, which sorts ABOVE 1.3.5 in the
        // version model so it (and 1.3.5b/c...) is correctly excluded.
        { "proftpd", "CVE-2015-3306", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "1.3.5", "1.3.5a", false, "1.3.5 (mod_copy)",
          "mod_copy SITE CPFR/CPTO lets an unauthenticated attacker copy files -> RCE.",
          "1.3.5a", "https://nvd.nist.gov/vuln/detail/CVE-2015-3306" },
        { "exim", "CVE-2019-10149", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "4.87", "4.92", false, "4.87 - 4.91",
          "Improper validation of the recipient address allows remote command execution as root.",
          "4.92", "https://nvd.nist.gov/vuln/detail/CVE-2019-10149" },
        { "apache", "CVE-2021-41773", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "2.4.49", "2.4.50", true, "2.4.49",
          "Path traversal + RCE via %2e encoding when mod_cgi is enabled and Require all denied missing.",
          "2.4.51", "https://nvd.nist.gov/vuln/detail/CVE-2021-41773" },
        { "apache", "CVE-2021-42013", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "2.4.50", "2.4.51", true, "2.4.50",
          "Incomplete fix for CVE-2021-41773; double-encoded path traversal -> RCE.",
          "2.4.51", "https://nvd.nist.gov/vuln/detail/CVE-2021-42013" },
        { "nginx", "CVE-2021-23017", 7.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L",
          "0.6.18", "1.21.0", false, "0.6.18 - 1.20.x (resolver)",
          "Off-by-one in the DNS resolver can corrupt memory; RCE-class when resolver is configured.",
          "1.21.0", "https://nvd.nist.gov/vuln/detail/CVE-2021-23017" },
        { "iis", "CVE-2017-7269", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "6.0", "6.1", true, "6.0 (WebDAV)",
          "Buffer overflow in the WebDAV ScStoragePathFromUrl handler -> unauthenticated RCE.",
          "no vendor fix (EOL); disable WebDAV", "https://nvd.nist.gov/vuln/detail/CVE-2017-7269" },
        { "samba", "CVE-2017-7494", 9.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
          "3.5.0", "4.6.4", false, "3.5.0 - 4.6.3 (SambaCry)",
          "A writable share + this version lets a client load and run a shared library as root.",
          "4.6.4", "https://nvd.nist.gov/vuln/detail/CVE-2017-7494" },
        { "openssh", "CVE-2023-38408", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "5.5", "9.3.2", false, "5.5 - 9.3p1 (ssh-agent PKCS#11)",
          "Remote code execution in ssh-agent's PKCS#11 provider loading; exploitable when an agent is forwarded to an attacker-controlled host.",
          "9.3p2", "https://nvd.nist.gov/vuln/detail/CVE-2023-38408" },
        { "apache", "CVE-2023-25690", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "2.4.0", "2.4.56", false, "2.4.0 - 2.4.55 (mod_proxy)",
          "HTTP request smuggling via mod_proxy with certain RewriteRule/ProxyPassMatch patterns (config-dependent).",
          "2.4.56", "https://nvd.nist.gov/vuln/detail/CVE-2023-25690" },
        { "apache", "CVE-2021-44790", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "2.4.0", "2.4.52", false, "2.4.0 - 2.4.51 (mod_lua)",
          "Buffer overflow in mod_lua multipart parsing -> possible RCE (requires a mod_lua script calling r:parsebody).",
          "2.4.52", "https://nvd.nist.gov/vuln/detail/CVE-2021-44790" },
    };
    return t;
}

// ---- Version model ---------------------------------------------------------
// A service version compares as: numeric RELEASE components first, then a
// release-STAGE tiebreaker. The stage distinguishes three suffix shapes the old
// "replace every letter run with a dot" parser silently conflated:
//
//   * openssh 'p<N>' portable patch ("9.3p1"): 'p' is a soft separator, so the
//     number folds in as an ordinary numeric component -- 9.3p1 == 9.3.1. This
//     is what the curated ssh ranges rely on (e.g. the 9.3p2 fix == 9.3.2).
//   * a trailing maintenance LETTER ("1.3.5a", openssl "1.0.2k"): a PATCH build
//     that sorts ABOVE the bare release -- 1.3.5 < 1.3.5a. (Old parser dropped
//     the 'a' so the proftpd FIX 1.3.5a matched a 1.3.5-only CVE.)
//   * a pre-release WORD ("1.2.3rc1", "...beta2"): sorts BELOW the release --
//     1.2.3rc1 < 1.2.3. (Old parser turned "rc1" into a ".1", sorting the
//     pre-release ABOVE its own final release.)
enum Stage { StagePre = -1, StageRelease = 0, StagePatch = 1 };

struct Ver {
    QList<int> nums;
    int        stage    = StageRelease;
    int        stageKey = 0;   // ordering WITHIN a non-release stage
};

// alpha < beta < rc, with the looser snapshot/dev tags below alpha. Only the
// relative order matters (a pre-release always sorts below its release anyway).
int preRank(const QString &w) {
    if (w == "dev" || w == "snapshot") return 0;
    if (w == "alpha")                  return 1;
    if (w == "milestone")              return 2;
    if (w == "beta")                   return 3;
    if (w == "pre" || w == "preview")  return 4;
    if (w == "rc")                     return 5;
    return 0;
}

Ver parseVer(const QString &in) {
    Ver out;
    // Tokenize into maximal digit / letter runs; any other char is a separator.
    QStringList toks;
    QString cur; bool curDigit = false;
    auto flush = [&]() { if (!cur.isEmpty()) { toks << cur; cur.clear(); } };
    for (const QChar &c : in.toLower()) {
        if (c.isDigit()) {
            if (!cur.isEmpty() && !curDigit) flush();
            curDigit = true; cur += c;
        } else if (c.isLetter()) {
            if (!cur.isEmpty() && curDigit) flush();
            curDigit = false; cur += c;
        } else { flush(); }
    }
    flush();

    static const QSet<QString> preWords = {
        "rc", "alpha", "beta", "pre", "preview", "dev", "snapshot", "milestone" };

    for (int i = 0; i < toks.size(); ++i) {
        const QString &t = toks[i];
        // A DIGIT-run token that QString::toInt() can't represent must never fall
        // through to the maintenance-letter branch below: that left `nums` EMPTY, so
        // the release parsed as 0.0.0 and matched every "< maxVer" CVE -- PHANTOM
        // leads on a host far newer than any fix. Two ways in: a component over
        // INT_MAX ("99999999999"), and non-ASCII digits (QChar::isDigit() accepts
        // fullwidth, toInt() does not). Clamp the former; the latter is rejected at
        // the matchVersion entry as an unparseable version.
        bool allAsciiDigits = !t.isEmpty();
        for (const QChar &c : t)
            if (c < QLatin1Char('0') || c > QLatin1Char('9')) { allAsciiDigits = false; break; }
        if (allAsciiDigits) {
            bool okLong = false;
            const qlonglong big = t.toLongLong(&okLong);
            const int n = (!okLong || big > qlonglong(INT_MAX)) ? INT_MAX : int(big);
            if (out.stage == StageRelease) out.nums << n;   // release core
            continue;                                       // post-stage digits handled below
        }
        // 'p' immediately followed by digits is openssh's portable patch -- a
        // soft separator, NOT a stage; the following number folds into nums.
        if (t == QLatin1String("p") && i + 1 < toks.size()) {
            bool nx = false; toks[i + 1].toInt(&nx);
            if (nx) continue;
        }
        if (preWords.contains(t)) {
            out.stage = StagePre;
            int num = 0;
            if (i + 1 < toks.size()) { bool nx = false; const int x = toks[i + 1].toInt(&nx); if (nx) num = x; }
            out.stageKey = preRank(t) * 100000 + num;       // word rank, then its number
            break;
        }
        // a maintenance letter run (e.g. "a", "k") -> patch build above release.
        // Accumulate in 64-bit and clamp: base-26 over 7+ letters overflows a signed
        // int and INVERTS patch-build ordering.
        qlonglong key = 0;
        for (const QChar &c : t) {
            key = key * 26 + (c.toLatin1() - 'a' + 1);
            if (key > qlonglong(INT_MAX)) { key = INT_MAX; break; }
        }
        out.stage = StagePatch; out.stageKey = int(key);
        break;
    }
    return out;
}

// Numeric release components only (no stage) -- the truncation/precision checks
// reason about how many dotted numbers the scanned version actually disclosed.
QList<int> verNums(const QString &v) { return parseVer(v).nums; }

int verCmp(const QString &a, const QString &b) {
    const Ver va = parseVer(a), vb = parseVer(b);
    for (int i = 0; i < qMax(va.nums.size(), vb.nums.size()); ++i) {
        const int x = i < va.nums.size() ? va.nums[i] : 0;
        const int y = i < vb.nums.size() ? vb.nums[i] : 0;
        if (x != y) return x < y ? -1 : 1;
    }
    if (va.stage != vb.stage)       return va.stage < vb.stage ? -1 : 1;
    if (va.stageKey != vb.stageKey) return va.stageKey < vb.stageKey ? -1 : 1;
    return 0;
}

// Is `version` too imprecise to decide a range BOUNDARY? verCmp pads missing
// components with 0, so a less-precise version ("2.4") compares EQUAL on the
// shared prefix of a boundary ("2.4.56") and is judged below it -- even though
// the real (hidden) patch level could land on the other side. The match is then
// a LEAD, not a confirmation. Uncertain ONLY when: fewer components than the
// boundary, the shared prefix matches, AND at least one of the boundary's
// missing trailing components is non-zero (so the hidden component actually
// DECIDES). If the prefix differs ("2.3" vs "2.4.56") or the boundary's tail is
// all-zero ("2.4" vs "2.4.0", where every 2.4.x >= 2.4.0) the comparison is
// certain and this returns false.
bool truncatedAgainst(const QString &version, const QString &boundary) {
    if (boundary.isEmpty()) return false;
    const QList<int> pv = verNums(version), pb = verNums(boundary);
    if (pv.size() >= pb.size()) return false;
    for (int i = 0; i < pv.size(); ++i)
        if (pv[i] != pb[i]) return false;       // prefix differs -> certain
    for (int i = pv.size(); i < pb.size(); ++i)
        if (pb[i] != 0) return true;            // a non-zero hidden component decides
    return false;                               // boundary tail all-zero -> certain
}

// Truncation test for an EXACT-version CVE. The range rule above treats an
// all-zero boundary tail as certain -- correct for a "< maxVer" bound, but WRONG
// for equality: a banner that disclosed only "6" (Microsoft-IIS/6) could really be
// 6.0.1, which is NOT the exact 6.0.0, so confirming it is a false CONFIRM on a
// truncated scan. For equality, ANY hidden component makes it a lead.
bool truncatedForExact(const QString &version, const QString &boundary) {
    if (boundary.isEmpty()) return false;
    const QList<int> pv = verNums(version), pb = verNums(boundary);
    if (pv.size() >= pb.size()) return false;
    for (int i = 0; i < pv.size(); ++i)
        if (pv[i] != pb[i]) return false;       // prefix differs -> certainly not equal
    return true;                                // any hidden component -> lead
}

// Decide affected + precision for one CVE (exact, or a [minVer, maxVer) range
// with min inclusive / max exclusive) against a scanned version. Truncation at
// EITHER boundary that leaves the missing component(s) deciding yields an
// affected LEAD (affected=true, precise=false) -- never a silent drop on the
// min side, never a false confirm on the max side.
struct Verdict { bool affected; bool precise; };
Verdict evalCve(const QString &version, const QString &minVer, const QString &maxVer, bool exact) {
    if (exact) {
        // A scanned version LESS precise than the exact CVE version (e.g. "2.4"
        // vs "2.4.49") can't be confirmed equal, but the hidden patch level could
        // BE the vulnerable one -- report an affected LEAD (imprecise), never a
        // silent drop that also lies about precision.
        if (truncatedForExact(version, minVer))
            return { true, false };
        return { verCmp(version, minVer) == 0, true };
    }
    const bool hasMin = !minVer.isEmpty();
    const bool hasMax = !maxVer.isEmpty();
    const bool minTrunc = hasMin && truncatedAgainst(version, minVer);
    const bool maxTrunc = hasMax && truncatedAgainst(version, maxVer);
    const bool aboveMin = !hasMin || verCmp(version, minVer) >= 0 || minTrunc;
    const bool belowMax = !hasMax || verCmp(version, maxVer) <  0 || maxTrunc;
    return { aboveMin && belowMax, !(minTrunc || maxTrunc) };
}

// Runtime overlay store (cve_feed_sync). Guarded by a mutex because
// matchVersion runs on scan worker threads.
QMutex            g_overlayMutex;
QList<OverlayCve> g_overlay;

} // namespace

QList<int> serviceProbePorts() {
    // NOTE: SMB/445 is deliberately NOT probed here. A raw TCP banner grab on
    // 445 returns nothing (SMB requires a Negotiate Protocol exchange), so the
    // empty result is indistinguishable from "service identified & patched" --
    // a silent false-negative that would hide the curated Samba SambaCry CVE.
    // Until a minimal SMB negotiate is implemented, 445 stays out of the default
    // set so an empty scan is never misread as safe. Port-level SMB exposure is
    // still surfaced by the port scanner (scan_bridge classify -> file-share),
    // and the Samba CVE remains reachable via matchVersion / the overlay.
    return { 21, 22, 25, 80, 110, 143, 443, 587, 3306, 5432, 8080 };
}

namespace {

// Product + version-capture regex. A digit after the delimiter is required, so
// these only fire when the banner actually discloses a version. Order matters:
// MariaDB's "-MariaDB"-anchored pattern precedes anything that could shadow it.
struct VerPat { const char *product; QRegularExpression re; };
const QList<VerPat> &verPats() {
    static const QList<VerPat> p = {
        // "OpenSSH_for_Windows_8.1" DOES disclose its version, but requiring a digit
        // straight after the separator missed it -- the banner fell back to the
        // name-only path and a CVSS 9.8 CVE was downgraded to an INFO finding.
        { "openssh",  QRegularExpression("OpenSSH[_/](?:for_Windows_)?([0-9][0-9.p]*)",
                                         QRegularExpression::CaseInsensitiveOption) },
        { "vsftpd",   QRegularExpression("vsftpd\\s+([0-9][0-9.]*)",     QRegularExpression::CaseInsensitiveOption) },
        { "proftpd",  QRegularExpression("ProFTPD\\s+([0-9][0-9.]*)",    QRegularExpression::CaseInsensitiveOption) },
        { "exim",     QRegularExpression("Exim\\s+([0-9][0-9.]*)",       QRegularExpression::CaseInsensitiveOption) },
        { "apache",   QRegularExpression("Apache/([0-9][0-9.]*)",        QRegularExpression::CaseInsensitiveOption) },
        { "nginx",    QRegularExpression("nginx/([0-9][0-9.]*)",         QRegularExpression::CaseInsensitiveOption) },
        { "lighttpd", QRegularExpression("lighttpd/([0-9][0-9.]*)",      QRegularExpression::CaseInsensitiveOption) },
        { "iis",      QRegularExpression("Microsoft-IIS/([0-9][0-9.]*)", QRegularExpression::CaseInsensitiveOption) },
        { "samba",    QRegularExpression("Samba\\s+([0-9][0-9.]*)",      QRegularExpression::CaseInsensitiveOption) },
        // MariaDB greets as "5.5.5-10.x.y-MariaDB-..."; the real version is the
        // X.Y.Z immediately before "-MariaDB" (the 5.5.5 is a compat prefix).
        { "mariadb",  QRegularExpression("([0-9][0-9.]+)-MariaDB",       QRegularExpression::CaseInsensitiveOption) },
        { "postfix",  QRegularExpression("Postfix\\s+([0-9][0-9.]*)",    QRegularExpression::CaseInsensitiveOption) },
        { "dovecot",  QRegularExpression("Dovecot\\s+([0-9][0-9.]*)",    QRegularExpression::CaseInsensitiveOption) },
        { "redis",    QRegularExpression("redis_version:([0-9][0-9.]*)", QRegularExpression::CaseInsensitiveOption) },
    };
    return p;
}

// Product-NAME regexes (version optional). Lets productOnly() recognize a
// service whose banner withheld its version (ServerTokens Prod / server_tokens
// off / a bare "Postfix"/"Dovecot" greeting). Order matters: more specific
// product tokens first (MariaDB before the generic MySQL handshake markers).
struct NamePat { const char *product; QRegularExpression re; };

// Wrap a product-name pattern so it can't match INSIDE a longer alphanumeric run:
// bare "Exim" matched "eximius.example.com" and shadowed the real product (Postfix)
// for the whole banner. Plain \b is wrong here -- '_' is a word char, so \b would
// reject the legitimate "OpenSSH_9.7p1" -- so guard on ALNUM only.
static QRegularExpression nameRe(const char *pat) {
    return QRegularExpression(QStringLiteral("(?<![a-z0-9])(?:%1)(?![a-z0-9])")
                                  .arg(QLatin1String(pat)),
                              QRegularExpression::CaseInsensitiveOption);
}

const QList<NamePat> &namePats() {
    static const QList<NamePat> p = {
        { "openssh",  nameRe("OpenSSH")        },
        { "apache",   nameRe("Apache")         },
        { "nginx",    nameRe("nginx")          },
        { "lighttpd", nameRe("lighttpd")       },
        { "iis",      nameRe("Microsoft-IIS")  },
        { "vsftpd",   nameRe("vsftpd")         },
        { "proftpd",  nameRe("ProFTPD")        },
        { "exim",     nameRe("Exim")           },
        { "postfix",  nameRe("Postfix")        },
        { "dovecot",  nameRe("Dovecot")        },
        { "samba",    nameRe("Samba")          },
        { "mariadb",  nameRe("MariaDB")        },
        { "redis",    nameRe("Redis|redis_version") },
        { "mysql",    nameRe("MySQL|mysql_native_password|caching_sha2_password") },
    };
    return p;
}

} // namespace

void parseBanner(const QString &banner, int port, QString &product, QString &version) {
    product.clear(); version.clear();
    if (banner.isEmpty()) return;
    Q_UNUSED(port);
    for (const VerPat &p : verPats()) {
        const auto m = p.re.match(banner);
        if (m.hasMatch()) { product = p.product; version = m.captured(1); return; }
    }
}

QString productOnly(const QString &banner, int port) {
    if (banner.isEmpty()) return QString();
    // A full product+version parse (if one is available) keeps the canonical
    // product name identical to parseBanner.
    QString p, v; parseBanner(banner, port, p, v);
    if (!p.isEmpty()) return p;
    for (const NamePat &n : namePats())
        if (n.re.match(banner).hasMatch()) return QString::fromLatin1(n.product);
    return QString();
}

QList<CveHit> matchVersion(const QString &product, const QString &version) {
    QList<CveHit> out;
    if (product.isEmpty() || version.isEmpty()) return out;
    // A version with no ASCII digit discloses no release at all. QChar::isDigit() is
    // Unicode-aware while QString::toInt() is not, so a fullwidth "２.４" tokenized as
    // digits but parsed as nothing -- leaving an empty release that compares as 0.0.0
    // and matched every "< maxVer" CVE (phantom leads on an unparseable banner).
    bool hasAsciiDigit = false;
    for (const QChar &c : version)
        if (c >= QLatin1Char('0') && c <= QLatin1Char('9')) { hasAsciiDigit = true; break; }
    if (!hasAsciiDigit) return out;
    for (const ServiceCve &c : table()) {
        if (product.compare(QString::fromUtf8(c.product), Qt::CaseInsensitive) != 0) continue;
        const Verdict vd = evalCve(version, QString::fromUtf8(c.minVer),
                                   QString::fromUtf8(c.maxVer), c.exact);
        if (!vd.affected) continue;
        CveHit h;
        h.product = product; h.version = version;
        h.cveId = c.cveId; h.cvss = c.cvss; h.cvssVector = c.cvssVector;
        h.summary = c.summary; h.affected = c.affected; h.fix = c.fix; h.reference = c.reference;
        h.precise = vd.precise;
        out.append(h);
    }
    // Also consult the runtime overlay (same range semantics, reusing verCmp).
    // Dedup by cveId (static table wins) so a feed re-publishing a curated CVE,
    // or listing one twice, doesn't double-count downstream.
    QSet<QString> seenCve;
    for (const CveHit &h : out) seenCve.insert(h.cveId.toLower());
    {
        QMutexLocker lk(&g_overlayMutex);
        for (const OverlayCve &c : g_overlay) {
            if (product.compare(c.product, Qt::CaseInsensitive) != 0) continue;
            if (seenCve.contains(c.cveId.toLower())) continue;
            const Verdict vd = evalCve(version, c.minVer, c.maxVer, c.exact);
            if (!vd.affected) continue;
            seenCve.insert(c.cveId.toLower());
            CveHit h;
            h.product = product; h.version = version;
            h.cveId = c.cveId; h.cvss = c.cvss; h.cvssVector = c.cvssVector;
            h.summary = c.summary; h.affected = c.affected; h.fix = c.fix; h.reference = c.reference;
            h.precise = vd.precise;
            out.append(h);
        }
    }
    return out;
}

int setOverlay(const QList<OverlayCve> &entries) {
    QMutexLocker lk(&g_overlayMutex);
    g_overlay = entries;
    return g_overlay.size();
}

void clearOverlay() {
    QMutexLocker lk(&g_overlayMutex);
    g_overlay.clear();
}

int overlayCount() {
    QMutexLocker lk(&g_overlayMutex);
    return g_overlay.size();
}

} // namespace Nullock::Core::ServiceVulns
