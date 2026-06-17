#include "waf_detect.hpp"
#include "networking.hpp"

#include <QSet>

namespace Nullock::Core::WafDetect {

namespace {

// One signature. Either a header match (headerName set; valueNeedle "" => the
// header's mere presence is the signal, else its value must contain valueNeedle)
// OR a cookie match (headerName "" + cookieNeedle => some Set-Cookie value
// contains cookieNeedle). All matching is case-insensitive. Several rows may
// share a name (e.g. Cloudflare via cf-ray OR Server) -- results dedup by name.
struct Sig {
    const char *name;
    const char *kind;
    const char *headerName;
    const char *valueNeedle;
    const char *cookieNeedle;
};

const QList<Sig> &sigs() {
    static const QList<Sig> t = {
        { "Cloudflare",         "cdn",   "cf-ray", "", "" },
        { "Cloudflare",         "cdn",   "server", "cloudflare", "" },
        { "Cloudflare",         "cdn",   "", "", "__cf_bm" },
        { "Akamai",             "cdn",   "server", "AkamaiGHost", "" },
        { "Akamai",             "cdn",   "x-akamai-transformed", "", "" },
        { "Akamai",             "cdn",   "", "", "ak_bmsc" },
        { "AWS CloudFront",     "cdn",   "x-amz-cf-id", "", "" },
        { "AWS CloudFront",     "cdn",   "server", "CloudFront", "" },
        { "AWS WAF",            "waf",   "", "", "aws-waf-token" },
        { "AWS WAF",            "waf",   "x-amzn-waf-action", "", "" },
        { "Imperva Incapsula",  "waf",   "x-iinfo", "", "" },
        { "Imperva Incapsula",  "waf",   "x-cdn", "Incapsula", "" },
        { "Imperva Incapsula",  "waf",   "", "", "visid_incap" },
        { "Imperva Incapsula",  "waf",   "", "", "incap_ses" },
        { "Sucuri CloudProxy",  "waf",   "x-sucuri-id", "", "" },
        { "Sucuri CloudProxy",  "waf",   "server", "Sucuri", "" },
        { "F5 BIG-IP",          "lb",    "", "", "BIGipServer" },
        { "Citrix NetScaler",   "lb",    "via", "NS-CACHE", "" },
        { "Citrix NetScaler",   "lb",    "", "", "citrix_ns_id" },
        { "Citrix NetScaler",   "lb",    "", "", "NSC_" },
        { "Fastly",             "cdn",   "x-fastly-request-id", "", "" },
        { "Varnish",            "cache", "x-varnish", "", "" },
        { "Barracuda",          "waf",   "", "", "barra_counter_session" },
        { "Azure Front Door",   "cdn",   "x-azure-ref", "", "" },
        { "Microsoft Edge/CDN", "cdn",   "x-msedge-ref", "", "" },
        { "Google Frontend",    "cdn",   "server", "Google Frontend", "" },
        { "DDoS-Guard",         "waf",   "server", "ddos-guard", "" },
        { "StackPath",          "cdn",   "x-hw", "", "" },
        { "ModSecurity",        "waf",   "server", "mod_security", "" },
        // --- extended coverage (vendor-unique header/cookie sigs) ---
        { "FortiWeb",           "waf",   "", "", "FORTIWAFSID" },
        { "Reblaze",            "waf",   "", "", "rbzid" },
        { "PerimeterX / HUMAN", "waf",   "", "", "_pxhd" },
        { "DataDome",           "waf",   "", "", "datadome" },
        { "Yundun",             "waf",   "", "", "yd_cookie" },
        { "Qrator",             "waf",   "server", "QRATOR", "" },
        { "Cloudbric",          "waf",   "server", "Cloudbric", "" },
        { "Netlify",            "cdn",   "x-nf-request-id", "", "" },
        { "Vercel",             "cdn",   "x-vercel-id", "", "" },
        { "Section.io",         "cdn",   "section-io-id", "", "" },
        { "KeyCDN",             "cdn",   "server", "keycdn-engine", "" },
        { "BunnyCDN",           "cdn",   "server", "BunnyCDN", "" },
        { "Edgecast",           "cdn",   "server", "ECAcc", "" },
        { "CacheFly",           "cdn",   "server", "CacheFly", "" },
    };
    return t;
}

QByteArray buildGet(const Request &req) {
    // Self-protect the request line + Host against CR/LF regardless of caller
    // (the endpoint already FullyEncodes the path, but the helper shouldn't rely
    // on that).
    QString path = req.basePath.isEmpty() ? QStringLiteral("/") : req.basePath;
    path.remove('\r'); path.remove('\n');
    QString host = req.host;
    host.remove('\r'); host.remove('\n');
    QByteArray out = "GET " + path.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/waf-detect\r\n";
    out += "Accept: */*\r\nAccept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace

QList<Detection> detectFromHeaders(const QList<QPair<QString, QString>> &headers) {
    auto headerVal = [&](const QString &name) -> QString {
        QStringList vals;
        for (const auto &h : headers)
            if (h.first.compare(name, Qt::CaseInsensitive) == 0) vals << h.second;
        return vals.join("; ");
    };
    auto headerPresent = [&](const QString &name) -> bool {
        for (const auto &h : headers)
            if (h.first.compare(name, Qt::CaseInsensitive) == 0) return true;
        return false;
    };
    // Match cookie NAMES only (substring before the first '='), not the whole
    // Set-Cookie line -- so a needle like "NSC_" can't false-match a cookie
    // *value* or attribute.
    QStringList cookieNames;
    for (const auto &h : headers)
        if (h.first.compare(QLatin1String("set-cookie"), Qt::CaseInsensitive) == 0) {
            const QString name = h.second.section('=', 0, 0).trimmed();
            if (!name.isEmpty()) cookieNames << name;
        }

    QList<Detection> out;
    QSet<QString> seen;
    // Rows are ordered strongest-evidence-first per product; the seen-check
    // dedups by product name and keeps that first (strongest) match's evidence.
    for (const Sig &s : sigs()) {
        if (seen.contains(QString::fromLatin1(s.name))) continue;  // already detected this product
        bool matched = false;
        QString evidence;
        if (s.headerName && *s.headerName) {
            const QString hn = QString::fromLatin1(s.headerName);
            if (s.valueNeedle && *s.valueNeedle) {
                const QString needle = QString::fromLatin1(s.valueNeedle);
                const QString v = headerVal(hn);
                if (v.contains(needle, Qt::CaseInsensitive)) {
                    matched = true;
                    evidence = hn + ": " + v.left(80);
                }
            } else if (headerPresent(hn)) {
                matched = true;
                evidence = "header " + hn;
            }
        } else if (s.cookieNeedle && *s.cookieNeedle) {
            const QString needle = QString::fromLatin1(s.cookieNeedle);
            for (const QString &cn : cookieNames) {
                if (cn.contains(needle, Qt::CaseInsensitive)) {
                    matched = true;
                    evidence = "cookie " + cn.left(40);
                    break;
                }
            }
        }
        if (matched) {
            seen.insert(QString::fromLatin1(s.name));
            out.append({ QString::fromLatin1(s.name), QString::fromLatin1(s.kind), evidence });
        }
    }
    return out;
}

Result detect(const Request &req) {
    Result result;
    result.host = req.host;
    if (req.host.isEmpty()) { result.error = "host required"; return result; }
    HttpClient client;
    const auto r = client.send(req.host, static_cast<quint16>(req.port), req.tls, buildGet(req));
    if (!r.ok) { result.error = r.errorMessage; return result; }
    result.status = r.parsed.statusCode;
    result.detections = detectFromHeaders(r.parsed.headers);
    return result;
}

} // namespace Nullock::Core::WafDetect
