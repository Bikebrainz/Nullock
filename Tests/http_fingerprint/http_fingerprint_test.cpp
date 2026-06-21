// Regression corpus for the HTTP tech-fingerprint probe's pure logic (no
// network):
//   - detect(): a CVE-bearing version is attached ONLY from a distinctive
//     marker (generator meta / product path / specific header) -- a page that
//     merely mentions a product+version does NOT get a version+cveKind (which
//     would CVE-correlate the scanned site). Joomla + Drupal FP fixes.
//   - Django now requires BOTH csrftoken AND sessionid cookies.
//   - the well-gated positives still fire; buildGet CR/LF guards.
//
// Run via:  ctest -R http_fingerprint -V

#include "http_fingerprint.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::HttpFingerprint;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
const Tech *find(const QList<Tech> &ts, const char *name) {
    for (const auto &t : ts) if (t.name == QString::fromLatin1(name)) return &t;
    return nullptr;
}
Headers H(std::initializer_list<QPair<QString, QString>> l) { return Headers(l); }
QList<Tech> body(const char *b) { return detect({}, QByteArray(b)); }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- Joomla FP fix: prose mention must NOT become a version+CVE -----
    chk("joomla prose 'Joomla! 3.4.5' (no marker) -> NOT detected (no false CVE)",
        find(body("<p>A flaw was found in Joomla! 3.4.5 last week</p>"), "Joomla") == nullptr);
    chk("joomla generator meta -> version + cms-joomla",
        [](){ const Tech *t = find(body("<meta name=\"generator\" content=\"Joomla! 3.9.28\">"), "Joomla");
              return t && t->version == "3.9.28" && t->cveKind == "cms-joomla"; }());
    chk("joomla path marker -> versionless inventory (cveKind set, version empty -> no CVE)",
        [](){ const Tech *t = find(body("<script src=\"/media/jui/js/x.js\"></script>"), "Joomla");
              return t && t->version.isEmpty() && t->cveKind == "cms-joomla"; }());

    // ---- Drupal FP fix: prose version must NOT become a version+CVE -----
    chk("drupal prose 'Drupal 7.58' (no marker) -> NOT detected with version",
        [](){ const Tech *t = find(body("<p>Drupal 7.58 had an SA-CORE advisory</p>"), "Drupal");
              return t == nullptr || t->version.isEmpty(); }());
    chk("drupal generator meta -> version + cms-drupal",
        [](){ const Tech *t = find(body("<meta name=\"generator\" content=\"Drupal 9.4 (https://www.drupal.org)\">"), "Drupal");
              return t && t->version == "9.4" && t->cveKind == "cms-drupal"; }());
    chk("drupal /sites/ path -> versionless inventory",
        [](){ const Tech *t = find(body("<link href=\"/sites/all/themes/x.css\">"), "Drupal");
              return t && t->version.isEmpty(); }());

    // ---- Django: require BOTH cookies (was bare sessionid) --------------
    chk("django bare sessionid cookie -> NOT Django (FP fix)",
        find(detect(H({{"Set-Cookie", "sessionid=abc; Path=/"}}), ""), "Django") == nullptr);
    chk("django csrftoken + sessionid -> Django",
        find(detect(H({{"Set-Cookie", "csrftoken=x"}, {"Set-Cookie", "sessionid=y"}}), ""), "Django") != nullptr);

    // ---- well-gated positives still fire (no regression) ----------------
    chk("tomcat body marker -> version",
        [](){ const Tech *t = find(body("<h3>Apache Tomcat/9.0.30</h3>"), "Apache Tomcat");
              return t && t->version == "9.0.30" && t->cveKind == "app-tomcat"; }());
    chk("server header Apache -> version",
        [](){ const Tech *t = find(detect(H({{"Server", "Apache/2.4.52 (Ubuntu)"}}), ""), "Apache");
              return t && t->version == "2.4.52" && t->cveKind == "server-apache"; }());
    chk("wordpress generator meta -> version",
        [](){ const Tech *t = find(body("<meta name='generator' content='WordPress 6.4.2'>"), "WordPress");
              return t && t->version == "6.4.2"; }());
    chk("grafana gated marker -> version",
        [](){ const Tech *t = find(body("window.grafanaBootData={\"settings\":{\"buildInfo\":{\"version\":\"9.5.2\"}}}"), "Grafana");
              return t && t->version == "9.5.2"; }());
    chk("phpsessid cookie -> PHP", find(detect(H({{"Set-Cookie", "PHPSESSID=abc"}}), ""), "PHP") != nullptr);

    // ---- buildGet: CR/LF guards ----------------------------------------
    {
        Request req; req.host = "victim.tld"; req.basePath = "/";
        chk("build: request line", buildGet(req).startsWith("GET / HTTP/1.1\r\n"));
        chk("build: Host", buildGet(req).contains("Host: victim.tld\r\n"));
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildGet(badHost).isEmpty());
        Request badPath = req; badPath.basePath = "/\r\nX: y";
        chk("build: CRLF path -> empty", buildGet(badPath).isEmpty());
    }

    std::fprintf(stderr, "http_fingerprint_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
