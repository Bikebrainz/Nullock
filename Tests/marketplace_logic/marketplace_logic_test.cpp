// Extension marketplace -- the trust boundary.
//
// This module decides whether third-party JavaScript is allowed to land in the
// directory the proxy's JS engine loads from. That engine sees every request and
// response the user's browser makes, so a wrong "yes" here hands an attacker
// session cookies and bearer tokens for a live engagement. There is no sandbox
// downstream that makes a bad decision survivable.
//
// So the cases below are weighted toward the FAIL-OPEN direction: for every
// check, the important assertion is not "it accepts the good input" but "it
// refuses the malformed, the missing, and the almost-right". A parser that
// repairs its input is the bug being tested for.

#include "marketplace_logic.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QSet>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::MarketplaceLogic;

static int pass = 0, fail = 0;
static void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

// sha256("") and sha256("x") -- fixed vectors so the digest itself is pinned and
// not merely self-consistent.
static const char *kSha256Empty =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ================= integrity =========================================
    {
        chk("sha256: empty string matches the known vector",
            sha256Hex(QByteArray()) == QLatin1String(kSha256Empty));
        chk("sha256: output is 64 lowercase hex chars",
            sha256Hex("hello").size() == 64
            && sha256Hex("hello") == sha256Hex("hello").toLower());
        chk("sha256: one changed byte changes the digest",
            sha256Hex("hello") != sha256Hex("hellp"));

        chk("wellformed: exactly 64 hex is accepted", isWellFormedSha256(kSha256Empty));
        chk("wellformed: uppercase hex is accepted",
            isWellFormedSha256(QString(kSha256Empty).toUpper()));
        chk("wellformed: 63 chars rejected", !isWellFormedSha256(QString(kSha256Empty).left(63)));
        chk("wellformed: 65 chars rejected", !isWellFormedSha256(QString(kSha256Empty) + "a"));
        chk("wellformed: empty rejected", !isWellFormedSha256(""));
        chk("wellformed: non-hex rejected",
            !isWellFormedSha256("g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        chk("wellformed: whitespace rejected",
            !isWellFormedSha256(" 3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

        // THE load-bearing one. If a missing expectation ever verifies, an
        // attacker who can drop a field from the catalog can install anything.
        chk("verify: an EMPTY expected hash must NOT verify",
            !verifyIntegrity("anything", ""));
        chk("verify: a malformed expected hash must NOT verify",
            !verifyIntegrity("anything", "deadbeef"));
        chk("verify: a null expected hash must NOT verify",
            !verifyIntegrity("anything", QString()));
        chk("verify: correct digest verifies",
            verifyIntegrity(QByteArray(), kSha256Empty));
        chk("verify: correct digest verifies case-insensitively",
            verifyIntegrity(QByteArray(), QString(kSha256Empty).toUpper()));
        chk("verify: wrong digest does not verify",
            !verifyIntegrity("hello", kSha256Empty));
        chk("verify: empty data against a real non-empty digest fails",
            !verifyIntegrity(QByteArray(), sha256Hex("hello")));
    }

    // ================= transport trust ===================================
    {
        // Pin the allow-list itself. Adding a host here is a security decision;
        // this case makes an accidental widening fail loudly rather than pass.
        const QStringList hosts = trustedHosts();
        chk("hosts: the allow-list is exactly the two expected entries",
            hosts.size() == 2
            && hosts.contains("raw.githubusercontent.com")
            && hosts.contains("bikebrainz.github.io"));

        chk("url: an allow-listed https url is trusted",
            isTrustedAssetUrl("https://raw.githubusercontent.com/o/r/b/x.js"));
        chk("url: a subdomain of an allow-listed host is trusted",
            isTrustedAssetUrl("https://cdn.raw.githubusercontent.com/x.js"));

        chk("url: http is rejected",
            !isTrustedAssetUrl("http://raw.githubusercontent.com/x.js"));
        chk("url: an unlisted host is rejected",
            !isTrustedAssetUrl("https://evil.tld/x.js"));
        // The classic: a substring or endsWith check on the allow-listed name
        // accepts this, because the real host is evil.tld.
        chk("url: userinfo-@ bypass rejected (host is evil.tld)",
            !isTrustedAssetUrl("https://raw.githubusercontent.com@evil.tld/x.js"));
        chk("url: userinfo with password rejected",
            !isTrustedAssetUrl("https://user:pw@raw.githubusercontent.com/x.js"));
        // Dot-anchoring: a prefix look-alike must not pass.
        chk("url: prefix look-alike rejected (evilraw.githubusercontent.com)",
            !isTrustedAssetUrl("https://evilraw.githubusercontent.com/x.js"));
        chk("url: suffix look-alike rejected (…com.evil.tld)",
            !isTrustedAssetUrl("https://raw.githubusercontent.com.evil.tld/x.js"));
        chk("url: a non-443 port on an allow-listed host is rejected",
            !isTrustedAssetUrl("https://raw.githubusercontent.com:8443/x.js"));
        chk("url: an explicit :443 is fine",
            isTrustedAssetUrl("https://raw.githubusercontent.com:443/x.js"));
        chk("url: javascript: scheme rejected", !isTrustedAssetUrl("javascript:alert(1)"));
        chk("url: file: scheme rejected", !isTrustedAssetUrl("file:///etc/passwd"));
        chk("url: empty rejected", !isTrustedAssetUrl(""));
        chk("url: garbage rejected", !isTrustedAssetUrl("not a url at all"));

        QString host, target;
        chk("split: a trusted url splits into host + target",
            splitTrustedUrl("https://raw.githubusercontent.com/o/r/x.js", &host, &target)
            && host == "raw.githubusercontent.com" && target == "/o/r/x.js");
        chk("split: the query string is preserved",
            splitTrustedUrl("https://raw.githubusercontent.com/x.js?v=2", &host, &target)
            && target == "/x.js?v=2");
        chk("split: a bare host gets target '/'",
            splitTrustedUrl("https://bikebrainz.github.io", &host, &target)
            && target == "/");
        // splitTrustedUrl must not be a way around isTrustedAssetUrl.
        host.clear(); target.clear();
        chk("split: an untrusted url returns false and writes nothing",
            !splitTrustedUrl("https://evil.tld/x.js", &host, &target)
            && host.isEmpty() && target.isEmpty());
    }

    // ================= path confinement ==================================
    {
        chk("name: a plain id becomes id.js", safeScriptFileName("aws_sigv4") == "aws_sigv4.js");
        chk("name: dashes and digits are fine", safeScriptFileName("x-9_a") == "x-9_a.js");

        chk("name: forward-slash traversal rejected", safeScriptFileName("../evil").isEmpty());
        chk("name: back-slash traversal rejected", safeScriptFileName("..\\evil").isEmpty());
        chk("name: a bare separator rejected", safeScriptFileName("a/b").isEmpty());
        chk("name: a backslash separator rejected", safeScriptFileName("a\\b").isEmpty());
        chk("name: an absolute posix path rejected", safeScriptFileName("/etc/passwd").isEmpty());
        // Windows: a drive letter and a UNC prefix are both absolute.
        chk("name: a drive-letter path rejected", safeScriptFileName("C:evil").isEmpty());
        chk("name: a UNC path rejected", safeScriptFileName("\\\\host\\share").isEmpty());
        // An NTFS alternate data stream is a colon, which the allow-list bars.
        chk("name: an ADS colon rejected", safeScriptFileName("good:bad").isEmpty());
        chk("name: '.' rejected", safeScriptFileName(".").isEmpty());
        chk("name: '..' rejected", safeScriptFileName("..").isEmpty());
        chk("name: a leading dot rejected", safeScriptFileName(".hidden").isEmpty());
        chk("name: a trailing dot rejected (Windows strips it)",
            safeScriptFileName("evil.").isEmpty());
        chk("name: empty rejected", safeScriptFileName("").isEmpty());
        chk("name: whitespace-only rejected", safeScriptFileName("   ").isEmpty());
        chk("name: an embedded space rejected", safeScriptFileName("a b").isEmpty());
        chk("name: a NUL rejected", safeScriptFileName(QString("a") + QChar(0) + "b").isEmpty());
        chk("name: over-long rejected", safeScriptFileName(QString(65, 'a')).isEmpty());
        chk("name: exactly 64 accepted", !safeScriptFileName(QString(64, 'a')).isEmpty());
        // Windows device names are not files no matter what directory they are in.
        chk("name: CON rejected", safeScriptFileName("CON").isEmpty());
        chk("name: con lowercase rejected", safeScriptFileName("con").isEmpty());
        chk("name: NUL rejected", safeScriptFileName("nul").isEmpty());
        chk("name: COM1 rejected", safeScriptFileName("COM1").isEmpty());
        chk("name: LPT9 rejected", safeScriptFileName("LPT9").isEmpty());
        chk("name: CON.something rejected (stem is still the device)",
            safeScriptFileName("CON.backup").isEmpty());
        chk("name: 'console' is NOT a device and is accepted",
            safeScriptFileName("console") == "console.js");
        chk("name: unicode rejected", safeScriptFileName(QString::fromUtf8("café")).isEmpty());
    }

    // ================= catalog parsing ===================================
    {
        const QString goodSha = sha256Hex("body");
        auto entryJson = [&](const QString &id, const QString &url, const QString &sha) {
            return QStringLiteral(
                R"({"id":"%1","name":"N","summary":"S","version":"1.0.0",)"
                R"("author":"A","url":"%2","sha256":"%3"})").arg(id, url, sha);
        };
        const QString goodUrl = "https://raw.githubusercontent.com/o/r/x.js";

        {
            const QString js = QStringLiteral(R"({"version":1,"updated":"2026-01-01","extensions":[%1]})")
                                   .arg(entryJson("good", goodUrl, goodSha));
            const Catalog c = parseCatalog(js.toUtf8());
            chk("catalog: a well-formed doc parses", c.error.isEmpty() && c.entries.size() == 1);
            chk("catalog: version and updated survive", c.version == 1 && c.updated == "2026-01-01");
            chk("catalog: the sha is lowercased", c.entries.at(0).sha256 == goodSha.toLower());
        }

        // Each of these must DROP the entry, not repair it. Exactly one field
        // is wrong per row and every other field is valid, so a pass proves the
        // named check fired and not some unrelated one.
        struct Bad { const char *label; QString id, url, sha; };
        const Bad bads[] = {
            { "an entry with no sha256 is dropped",
              "a", goodUrl, QString() },
            { "an entry with a short sha256 is dropped",
              "a", goodUrl, QStringLiteral("abc") },
            { "an entry with a non-hex sha256 is dropped",
              "a", goodUrl, QString(64, QLatin1Char('z')) },
            { "an entry with an http url is dropped",
              "a", QStringLiteral("http://raw.githubusercontent.com/x.js"), goodSha },
            { "an entry on an unlisted host is dropped",
              "a", QStringLiteral("https://evil.tld/x.js"), goodSha },
            { "an entry with a userinfo-@ url is dropped",
              "a", QStringLiteral("https://raw.githubusercontent.com@evil.tld/x.js"), goodSha },
            { "an entry with a traversal id is dropped",
              QStringLiteral("../x"), goodUrl, goodSha },
            { "an entry with a separator in the id is dropped",
              QStringLiteral("a/b"), goodUrl, goodSha },
            { "an entry with an empty id is dropped",
              QString(), goodUrl, goodSha },
        };
        for (const Bad &b : bads) {
            const QString js = QStringLiteral(R"({"version":1,"extensions":[%1]})")
                                   .arg(entryJson(b.id, b.url, b.sha));
            const Catalog c = parseCatalog(js.toUtf8());
            chk(b.label, c.entries.isEmpty() && !c.error.isEmpty());
        }

        {
            // A good entry alongside a bad one: the good one survives, the bad
            // one is dropped. Partial failure must not take the catalog down.
            const QString js = QStringLiteral(R"({"version":1,"extensions":[%1,%2]})")
                .arg(entryJson("bad", "https://evil.tld/x.js", goodSha),
                     entryJson("good", goodUrl, goodSha));
            const Catalog c = parseCatalog(js.toUtf8());
            chk("catalog: one bad entry does not sink the good ones",
                c.error.isEmpty() && c.entries.size() == 1 && c.entries.at(0).id == "good");
        }
        {
            // Duplicate ids would collide on disk; first wins, rest dropped.
            const QString js = QStringLiteral(R"({"version":1,"extensions":[%1,%2]})")
                .arg(entryJson("dup", goodUrl, goodSha), entryJson("dup", goodUrl, goodSha));
            const Catalog c = parseCatalog(js.toUtf8());
            chk("catalog: a duplicate id is dropped", c.entries.size() == 1);
        }

        chk("catalog: empty input errors", !parseCatalog(QByteArray()).error.isEmpty());
        chk("catalog: non-JSON errors", !parseCatalog("not json").error.isEmpty());
        chk("catalog: a JSON array (not object) errors", !parseCatalog("[1,2]").error.isEmpty());
        chk("catalog: no extensions key errors", !parseCatalog(R"({"version":1})").error.isEmpty());
        chk("catalog: an empty extensions array errors",
            !parseCatalog(R"({"version":1,"extensions":[]})").error.isEmpty());
        {
            QByteArray huge(kMaxCatalogBytes + 1, 'x');
            chk("catalog: an oversized document is refused before parsing",
                !parseCatalog(huge).error.isEmpty());
        }
    }

    // ================= install audit =====================================
    {
        CatalogEntry e;
        e.id = "demo";
        e.name = "Demo";
        e.summary = "does a thing";
        e.version = "1.0.0";
        e.url = "https://raw.githubusercontent.com/o/r/demo.js";
        e.sha256 = sha256Hex("x");

        {
            const InstallAudit a = auditInstall(e, "console.log(1)", {});
            chk("audit: an observe-only extension is ok", a.ok && a.blocker.isEmpty());
            chk("audit: observe-only does not flag traffic mutation", !a.mutatesTraffic);
            chk("audit: observe-only has no undeclared permissions",
                a.undeclaredPermissions.isEmpty());
        }
        {
            // The script asks to rewrite requests; the catalog said nothing.
            // That must surface, because the script's directive is what the
            // engine enforces -- the catalog's silence is not binding.
            const InstallAudit a = auditInstall(e, "x", { "modify-requests" });
            chk("audit: a mutating capability is flagged", a.mutatesTraffic);
            chk("audit: an undeclared capability is reported",
                a.undeclaredPermissions.contains("modify-requests"));
            chk("audit: an undeclared capability warns but does not block",
                a.ok && !a.warnings.isEmpty());
        }
        {
            e.declaredPermissions = QStringList{ "modify-requests" };
            const InstallAudit a = auditInstall(e, "x", { "modify-requests" });
            chk("audit: a declared capability is not reported as undeclared",
                a.undeclaredPermissions.isEmpty());
            chk("audit: but it is still flagged as mutating", a.mutatesTraffic);
            e.declaredPermissions = QStringList{ "Modify-Requests" };
            const InstallAudit b = auditInstall(e, "x", { "modify-requests" });
            chk("audit: declaration matching is case-insensitive",
                b.undeclaredPermissions.isEmpty());
            e.declaredPermissions.clear();
        }
        {
            const InstallAudit a = auditInstall(e, QByteArray(), {});
            chk("audit: an empty script is BLOCKED", !a.ok && !a.blocker.isEmpty());
        }
        {
            const InstallAudit a = auditInstall(e, QByteArray(kMaxScriptBytes + 1, 'x'), {});
            chk("audit: an oversized script is BLOCKED", !a.ok && !a.blocker.isEmpty());
        }
        {
            CatalogEntry bad = e;
            bad.id = "../escape";
            const InstallAudit a = auditInstall(bad, "x", {});
            chk("audit: an unsafe id is BLOCKED", !a.ok && !a.blocker.isEmpty());
        }
        {
            const InstallAudit a = auditInstall(e, "x", { "modify-requests", "modify-responses" });
            chk("audit: permissions are reported sorted and complete",
                a.effectivePermissions == QStringList({ "modify-requests", "modify-responses" }));
        }
    }

    // ================= installed version + merge =========================
    {
        chk("version: a directive is read",
            parseInstalledVersion("// nullock:version 1.2.3\ncode();") == "1.2.3");
        chk("version: a leading v is stripped",
            parseInstalledVersion("// nullock:version v2.0.0") == "2.0.0");
        chk("version: the @ form works",
            parseInstalledVersion("// @nullock-version 3.1.0") == "3.1.0");
        chk("version: case-insensitive",
            parseInstalledVersion("// NULLOCK:VERSION 1.0.0") == "1.0.0");
        chk("version: absent yields empty", parseInstalledVersion("code();").isEmpty());
        chk("version: a non-comment line does not count",
            parseInstalledVersion("var s = 'nullock:version 9.9.9';").isEmpty());

        Catalog c;
        CatalogEntry a; a.id = "a"; a.version = "2.0.0";
        CatalogEntry b; b.id = "b"; b.version = "1.0.0";
        c.entries = { a, b };

        {
            const auto m = merge(c, {}, {});
            chk("merge: nothing installed => all NotInstalled",
                m.size() == 2 && m.at(0).state == InstallState::NotInstalled);
        }
        {
            const auto m = merge(c, { "a.js" }, { { "a", "1.0.0" } });
            chk("merge: an older installed version is UpdateAvailable",
                m.at(0).state == InstallState::UpdateAvailable);
            chk("merge: the installed version is reported",
                m.at(0).installedVersion == "1.0.0");
            chk("merge: the other entry is still NotInstalled",
                m.at(1).state == InstallState::NotInstalled);
        }
        {
            const auto m = merge(c, { "a.js" }, { { "a", "2.0.0" } });
            chk("merge: an equal version is Installed, not UpdateAvailable",
                m.at(0).state == InstallState::Installed);
        }
        {
            const auto m = merge(c, { "a.js" }, { { "a", "3.0.0" } });
            chk("merge: a NEWER installed version is Installed, not a downgrade prompt",
                m.at(0).state == InstallState::Installed);
        }
        {
            // Unknown installed version must NOT be reported as an update --
            // nagging on a comparison we cannot make trains the user to click
            // through the confirm prompt, which is the only real protection.
            const auto m = merge(c, { "a.js" }, {});
            chk("merge: an unknown installed version is Installed, not UpdateAvailable",
                m.at(0).state == InstallState::Installed);
        }
        {
            const auto m = merge(c, { "a.js", "handwritten.js" }, {});
            chk("merge: an on-disk script absent from the catalog appears as Local",
                m.size() == 3
                && m.at(2).state == InstallState::Local
                && m.at(2).entry.id == "handwritten");
        }
        {
            const auto m = merge(c, { "notes.txt", "a.js" }, {});
            chk("merge: a non-.js file in the dir is ignored",
                m.size() == 2);
        }
    }

    std::fprintf(stderr, "\nmarketplace_logic: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
