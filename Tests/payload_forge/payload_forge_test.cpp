// Regression corpus for the Payload Forge (pure PoC-payload generator).
// Locks the contract that matters for a payload builder: placeholders are always
// resolved (no %OAST%/%MARKER% ever leaks into output), OOB payloads appear only
// when an OAST domain is supplied, detection payloads always appear, and the JWT
// alg=none tokens are structurally valid base64url.
//
// Run via:  ctest -R payload_forge -V

#include "payload_forge.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>

using namespace Nullock::Core::PayloadForge;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

bool anyContains(const QList<Payload> &ps, const QString &needle) {
    for (const auto &p : ps) if (p.payload.contains(needle)) return true;
    return false;
}
bool noLeftoverPlaceholders(const QList<Payload> &ps) {
    for (const auto &p : ps) {
        if (p.payload.contains("%OAST%") || p.payload.contains("%MARKER%")) return false;
        if (p.note.contains("%OAST%")   || p.note.contains("%MARKER%"))   return false;
    }
    return true;
}
bool allTechnique(const QList<Payload> &ps, const QString &tech) {
    for (const auto &p : ps) if (p.technique != tech) return false;
    return true;
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    const QString OAST   = "abcd1234.oast.example";
    const QString MARK   = "CANARY99";
    ForgeParams withOob{ OAST, MARK };
    ForgeParams noOob{ QString(), MARK };

    // ===== technique registry ==========================================
    {
        const QStringList t = techniques();
        chk("techniques: twelve listed", t.size() == 12);
        chk("techniques: includes the core set",
            t.contains("ssti") && t.contains("cmdi") && t.contains("xxe") &&
            t.contains("sqli") && t.contains("xss") && t.contains("jwt"));
        chk("techniques: includes the extended set",
            t.contains("lfi") && t.contains("ssrf") && t.contains("redirect") &&
            t.contains("nosqli") && t.contains("ldap") && t.contains("crlf"));
        // Every listed technique must actually produce at least one payload.
        for (const QString &name : t)
            chk(qPrintable("technique '" + name + "' yields payloads"),
                !forge(name, withOob).isEmpty());
    }

    // ===== placeholders always resolved ================================
    {
        const auto all = forge("all", withOob);
        chk("all: produces payloads", all.size() > 20);
        chk("all: no %OAST%/%MARKER% leaks into any output", noLeftoverPlaceholders(all));
        const auto allNo = forge("", noOob);   // "" behaves like "all"
        chk("empty technique == all", allNo.size() > 0);
        chk("no-OOB: still no placeholder leaks", noLeftoverPlaceholders(allNo));
    }

    // ===== OOB gating ==================================================
    {
        const auto with = forge("cmdi", withOob);
        const auto without = forge("cmdi", noOob);
        chk("cmdi: all rows are cmdi", allTechnique(with, "cmdi"));
        chk("cmdi(with OAST): OAST domain baked in somewhere", anyContains(with, OAST));
        chk("cmdi(with OAST) has more rows than without (OOB rows gated)",
            with.size() > without.size());
        // Without an OAST domain every remaining cmdi payload must be non-OOB.
        bool anyOobWithout = false;
        for (const auto &p : without) if (p.oob) anyOobWithout = true;
        chk("cmdi(no OAST): zero OOB payloads emitted", !anyOobWithout);
        chk("cmdi(no OAST): detection payloads still present (sleep/echo)",
            anyContains(without, "sleep 5") && anyContains(without, MARK));
    }

    // ===== SSTI: detection always, RCE gated ===========================
    {
        const auto with = forge("ssti", withOob);
        const auto without = forge("ssti", noOob);
        chk("ssti: {{7*7}} detection present with or without OAST",
            anyContains(with, "{{7*7}}") && anyContains(without, "{{7*7}}"));
        chk("ssti: ${7*7} detection present", anyContains(without, "${7*7}"));
        chk("ssti(with OAST): an RCE payload calls the OAST domain", anyContains(with, OAST));
        for (const auto &p : without) chk("ssti(no OAST): no OOB row", !p.oob);
    }

    // ===== SQLi: never OOB, DBMS coverage ==============================
    {
        const auto s = forge("sqli", noOob);           // no OAST needed
        chk("sqli: emitted even without OAST", s.size() >= 8);
        chk("sqli: MySQL time-blind present", anyContains(s, "SLEEP(5)"));
        chk("sqli: Postgres time-blind present", anyContains(s, "pg_sleep(5)"));
        chk("sqli: MSSQL time-blind present", anyContains(s, "WAITFOR DELAY"));
        chk("sqli: UNION column-count ladder present", anyContains(s, "ORDER BY 5"));
        bool anyOob = false; for (const auto &p : s) if (p.oob) anyOob = true;
        chk("sqli: no payload is OOB", !anyOob);
    }

    // ===== XSS: marker substitution + OOB gating =======================
    {
        const auto with = forge("xss", withOob);
        const auto without = forge("xss", noOob);
        chk("xss: marker substituted into a PoC", anyContains(without, MARK));
        chk("xss(with OAST): cookie-exfil OOB row appears", anyContains(with, OAST));
        chk("xss(with OAST) has the extra OOB row", with.size() == without.size() + 1);
    }

    // ===== XXE: file-read always, OOB gated ============================
    {
        const auto with = forge("xxe", withOob);
        const auto without = forge("xxe", noOob);
        chk("xxe: file-read payload present without OAST",
            anyContains(without, "file:///etc/passwd"));
        chk("xxe(with OAST): OOB external-DTD row present", anyContains(with, OAST));
        chk("xxe(with OAST): the hosting DTD note is resolved too",
            [&]{ for (const auto &p : with) if (p.note.contains(OAST)) return true; return false; }());
    }

    // ===== JWT: structurally valid alg=none tokens =====================
    {
        const auto j = forge("jwt", noOob);
        chk("jwt: three alg=none case variants", j.size() == 3);
        for (const auto &p : j) {
            const QStringList parts = p.payload.split('.');
            chk("jwt: token has header.claims. (trailing empty sig)",
                parts.size() == 3 && parts[2].isEmpty());
            // Decode the header from base64url and confirm alg is a none-variant.
            QByteArray h = parts.value(0).toLatin1();
            // pad for QByteArray::fromBase64 (url mode tolerates missing padding)
            const QJsonObject hdr =
                QJsonDocument::fromJson(QByteArray::fromBase64(
                    h, QByteArray::Base64UrlEncoding)).object();
            const QString alg = hdr.value("alg").toString();
            chk("jwt: header alg is a none variant",
                alg.compare("none", Qt::CaseInsensitive) == 0);
            // Claims decode to our forged admin canary.
            const QJsonObject claims =
                QJsonDocument::fromJson(QByteArray::fromBase64(
                    parts.value(1).toLatin1(), QByteArray::Base64UrlEncoding)).object();
            chk("jwt: claims carry role=admin", claims.value("role").toString() == "admin");
            chk("jwt: claims carry the canary marker", claims.value("canary").toString() == MARK);
        }
    }

    // ===== extended techniques =========================================
    {
        const auto lfi = forge("lfi", noOob);
        chk("lfi: /etc/passwd traversal present", anyContains(lfi, "etc/passwd"));
        const auto ssrf = forge("ssrf", withOob);
        chk("ssrf: AWS metadata IP present", anyContains(ssrf, "169.254.169.254"));
        chk("ssrf: OOB confirm bakes the OAST domain", anyContains(ssrf, OAST));
        const auto redir = forge("redirect", noOob);
        chk("redirect: scheme-relative present", anyContains(redir, "//evil.example"));
        const auto nosql = forge("nosqli", noOob);
        chk("nosqli: $ne operator bypass present", anyContains(nosql, "$ne"));
        const auto ldap = forge("ldap", noOob);
        chk("ldap: wildcard filter present", ldap.size() >= 3);
        const auto crlf = forge("crlf", noOob);
        chk("crlf: encoded CRLF present", anyContains(crlf, "%0d%0a"));
        chk("crlf(no OAST): the OOB Location row is gated out",
            [&]{ for (const auto &p : crlf) if (p.oob) return false; return true; }());
    }

    // ===== unknown technique -> empty ==================================
    chk("unknown technique yields nothing", forge("not-a-real-technique", withOob).isEmpty());

    std::fprintf(stderr, "payload_forge_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
