// Tests for the extension permission gate
// (Src/Core/APIs/ExtensionsAPI/extension_perms_logic.cpp). Invariants:
//   * a header directive's declared capabilities parse (alias-tolerant,
//     case-insensitive, comma/space separated);
//   * no directive -> empty grant set;
//   * the dangerous capabilities (modify-requests / modify-responses) are
//     DEFAULT-DENY -- allowed only when explicitly granted;
//   * observe-level capabilities are always allowed.
//
// Run via:  ctest -R extension_perms_logic -V

#include "extension_perms_logic.hpp"

#include <QCoreApplication>

#include <cstdio>

using namespace Nullock::Core::ExtensionPerms;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ----- parse: canonical + aliases -----
    {
        const QSet<QString> g = parsePermissions(
            "// nullock:permissions modify-requests, modify-responses\n"
            "nullock.onRequest(function(e){return e;});\n");
        chk("parse both dangerous caps", g.contains(kModifyRequests) && g.contains(kModifyResponses));
    }
    {
        const QSet<QString> g = parsePermissions("// @nullock-permissions onRequest\n");
        chk("alias onRequest -> modify-requests", g.contains(kModifyRequests));
        chk("only what was declared", !g.contains(kModifyResponses));
    }
    {
        const QSet<QString> g = parsePermissions("//   NULLOCK:PERMISSIONS   Modify-Responses  \n");
        chk("case-insensitive directive + cap", g.contains(kModifyResponses));
    }
    {
        const QSet<QString> g = parsePermissions("// nullock:permissions onResponse-mutate mutate-requests\n");
        chk("space-separated + aliases", g.contains(kModifyResponses) && g.contains(kModifyRequests));
    }
    {
        // directive not on the first line still found.
        const QSet<QString> g = parsePermissions(
            "// AWS SigV4 signer\n// author: x\n// nullock:permissions modify-requests\nvar k=1;\n");
        chk("directive below other comments", g.contains(kModifyRequests));
    }
    {
        // CRLF (Windows) line endings must still match -- a trailing `$` anchor
        // would fail before the CR. This is the exact bug the live test caught.
        const QSet<QString> g = parsePermissions(
            "// nullock:permissions modify-requests\r\nnullock.onRequest(function(e){return e;});\r\n");
        chk("CRLF line endings: directive still matches", g.contains(kModifyRequests));
    }

    // ----- no directive -> empty -----
    chk("no directive -> empty", parsePermissions("nullock.log('hi');\n").isEmpty());
    chk("empty source -> empty", parsePermissions(QString()).isEmpty());
    {
        // a mention that isn't the directive doesn't grant anything.
        chk("non-directive mention -> empty",
            parsePermissions("// this extension does modify-requests to headers\n").isEmpty());
    }

    // ----- requiresGrant -----
    chk("modify-requests requires grant", requiresGrant(kModifyRequests));
    chk("modify-responses requires grant", requiresGrant(kModifyResponses));
    chk("observe does not require grant", !requiresGrant(QStringLiteral("observe")));
    chk("report-findings does not require grant", !requiresGrant(QStringLiteral("report-findings")));

    // ----- isAllowed: default-deny the dangerous ones -----
    {
        const QSet<QString> none;
        chk("undeclared modify-requests DENIED", !isAllowed(none, kModifyRequests));
        chk("undeclared modify-responses DENIED", !isAllowed(none, kModifyResponses));
        chk("observe always allowed", isAllowed(none, QStringLiteral("observe")));
        chk("log always allowed", isAllowed(none, QStringLiteral("log")));
    }
    {
        QSet<QString> g; g.insert(kModifyRequests);
        chk("granted modify-requests ALLOWED", isAllowed(g, kModifyRequests));
        chk("but modify-responses still DENIED", !isAllowed(g, kModifyResponses));
    }

    // ----- bounded: a huge file with the directive at the top still parses -----
    {
        QString big = "// nullock:permissions modify-requests\n";
        big += QString(200000, QLatin1Char('x'));   // 200k of filler
        chk("huge file: directive still found", parsePermissions(big).contains(kModifyRequests));
    }

    std::fprintf(stderr, "extension_perms_logic_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
