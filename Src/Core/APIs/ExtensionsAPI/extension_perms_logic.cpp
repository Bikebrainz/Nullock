#include "extension_perms_logic.hpp"

#include <QRegularExpression>
#include <QStringList>

namespace Nullock::Core::ExtensionPerms {

namespace {
constexpr int kMaxScan = 64 * 1024;   // permission directive lives in the header

// Map a declared token (alias-tolerant) to its canonical capability, or "" if
// it's an unknown/observe-level token we don't need to grant.
QString canonical(const QString &tokenIn) {
    const QString t = tokenIn.trimmed().toLower();
    if (t.isEmpty()) return {};
    if (t == QLatin1String("onrequest") || t == QLatin1String("modify-request")
        || t == QLatin1String("modify-requests") || t == QLatin1String("mutate-request")
        || t == QLatin1String("mutate-requests"))
        return kModifyRequests;
    if (t == QLatin1String("onresponse-mutate") || t == QLatin1String("modify-response")
        || t == QLatin1String("modify-responses") || t == QLatin1String("mutate-response")
        || t == QLatin1String("mutate-responses"))
        return kModifyResponses;
    // Anything else (observe, log, report-findings, or a future capability) is
    // kept verbatim -- harmless for gating (only the dangerous set is enforced).
    return t;
}
} // namespace

QSet<QString> parsePermissions(const QString &jsSource) {
    QSet<QString> out;
    const QString src = jsSource.size() > kMaxScan ? jsSource.left(kMaxScan) : jsSource;

    // // nullock:permissions a, b   OR   // @nullock-permissions a b
    // No trailing `$` anchor: [^\r\n]+ already stops at the line end, and a `$`
    // would fail to match before a CR on CRLF-terminated (Windows) files.
    static const QRegularExpression re(
        QStringLiteral("(?im)^[ \\t]*//[ \\t]*@?nullock[:-]permissions[ \\t:]*([^\\r\\n]+)"));
    auto it = re.globalMatch(src);
    while (it.hasNext()) {
        const QString rest = it.next().captured(1);
        for (const QString &tok : rest.split(QRegularExpression(QStringLiteral("[,\\s]+")),
                                             Qt::SkipEmptyParts)) {
            const QString c = canonical(tok);
            if (!c.isEmpty()) out.insert(c);
        }
    }
    return out;
}

bool requiresGrant(const QString &capability) {
    return capability == kModifyRequests || capability == kModifyResponses;
}

bool isAllowed(const QSet<QString> &granted, const QString &capability) {
    if (!requiresGrant(capability)) return true;   // observe / log / report: free
    return granted.contains(capability);           // dangerous: default-deny
}

} // namespace Nullock::Core::ExtensionPerms
