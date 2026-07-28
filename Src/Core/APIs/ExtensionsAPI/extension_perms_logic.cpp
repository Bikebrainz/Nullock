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

// Shape of a DECLARATION token: must START WITH A LETTER, then letters/digits
// plus - _ . (real capability names are "modify-responses", "report-findings").
// The leading-letter rule is load-bearing, not decoration: allowing '-' anywhere
// made "--" itself declaration-shaped, so an em-dash prose separator sailed
// straight through and the sentence after it was still tokenised. Punctuation
// never STARTS a genuine capability name -- it only appears once prose has begun.
bool isDeclarationToken(const QString &t) {
    if (t.isEmpty() || !t.at(0).isLetter()) return false;
    for (const QChar c : t) {
        if (!(c.isLetterOrNumber() || c == QLatin1Char('-')
              || c == QLatin1Char('_') || c == QLatin1Char('.')))
            return false;
    }
    return true;
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
        // Stop at the first token that is not declaration-shaped. The capture
        // runs to end-of-line, so trailing PROSE used to be tokenised and
        // granted along with the list:
        //     // nullock:permissions observe -- do NOT grant modify-responses
        // tokenises to [observe, --, do, NOT, grant, modify-responses], and that
        // last token GRANTED the capability the sentence disclaims. This line is
        // exactly what a human reads before trusting an extension, so one that
        // scans as observe-only while granting mutation is a review-time
        // deception. Cutting at punctuation costs a legitimate declaration
        // nothing -- a real list is only names, commas and spaces.
        //
        // RESIDUAL, on purpose: prose made ENTIRELY of bare words still grants
        // ("observe only please modify-responses"). Closing that needs the
        // parser to reject tokens it does not recognise, which would break the
        // deliberate forward-compatibility of keeping unknown tokens verbatim.
        // That is a format decision, not a bug fix -- see the locks in the test.
        for (const QString &tok : rest.split(QRegularExpression(QStringLiteral("[,\\s]+")),
                                             Qt::SkipEmptyParts)) {
            if (!isDeclarationToken(tok)) break;   // prose started; ignore the rest
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
