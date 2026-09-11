#pragma once

// Pure advanced scope-control logic. Burp's "advanced scope": include/exclude
// rules over protocol / host-regex / port-range / file-regex.
//
// CRITICAL DESIGN (from the adversarial review): advanced scope COMPOSES on top
// of the existing simple host-glob scope, it NEVER replaces it. The composed
// decision is:
//   * OUT iff  (a simple out-of-scope glob matched)  OR  (an enabled advanced
//              EXCLUDE rule matched)                       -- deny wins across layers
//   * IN  requires: if >=1 enabled advanced INCLUDE rule exists, the URL must match
//              one of them (advanced inclusion regime); otherwise the simple
//              in-scope layer governs allow (glob-in).
// So with NO enabled advanced rules the decision is byte-identical to today, and a
// lone EXCLUDE rule can never silently widen scope to allow-all.
//
// The decision + the regex compilation both live here so they can be unit-tested
// against Qt6::Core alone; the ProxyServer just holds the compiled rules under its
// scope mutex and supplies the glob-layer booleans.

#include <QJsonArray>
#include <QList>
#include <QRegularExpression>
#include <QString>

namespace Nullock::Proxy::ScopeLogic {

enum Protocol { ProtoAny = 0, ProtoHttp = 1, ProtoHttps = 2 };

// Raw / wire form (round-trips through JSON + project.json). A regex dimension
// left empty means "match any"; port 0 means "any port".
struct AdvancedScopeRule {
    bool    enabled  = true;
    bool    include  = true;          // true = include rule, false = exclude rule
    int     protocol = ProtoAny;      // 0=any, 1=http, 2=https
    QString hostRegex;                // matched against host; empty = any
    int     portFrom = 0;             // 0 = any
    int     portTo   = 0;             // 0 => exact portFrom (when portFrom>0)
    QString fileRegex;                // matched against the path; empty = any
};

// Compiled policy. Invalid enabled rules produce a universal deny policy;
// API edits are rejected before persistence. No broken rule is silently omitted.
struct CompiledRule {
    bool enabled = false;
    bool include = true;
    int  protocol = ProtoAny;
    bool hostAny = true;
    QRegularExpression hostRx;
    int  portFrom = 0;
    int  portTo   = 0;
    bool fileAny = true;
    QRegularExpression fileRx;
    // True when the rule constrains a dimension a host-only caller can't evaluate
    // (protocol / port / file). Drives the host-only fail-closed path.
    bool constrainsBeyondHost = false;
};

inline constexpr int kMaxPatternBytes = 4096;   // mirror the M&R rule cap
inline constexpr int kMaxRules        = 256;

// Validate enabled rules and bounded input. Disabled drafts are ignored.
// compile anchors expressions and returns a deny policy if validation fails.
QString validationError(const QList<AdvancedScopeRule> &rules);
QList<CompiledRule> compile(const QList<AdvancedScopeRule> &rules);

bool hasEnabledInclude(const QList<CompiledRule> &rules);
bool hasEnabledExclude(const QList<CompiledRule> &rules);
inline bool configured(const QList<CompiledRule> &rules) {
    return hasEnabledInclude(rules) || hasEnabledExclude(rules);
}

// Numeric port match. from<=0 => any; to<=0 => exact `from`; else inclusive range.
bool portInRange(int portFrom, int portTo, int port);

// Does an enabled rule match this full URL? protocol + host + port + file, each
// empty/any dimension a pass.
bool ruleMatchesUrl(const CompiledRule &r, bool tls, const QString &host,
                    int port, const QString &path);

// The COMPOSED full-URL decision (see the header comment for the exact fold).
bool urlInScope(const QList<CompiledRule> &rules, bool globOut, bool globIn,
                bool tls, const QString &host, int port, const QString &path);

// Host-only decision for gates that lack the port/path. FAIL-CLOSED: any enabled
// EXCLUDE whose host dimension matches this host blocks it -- we can't evaluate a
// port/file dimension host-only, so we UNDER-permit (block) rather than fire an
// attack an exclude was meant to forbid. Include/glob layers govern allow.
bool hostInScope(const QList<CompiledRule> &rules, bool globOut, bool globIn,
                 const QString &host);

// Preliminary admission only. A constrained exclusion must be evaluated at
// the actual URL/transport boundary, not black out every path on its host.
bool mayTargetHost(const QList<CompiledRule> &rules, bool globOut, bool globIn, const QString &host);
// Raw connections have no path. Require a path-unrestricted include; any
// possibly matching exclusion denies. Unknown protocol cannot satisfy an
// HTTP/HTTPS-only include.
bool transportInScope(const QList<CompiledRule> &rules, bool globOut, bool globIn,
                      const QString &host, int port, int protocol);

// JSON <-> raw rules (API body + project.json persistence).
QList<AdvancedScopeRule> rulesFromJson(const QJsonArray &arr);
QJsonArray               rulesToJson(const QList<AdvancedScopeRule> &rules);

} // namespace Nullock::Proxy::ScopeLogic
