// Pure advanced scope-control logic (see scope_logic.hpp). Qt6::Core only.

#include "scope_logic.hpp"

#include <QJsonObject>
#include <QJsonValue>

namespace Nullock::Proxy::ScopeLogic {

namespace {
// Anchor + case-insensitive, mirroring the glob compile (\A..\z, not ^..$, so a
// trailing-newline host/path can't over-match). Returns an invalid QRegularExpression
// if the pattern is bad -- the caller drops such a rule.
QRegularExpression anchored(const QString &pat) {
    QRegularExpression rx(QStringLiteral("\\A(?:") + pat + QStringLiteral(")\\z"),
                          QRegularExpression::CaseInsensitiveOption);
    return rx;
}
} // namespace

QList<CompiledRule> compile(const QList<AdvancedScopeRule> &rules) {
    QList<CompiledRule> out;
    for (const AdvancedScopeRule &r : rules) {
        if (out.size() >= kMaxRules) break;
        // Size caps first (a huge pattern is a footgun even before compiling).
        if (r.hostRegex.size() > kMaxPatternBytes) continue;
        if (r.fileRegex.size() > kMaxPatternBytes) continue;

        CompiledRule c;
        c.enabled  = r.enabled;
        c.include  = r.include;
        c.protocol = (r.protocol == ProtoHttp || r.protocol == ProtoHttps) ? r.protocol : ProtoAny;
        c.hostAny  = r.hostRegex.isEmpty();
        c.fileAny  = r.fileRegex.isEmpty();
        c.portFrom = r.portFrom > 0 ? r.portFrom : 0;
        c.portTo   = r.portTo   > 0 ? r.portTo   : 0;

        if (!c.hostAny) {
            c.hostRx = anchored(r.hostRegex);
            if (!c.hostRx.isValid()) continue;   // fail-safe: drop uncompilable
            c.hostRx.optimize();
        }
        if (!c.fileAny) {
            c.fileRx = anchored(r.fileRegex);
            if (!c.fileRx.isValid()) continue;
            c.fileRx.optimize();
        }
        c.constrainsBeyondHost =
            (c.protocol != ProtoAny) || (c.portFrom > 0) || !c.fileAny;

        // Drop a blank EXCLUDE rule (every dimension "any"): it would match
        // everything and black out all scope -- almost always a mis-edit.
        if (!c.include && c.hostAny && c.fileAny && c.portFrom == 0 && c.protocol == ProtoAny)
            continue;

        out.append(c);
    }
    return out;
}

bool hasEnabledInclude(const QList<CompiledRule> &rules) {
    for (const CompiledRule &r : rules)
        if (r.enabled && r.include) return true;
    return false;
}

bool hasEnabledExclude(const QList<CompiledRule> &rules) {
    for (const CompiledRule &r : rules)
        if (r.enabled && !r.include) return true;
    return false;
}

bool portInRange(int portFrom, int portTo, int port) {
    if (portFrom <= 0) return true;              // any
    if (portTo   <= 0) return port == portFrom;  // exact
    return port >= portFrom && port <= portTo;   // inclusive range
}

bool ruleMatchesUrl(const CompiledRule &r, bool tls, const QString &host,
                    int port, const QString &path) {
    if (!r.enabled) return false;
    if (r.protocol != ProtoAny) {
        const int reqProto = tls ? ProtoHttps : ProtoHttp;
        if (r.protocol != reqProto) return false;
    }
    if (!r.hostAny && !r.hostRx.match(host).hasMatch()) return false;
    if (!portInRange(r.portFrom, r.portTo, port)) return false;
    if (!r.fileAny && !r.fileRx.match(path).hasMatch()) return false;
    return true;
}

bool urlInScope(const QList<CompiledRule> &rules, bool globOut, bool globIn,
                bool tls, const QString &host, int port, const QString &path) {
    // Deny wins across layers -- the glob out-of-scope layer first (as today).
    if (globOut) return false;
    // ...then an enabled advanced EXCLUDE.
    for (const CompiledRule &r : rules)
        if (r.enabled && !r.include && ruleMatchesUrl(r, tls, host, port, path))
            return false;
    // Inclusion: the advanced include regime governs only when includes exist.
    if (hasEnabledInclude(rules)) {
        for (const CompiledRule &r : rules)
            if (r.enabled && r.include && ruleMatchesUrl(r, tls, host, port, path))
                return true;
        return false;                 // has includes, none matched -> out
    }
    return globIn;                     // no advanced includes -> glob inclusion governs
}

bool hostInScope(const QList<CompiledRule> &rules, bool globOut, bool globIn,
                 const QString &host) {
    if (globOut) return false;
    // Fail closed: any enabled exclude whose HOST dimension matches this host
    // blocks it. We can't check a port/file dimension host-only, so a host-matching
    // exclude under-permits (blocks) rather than letting a forbidden attack fire.
    for (const CompiledRule &r : rules)
        if (r.enabled && !r.include && (r.hostAny || r.hostRx.match(host).hasMatch()))
            return false;
    if (hasEnabledInclude(rules)) {
        for (const CompiledRule &r : rules)
            if (r.enabled && r.include && (r.hostAny || r.hostRx.match(host).hasMatch()))
                return true;
        return false;
    }
    return globIn;
}

QList<AdvancedScopeRule> rulesFromJson(const QJsonArray &arr) {
    QList<AdvancedScopeRule> out;
    for (const QJsonValue &v : arr) {
        const QJsonObject o = v.toObject();
        AdvancedScopeRule r;
        r.enabled   = o.value("enabled").toBool(true);
        r.include   = o.value("include").toBool(true);
        r.protocol  = o.value("protocol").toInt(ProtoAny);
        r.hostRegex = o.value("host").toString();
        r.portFrom  = o.value("portFrom").toInt(0);
        r.portTo    = o.value("portTo").toInt(0);
        r.fileRegex = o.value("file").toString();
        out.append(r);
    }
    return out;
}

QJsonArray rulesToJson(const QList<AdvancedScopeRule> &rules) {
    QJsonArray arr;
    for (const AdvancedScopeRule &r : rules)
        arr.append(QJsonObject{
            { "enabled", r.enabled }, { "include", r.include },
            { "protocol", r.protocol }, { "host", r.hostRegex },
            { "portFrom", r.portFrom }, { "portTo", r.portTo },
            { "file", r.fileRegex } });
    return arr;
}

} // namespace Nullock::Proxy::ScopeLogic
