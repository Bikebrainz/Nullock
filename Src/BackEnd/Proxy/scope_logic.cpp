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

QString validationError(const QList<AdvancedScopeRule> &rules) {
    if (rules.size() > kMaxRules) return QStringLiteral("Advanced scope exceeds the 256-rule limit");
    for (qsizetype i = 0; i < rules.size(); ++i) {
        const auto &r = rules[i];
        if (!r.enabled) continue;
        QString reason;
        if (r.hostRegex.size() > kMaxPatternBytes || r.fileRegex.size() > kMaxPatternBytes)
            reason = "pattern exceeds the 4096-character limit";
        else if ((!r.hostRegex.isEmpty() && !anchored(r.hostRegex).isValid())
                 || (!r.fileRegex.isEmpty() && !anchored(r.fileRegex).isValid())) reason = "invalid regular expression";
        else if (r.protocol < ProtoAny || r.protocol > ProtoHttps) reason = "invalid protocol";
        else if (r.portFrom < 0 || r.portFrom > 65535 || r.portTo < 0 || r.portTo > 65535
                 || (r.portTo > 0 && (r.portFrom == 0 || r.portTo < r.portFrom))) reason = "invalid port range";
        else if (!r.include && r.hostRegex.isEmpty() && r.fileRegex.isEmpty()
                 && r.portFrom == 0 && r.protocol == ProtoAny) reason = "empty exclusion; use an explicit host pattern to exclude all targets";
        if (!reason.isEmpty()) return QStringLiteral("Advanced scope rule %1: %2").arg(i + 1).arg(reason);
    }
    return {};
}

QList<CompiledRule> compile(const QList<AdvancedScopeRule> &rules) {
    if (!validationError(rules).isEmpty()) {
        // Imported/corrupt project settings must not widen scope by losing a
        // broken include or exclusion. One enabled universal deny fails closed.
        CompiledRule deny;
        deny.enabled = true;
        deny.include = false;
        return {deny};
    }
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

bool mayTargetHost(const QList<CompiledRule> &rules, bool globOut, bool globIn, const QString &host) {
    if (globOut) return false;
    for (const auto &r : rules)
        if (r.enabled && !r.include && !r.constrainsBeyondHost
            && (r.hostAny || r.hostRx.match(host).hasMatch())) return false;
    if (!hasEnabledInclude(rules)) return globIn;
    for (const auto &r : rules)
        if (r.enabled && r.include && (r.hostAny || r.hostRx.match(host).hasMatch())) return true;
    return false;
}

bool transportInScope(const QList<CompiledRule> &rules, bool globOut, bool globIn,
                      const QString &host, int port, int protocol) {
    if (globOut) return false;
    bool included = false;
    for (const auto &r : rules) {
        if (!r.enabled || (!r.hostAny && !r.hostRx.match(host).hasMatch())
            || !portInRange(r.portFrom, r.portTo, port)) continue;
        if (!r.include) {
            if (protocol == ProtoAny || r.protocol == ProtoAny || protocol == r.protocol) return false;
        } else if (r.fileAny && (r.protocol == ProtoAny || protocol == r.protocol)) {
            included = true;
        }
    }
    return hasEnabledInclude(rules) ? included : globIn;
}

QList<AdvancedScopeRule> rulesFromJson(const QJsonArray &arr) {
    QList<AdvancedScopeRule> out;
    for (const QJsonValue &v : arr) {
        const QJsonObject o = v.toObject();
        AdvancedScopeRule r;
        if (!v.isObject()
            || (o.contains("enabled") && !o.value("enabled").isBool())
            || (o.contains("include") && !o.value("include").isBool())
            || (o.contains("host") && !o.value("host").isString())
            || (o.contains("file") && !o.value("file").isString())
            || (o.contains("protocol") && (!o.value("protocol").isDouble() || o.value("protocol").toDouble() != o.value("protocol").toInt(-1)))
            || (o.contains("portFrom") && (!o.value("portFrom").isDouble() || o.value("portFrom").toDouble() != o.value("portFrom").toInt(-1)))
            || (o.contains("portTo") && (!o.value("portTo").isDouble() || o.value("portTo").toDouble() != o.value("portTo").toInt(-1)))) {
            r.protocol = -1; // validationError reports a malformed rule; fail closed on disk.
            out.append(r);
            continue;
        }
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
