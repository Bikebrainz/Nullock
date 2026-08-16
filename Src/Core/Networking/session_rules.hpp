#pragma once

// Session handling rules. The "Burp macros / session handling rules"
// equivalent: pull a value out of a response, then re-inject it into
// every subsequent request.
//
// Use cases this covers:
//   * CSRF token refresh -- grab `csrf_token` from each /form HTML
//     response, replace the value in the next POST's body.
//   * JWT refresh -- watch for `Authorization: Bearer ...` in a /login
//     response, substitute it into every subsequent request's
//     Authorization header.
//   * Per-request nonce -- read a header / cookie from any response,
//     inject into the next request.
//
// Two halves to each rule:
//
//   EXTRACT: From a response that matches host+path, pull a value via
//            one of: cookie name | header name | JSON path | regex on
//            body. Store under a named variable.
//
//   INJECT:  Into every subsequent request that matches host+path,
//            substitute `{{var}}` placeholders in the named target
//            field: request header / body / cookie / URL query.
//
// Implementation surface: applyToResponse() is called after every
// captured response (host-keyed bag updates), applyToRequest() runs
// before the request hits the wire (substitutes {{vars}}).

#include "proxy_server.hpp"
#include "session_rules_logic.hpp"   // SessionTool enum for tool scoping

#include <QHash>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QString>

namespace Nullock::Core {

struct SessionRule {
    QString name;
    bool    enabled = true;

    // Match shape -- both globs are case-insensitive, * matches any chars.
    QString hostGlob = "*";
    QString pathGlob = "*";

    // What to extract from the matched response.
    enum ExtractFrom {
        ExtractFromHeader   = 0,
        ExtractFromCookie   = 1,
        ExtractFromJsonPath = 2,   // dot-separated, e.g. data.session.token
        ExtractFromRegex    = 3,   // first capture group of regex on raw body
    };
    int     extractFrom   = ExtractFromHeader;
    QString extractKey;            // header name, cookie name, json path, or pattern
    QString variable;              // store as $variable

    // What to inject into matched requests.
    enum InjectInto {
        InjectIntoHeader = 0,
        InjectIntoCookie = 1,
        InjectIntoBody   = 2,
        InjectIntoUrl    = 3,      // appended as &k=v
    };
    int     injectInto    = InjectIntoHeader;
    QString injectKey;             // header name, cookie name, URL param name, or template-var name
    // Template can reference any captured variable as {{name}}. If empty,
    // we just use the bare {{variable}} substitution.
    QString injectTemplate;

    // Tools this rule applies to: a bitmask of SessionRulesLogic::SessionTool
    // (Proxy|Repeater|Intruder|Scanner). 0 = ALL tools, so a rule authored before
    // scoping existed keeps applying everywhere (backward-compatible).
    int     tools = 0;
};

class SessionRules : public QObject {
    Q_OBJECT
public:
    explicit SessionRules(QObject *parent = nullptr) : QObject(parent) {}

    void setRules(const QList<SessionRule> &rules);
    QList<SessionRule> rules() const;

    // Read variable bag (for the UI / debug). Snapshot copy.
    QHash<QString, QString> variables() const;

    // Session-acquisition bridge: merge externally-obtained variables (e.g. the
    // vars a recorded login MACRO extracted via ChainRunner) into the per-host
    // bag, so a token acquired by replaying a login sequence is then injected into
    // subsequent requests by the matching rules. Host-keyed like every other
    // captured value, so an acquired secret never rides cross-origin.
    void ingestVariables(const QString &host, const QHash<QString, QString> &vars);

    // Pipeline hooks. Both safe to call from worker threads. `tool` is the
    // SessionTool doing the send; a rule applies only if its tools scope includes
    // it (SessionRulesLogic::ruleAppliesToTool). Defaults to Proxy so existing
    // proxy-pipeline callers stay unchanged. Returns true if any rule actually
    // injected (modified `req`).
    bool applyToRequest(Nullock::Proxy::HttpRequest &req,
                        int tool = SessionRulesLogic::ToolProxy) const;

    // Bytes-level wrapper for tools that hold a RAW request (Repeater / Intruder):
    // parse `rawRequest`, apply the rules scoped to `tool`, and reserialize INTO
    // rawRequest ONLY if a rule fired -- so a request no rule touches goes on the
    // wire byte-for-byte (raw fidelity preserved). Returns true if it changed.
    bool applyToRequestBytes(QByteArray &rawRequest, const QString &host,
                             int tool) const;
    void applyToResponse(const Nullock::Proxy::HttpRequest &req,
                         const Nullock::Proxy::HttpResponse &resp);

    // Wipe variable bag (engagement isolation -- wired to historyShouldClear).
public slots:
    void clearAll();

signals:
    void rulesChanged();
    void variablesChanged();

private:
    bool   matches(const SessionRule &r,
                   const QString &host, const QString &path) const;
    QString substitute(const QString &templ,
                       const QHash<QString, QString> &vars) const;

    mutable QMutex                m_mutex;
    QList<SessionRule>            m_rules;
    // host -> (variable name -> value). Keyed by the HOST a value was extracted
    // from, so a secret captured from host A is never injected into a request to
    // host B (a wildcard hostGlob otherwise carries credentials cross-origin).
    QHash<QString, QHash<QString, QString>> m_varsByHost;
};

} // namespace Nullock::Core
