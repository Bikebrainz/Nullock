#include "deser_probe.hpp"
#include "networking.hpp"

#include <QSet>
#include <QUrlQuery>

namespace Nullock::Core::DeserProbe {

namespace {
constexpr int kMaxSends  = 120;   // headroom for the per-hit well-formed re-confirm
constexpr int kMaxParams = 10;    // auto-detect query param cap
} // namespace

// (Pure helpers -- matchError, signatures, the four builders, queryWith,
// knownCookieNames, knownFieldNames, defaultParams, kindForFormat -- live in
// deser_logic.cpp so the regression test can exercise them without the network.)

Result test(const Request &reqIn) {
    Result result;
    if (reqIn.host.isEmpty()) { result.error = "host required"; return result; }
    Request req = reqIn;
    if (req.basePath.isEmpty()) req.basePath = QStringLiteral("/");

    // Raw-body injection: send each format's well-formed/malformed serialized
    // object as the REQUEST BODY (the application/x-java-serialized-object class
    // of sink). Same well-formed-vs-malformed differential as the query path.
    if (req.location.compare("body", Qt::CaseInsensitive) == 0) {
        HttpClient bclient;
        const quint16 bport = static_cast<quint16>(req.port);
        struct BodyProbe { const char *format; const char *wf; const char *mf;
                           const char *ct; bool b64; };
        static const QList<BodyProbe> bprobes = {
            { "Java",   "rO0ABXQAA2FiYw==", "rO0ABXNyABFOdWxsb2NrRGVzZXJDYW5hcnk=",
              "application/x-java-serialized-object", true },
            { "PHP",    "O:8:\"stdClass\":1:{s:1:\"a\";i:1;}",
              "O:18:\"NullockDeserCanary\":9:{s:1:\"x\";i:1;}",
              "application/x-www-form-urlencoded", false },
            { "Python", "gAJLAS4=", "gASVBQAAAAAAAACMAQ", "application/python-pickle", true },
            { "Ruby",   "BAhpBg==", "BAhbBg==", "application/octet-stream", true },
            // .NET BinaryFormatter: wf = a valid serialized String "abc"
            // (00 01 ... magic + BinaryObjectString + MessageEnd); mf = that
            // stream truncated mid-record so a .NET deserializer errors with a
            // SerializationException / "End of Stream encountered". Without this
            // entry deser-dotnet was structurally unreachable (never probed).
            { ".NET",   "AAEAAAD/////AQAAAAAAAAAGAQAAAANhYmML",
              "AAEAAAD/////AQAAAAAAAAAG", "application/octet-stream", true },
        };
        result.testedParams = QStringList{ QStringLiteral("(request body)") };
        auto raw = [](const char *s, bool b64) {
            return b64 ? QByteArray::fromBase64(QByteArray(s)) : QByteArray(s);
        };
        auto sendBody = [&](const QByteArray &b, const QString &ct) {
            ++result.requestsSent;
            return bclient.send(req.host, bport, req.tls, buildBodyRequest(req, b, ct));
        };
        for (const BodyProbe &p : bprobes) {
            if (result.requestsSent >= kMaxSends) break;
            const QString ct = req.contentType.isEmpty()
                ? QString::fromUtf8(p.ct) : req.contentType;
            const auto wf = sendBody(raw(p.wf, p.b64), ct);
            const bool wfOk = wf.ok;
            if (wfOk) result.baselineStatus = wf.parsed.statusCode;
            const bool wfErr = wfOk && !matchError(wf.parsed.body).first.isEmpty();
            if (!wfOk || wfErr) continue;   // shape-WAF / strict / not a deser
            const auto mf = sendBody(raw(p.mf, p.b64), ct);
            const bool mfOk = mf.ok;
            const auto err = mfOk ? matchError(mf.parsed.body) : QPair<QString, QString>{};
            const bool mfErr = !err.first.isEmpty();
            if (!mfOk || !mfErr) continue;
            // Re-confirm the well-formed control is STILL clean -- a server that
            // flapped into an error state between the two shots would otherwise
            // false-positive a critical finding.
            const auto wf2 = sendBody(raw(p.wf, p.b64), ct);
            const bool wf2Ok = wf2.ok;
            const bool wf2Err = wf2Ok && !matchError(wf2.parsed.body).first.isEmpty();
            if (!confirmsDeser(wfOk, wfErr, mfOk, mfErr, wf2Ok, wf2Err)) continue;
            result.hits.append({ QStringLiteral("(body)"), err.first,
                                 QString::fromUtf8(p.mf), err.second });
            result.vulnerable = true;
            break;
        }
        return result;
    }

    // Cookie injection: serialized blobs classically ride in auth/session
    // cookies (Shiro/Spring rememberMe, Ruby Marshal _session). Inject each
    // binary format's base64 well-formed/malformed object into a candidate
    // cookie; same differential. (PHP's text form doesn't fit a cookie value.)
    if (req.location.compare("cookie", Qt::CaseInsensitive) == 0) {
        HttpClient cclient;
        const quint16 cport = static_cast<quint16>(req.port);
        struct Ck { const char *format; const char *wf; const char *mf; };
        static const QList<Ck> cprobes = {
            { "Java",   "rO0ABXQAA2FiYw==", "rO0ABXNyABFOdWxsb2NrRGVzZXJDYW5hcnk=" },
            { "Python", "gAJLAS4=", "gASVBQAAAAAAAACMAQ" },
            { "Ruby",   "BAhpBg==", "BAhbBg==" },
            { ".NET",   "AAEAAAD/////AQAAAAAAAAAGAQAAAANhYmML", "AAEAAAD/////AQAAAAAAAAAG" },
        };
        QStringList cookies;
        if (!req.param.isEmpty()) cookies << req.param;
        else cookies = knownCookieNames();
        if (cookies.size() > 8) { result.droppedParams = cookies.mid(8); cookies = cookies.mid(0, 8); }
        result.testedParams = cookies;
        auto sendCookie = [&](const QString &name, const QString &val) {
            ++result.requestsSent;
            return cclient.send(req.host, cport, req.tls, buildCookieRequest(req, name, val));
        };
        for (const QString &ck : cookies) {
            if (result.requestsSent >= kMaxSends) break;
            for (const Ck &p : cprobes) {
                if (result.requestsSent >= kMaxSends) break;
                const auto wf = sendCookie(ck, QString::fromUtf8(p.wf));
                const bool wfOk = wf.ok;
                if (wfOk) result.baselineStatus = wf.parsed.statusCode;
                const bool wfErr = wfOk && !matchError(wf.parsed.body).first.isEmpty();
                if (!wfOk || wfErr) continue;  // shape-WAF / not a deser
                const auto mf = sendCookie(ck, QString::fromUtf8(p.mf));
                const bool mfOk = mf.ok;
                const auto err = mfOk ? matchError(mf.parsed.body) : QPair<QString, QString>{};
                const bool mfErr = !err.first.isEmpty();
                if (!mfOk || !mfErr) continue;
                const auto wf2 = sendCookie(ck, QString::fromUtf8(p.wf));   // re-confirm clean control
                const bool wf2Ok = wf2.ok;
                const bool wf2Err = wf2Ok && !matchError(wf2.parsed.body).first.isEmpty();
                if (!confirmsDeser(wfOk, wfErr, mfOk, mfErr, wf2Ok, wf2Err)) continue;
                result.hits.append({ "cookie:" + ck, err.first,
                                     QString::fromUtf8(p.mf), err.second });
                result.vulnerable = true;
                return result;     // one confirmed cookie sink is enough
            }
        }
        return result;
    }

    // Named form-field injection: a serialized blob set as one POST body field
    // (.NET __VIEWSTATE, unserialize($_POST[...])). Same differential; all four
    // formats fit a url-encoded field value.
    if (req.location.compare("field", Qt::CaseInsensitive) == 0) {
        HttpClient fclient;
        const quint16 fport = static_cast<quint16>(req.port);
        struct Fp { const char *format; const char *wf; const char *mf; };
        static const QList<Fp> fprobes = {
            { "Java", "rO0ABXQAA2FiYw==", "rO0ABXNyABFOdWxsb2NrRGVzZXJDYW5hcnk=" },
            { "PHP",  "O:8:\"stdClass\":1:{s:1:\"a\";i:1;}",
              "O:18:\"NullockDeserCanary\":9:{s:1:\"x\";i:1;}" },
            { "Python", "gAJLAS4=", "gASVBQAAAAAAAACMAQ" },
            { "Ruby", "BAhpBg==", "BAhbBg==" },
            { ".NET", "AAEAAAD/////AQAAAAAAAAAGAQAAAANhYmML", "AAEAAAD/////AQAAAAAAAAAG" },
        };
        QStringList fields;
        if (!req.param.isEmpty()) fields << req.param;
        else fields = knownFieldNames();
        if (fields.size() > 8) { result.droppedParams = fields.mid(8); fields = fields.mid(0, 8); }
        result.testedParams = fields;
        auto sendField = [&](const QString &f, const QString &v) {
            ++result.requestsSent;
            return fclient.send(req.host, fport, req.tls, buildFieldRequest(req, f, v));
        };
        for (const QString &f : fields) {
            if (result.requestsSent >= kMaxSends) break;
            for (const Fp &p : fprobes) {
                if (result.requestsSent >= kMaxSends) break;
                const auto wf = sendField(f, QString::fromUtf8(p.wf));
                const bool wfOk = wf.ok;
                if (wfOk) result.baselineStatus = wf.parsed.statusCode;
                const bool wfErr = wfOk && !matchError(wf.parsed.body).first.isEmpty();
                if (!wfOk || wfErr) continue;  // shape-WAF / not a deser
                const auto mf = sendField(f, QString::fromUtf8(p.mf));
                const bool mfOk = mf.ok;
                const auto err = mfOk ? matchError(mf.parsed.body) : QPair<QString, QString>{};
                const bool mfErr = !err.first.isEmpty();
                if (!mfOk || !mfErr) continue;
                const auto wf2 = sendField(f, QString::fromUtf8(p.wf));   // re-confirm clean control
                const bool wf2Ok = wf2.ok;
                const bool wf2Err = wf2Ok && !matchError(wf2.parsed.body).first.isEmpty();
                if (!confirmsDeser(wfOk, wfErr, mfOk, mfErr, wf2Ok, wf2Err)) continue;
                result.hits.append({ "field:" + f, err.first,
                                     QString::fromUtf8(p.mf), err.second });
                result.vulnerable = true;
                return result;     // one confirmed field sink is enough
            }
        }
        return result;
    }

    // Build the param set: the named param, else the query keys MERGED with the
    // curated carriers (so a URL that already has one query param doesn't shut
    // out the known names), prioritizing query keys, then capped.
    QStringList params;
    if (!req.param.isEmpty()) {
        params << req.param;
    } else {
        const QUrlQuery q(req.query);
        for (const auto &kv : q.queryItems())
            if (!params.contains(kv.first)) params << kv.first;
        for (const QString &d : defaultParams())
            if (!params.contains(d)) params << d;
    }
    if (params.size() > kMaxParams) {
        result.droppedParams = params.mid(kMaxParams);
        params = params.mid(0, kMaxParams);
    }
    result.testedParams = params;

    HttpClient client;
    const quint16 port = static_cast<quint16>(req.port);
    auto send = [&](const QString &query) {
        ++result.requestsSent;
        return client.send(req.host, port, req.tls, buildRequest(req, query));
    };

    const auto base = send(req.query);
    if (!base.ok) { result.error = "baseline failed: " + base.errorMessage; return result; }
    result.baselineStatus = base.parsed.statusCode;

    // Sound discriminator: a real deserializer ACCEPTS a well-formed benign
    // serialized object (deserializes it -> no parse error) but ERRORS on a
    // malformed one. A shape-keyed WAF/blocklist errors on BOTH (it never
    // deserializes -- it sniffs the magic), so the well-formed control errors
    // too and we don't flag. An echo/store sink errors on NEITHER. The
    // well-formed object is inert (a String / the integer 1); the malformed one
    // references only a non-existent canary class and fails before any gadget.
    struct Probe { const char *format; const char *wellFormed; const char *malformed; };
    static const QList<Probe> probes = {
        { "Java",   "rO0ABXQAA2FiYw==",
                    "rO0ABXNyABFOdWxsb2NrRGVzZXJDYW5hcnk=" },        // magic + obj header, truncated
        { "PHP",    "O:8:\"stdClass\":1:{s:1:\"a\";i:1;}",           // benign stdClass (no magic methods)
                    "O:18:\"NullockDeserCanary\":9:{s:1:\"x\";i:1;}" }, // declared 9 props, 1 given
        { "Python", "gAJLAS4=",
                    "gASVBQAAAAAAAACMAQ" },                          // truncated pickle
        { "Ruby",   "BAhpBg==",
                    "BAhbBg==" },                                    // Marshal array len 1, no elements -> EOF before any class
        { ".NET",   "AAEAAAD/////AQAAAAAAAAAGAQAAAANhYmML",          // valid serialized String "abc"
                    "AAEAAAD/////AQAAAAAAAAAG" },                    // magic + truncated record -> End of Stream
    };

    QSet<QString> confirmedParams;
    for (const QString &param : params) {
        if (result.requestsSent >= kMaxSends) break;
        if (confirmedParams.contains(param)) continue;
        for (const Probe &p : probes) {
            if (result.requestsSent >= kMaxSends) break;
            // 1) Well-formed control: a real deserializer accepts it cleanly.
            //    If even valid serialized data errors, the sink isn't a plain
            //    deserializer (shape-WAF / strict type / not deserializing) --
            //    can't soundly attribute a malformed error to deserialization.
            const auto wf = send(queryWith(req.query, param, QString::fromUtf8(p.wellFormed)));
            const bool wfOk = wf.ok;
            const bool wfErr = wfOk && !matchError(wf.parsed.body).first.isEmpty();
            if (!wfOk || wfErr) continue;   // short-circuit: don't send malformed
            // 2) Malformed of the same format: a real deserializer errors.
            const auto mf = send(queryWith(req.query, param, QString::fromUtf8(p.malformed)));
            const bool mfOk = mf.ok;
            const auto err = mfOk ? matchError(mf.parsed.body) : QPair<QString, QString>{};
            const bool mfErr = !err.first.isEmpty();
            if (!mfOk || !mfErr) continue;  // short-circuit: don't re-confirm
            // 3) Re-confirm the well-formed control is STILL clean: a server that
            //    flapped into a transient error state (load, rate limit) between
            //    shots would otherwise false-positive a critical finding.
            const auto wf2 = send(queryWith(req.query, param, QString::fromUtf8(p.wellFormed)));
            const bool wf2Ok = wf2.ok;
            const bool wf2Err = wf2Ok && !matchError(wf2.parsed.body).first.isEmpty();
            if (!confirmsDeser(wfOk, wfErr, mfOk, mfErr, wf2Ok, wf2Err)) continue;
            result.hits.append({ param, err.first,
                                 QString::fromUtf8(p.malformed), err.second });
            result.vulnerable = true;
            confirmedParams.insert(param);
            break;
        }
    }

    return result;
}

} // namespace Nullock::Core::DeserProbe
