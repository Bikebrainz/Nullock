// Regression corpus for the insecure-deserialization probe's pure logic (no
// network):
//   - matchError: deserialization-SPECIFIC signatures (positives per engine;
//     bare API names / generic 500 / ClassNotFoundException must NOT match).
//   - defaultParams / knownFieldNames / knownCookieNames: framework carriers
//     lead so they survive the auto-detect param cap.
//   - the four builders: CR/LF guards on method / host / path / carried headers.
//   - queryWith: param replace + preserve.
//
// Run via:  ctest -R deser_probe -V

#include "deser_probe.hpp"

#include <QByteArray>
#include <QCoreApplication>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::DeserProbe;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
bool matches(const char *body, const char *engine) {
    const auto m = matchError(QByteArray(body));
    return m.first == QString::fromLatin1(engine);
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- matchError: engine-specific positives --------------------------
    chk("sig: Java StreamCorrupted", matches("x java.io.StreamCorruptedException: bad", "Java"));
    chk("sig: Java invalid stream header", matches("invalid stream header: 0xAC", "Java"));
    chk("sig: PHP offset", matches("unserialize(): Error at offset 0 of 11 bytes", "PHP"));
    chk("sig: Python UnpicklingError", matches("_pickle.UnpicklingError: truncated", "Python"));
    chk("sig: Ruby marshal too short", matches("ArgumentError: marshal data too short", "Ruby"));
    chk("sig: .NET SerializationException",
        matches("System.Runtime.Serialization.SerializationException: End of Stream encountered", ".NET"));
    // Each signature is an alternation; pin the branches that had no positive so a
    // regex edit dropping one silently stops detecting that engine's error.
    chk("sig: Java OptionalDataException", matches("java.io.OptionalDataException", "Java"));
    chk("sig: Java InvalidClassException", matches("java.io.InvalidClassException: bad", "Java"));
    chk("sig: Java WriteAbortedException", matches("java.io.WriteAbortedException", "Java"));
    chk("sig: Java EOFException",          matches("java.io.EOFException at read", "Java"));
    chk("sig: Java cast-to-Serializable",  matches("class X cannot be cast to java.io.Serializable", "Java"));
    chk("sig: PHP __PHP_Incomplete_Class", matches("object(__PHP_Incomplete_Class)#1", "PHP"));
    chk("sig: PHP Premature end of data",  matches("Notice: unserialize(): Premature end of data", "PHP"));
    chk("sig: Python data truncated",      matches("pickle data was truncated", "Python"));
    chk("sig: Python stack underflow",     matches("unpickling stack underflow", "Python"));
    chk("sig: Python insecure string",     matches("insecure string pickle", "Python"));
    chk("sig: Ruby incompatible format",   matches("incompatible marshal file format", "Ruby"));
    chk("sig: Ruby dump format error",     matches("dump format error (user class)", "Ruby"));
    chk("sig: .NET invalid BinaryHeader",  matches("The input stream does not contain a valid BinaryHeader", ".NET"));
    chk("sig: .NET not a valid binary format", matches("input stream is not a valid binary format", ".NET"));

    // ---- matchError: must NOT match generic / bare-API noise ------------
    chk("sig: bare unserialize() not matched", matchError(QByteArray("call to unserialize() failed")).first.isEmpty());
    chk("sig: ClassNotFoundException not matched (JNDI/startup noise)",
        matchError(QByteArray("java.lang.ClassNotFoundException: com.x.Y")).first.isEmpty());
    chk("sig: generic 500 not matched", matchError(QByteArray("<html>500 Internal Server Error</html>")).first.isEmpty());
    chk("sig: empty body not matched", matchError(QByteArray("")).first.isEmpty());

    // ---- carrier ordering: framework names survive the cap (FN fix) -----
    {
        const QStringList dp = defaultParams();
        const QStringList top10 = dp.mid(0, 10);
        chk("params: __VIEWSTATE in first 10", top10.contains("__VIEWSTATE"));
        chk("params: javax.faces.ViewState in first 10", top10.contains("javax.faces.ViewState"));
        chk("params: rememberMe in first 10", top10.contains("rememberMe"));
        chk("params: __EVENTVALIDATION in first 10", top10.contains("__EVENTVALIDATION"));
        chk("fields: __VIEWSTATE leads", knownFieldNames().value(0) == "__VIEWSTATE");
        chk("cookies: rememberMe leads", knownCookieNames().value(0) == "rememberMe");
    }

    // ---- queryWith ------------------------------------------------------
    {
        const QString q = queryWith("a=1&data=old", "data", "NEW");
        chk("queryWith: replaces target param", q.contains("data=NEW") && !q.contains("data=old"));
        chk("queryWith: preserves others", q.contains("a=1"));
        chk("queryWith: adds when absent", queryWith("a=1", "data", "X").contains("data=X"));
    }

    // ---- builders: CR/LF guards (incl host -- the parity fix) -----------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET"; req.basePath = "/svc";
        chk("buildRequest: ok", buildRequest(req, "data=x").startsWith("GET /svc?data=x HTTP/1.1\r\n"));
        chk("buildRequest: Host", buildRequest(req, "data=x").contains("Host: victim.tld\r\n"));

        // audit-12: every deser builder forces "Accept-Encoding: identity" and
        // "Connection: close", and the body builders emit their OWN Content-Length --
        // so a carried Transfer-Encoding would ride ALONGSIDE it (a CL.TE ambiguous
        // request the scanner sends itself), a carried Content-Length would advertise a
        // phantom body on the GET builders, and a carried Accept-Encoding/Connection
        // would defeat the forced identity/close.
        {
            Request c = req;
            c.headers.append(qMakePair(QString("Content-Length"),    QString("100")));
            c.headers.append(qMakePair(QString("Transfer-Encoding"), QString("chunked")));
            c.headers.append(qMakePair(QString("Accept-Encoding"),   QString("gzip, deflate, br")));
            c.headers.append(qMakePair(QString("Connection"),        QString("keep-alive")));
            const QByteArray g  = buildRequest(c, "data=x");
            const QByteArray b  = buildBodyRequest(c, QByteArray("payload"), "application/octet-stream");
            const QByteArray ck = buildCookieRequest(c, "rememberMe", "v");
            const QByteArray fl = buildFieldRequest(c, "__VIEWSTATE", "v");
            for (const auto &pair : { qMakePair(QByteArray("buildRequest"), g),
                                      qMakePair(QByteArray("buildCookieRequest"), ck) }) {
                chk((pair.first + ": carried Content-Length dropped (body-less)").constData(),
                    !pair.second.contains("Content-Length"));
                chk((pair.first + ": carried Transfer-Encoding dropped").constData(),
                    !pair.second.contains("Transfer-Encoding"));
            }
            // The body builders keep their OWN Content-Length but must drop a carried TE.
            chk("buildBodyRequest: carried Transfer-Encoding dropped (no CL.TE)",
                !b.contains("Transfer-Encoding") && b.contains("Content-Length: 7\r\n"));
            chk("buildFieldRequest: carried Transfer-Encoding dropped (no CL.TE)",
                !fl.contains("Transfer-Encoding"));
            for (const auto &pair : { qMakePair(QByteArray("buildRequest"), g),
                                      qMakePair(QByteArray("buildBodyRequest"), b),
                                      qMakePair(QByteArray("buildCookieRequest"), ck),
                                      qMakePair(QByteArray("buildFieldRequest"), fl) }) {
                chk((pair.first + ": carried Accept-Encoding dropped -> one, identity").constData(),
                    pair.second.count("Accept-Encoding:") == 1
                    && pair.second.contains("Accept-Encoding: identity\r\n")
                    && !pair.second.contains("gzip"));
                chk((pair.first + ": carried Connection dropped -> one, close").constData(),
                    pair.second.count("Connection:") == 1
                    && pair.second.contains("Connection: close\r\n")
                    && !pair.second.contains("keep-alive"));
            }
            // The drops are not over-broad: a clean carried header still rides.
            Request clean = req;
            clean.headers.append(qMakePair(QString("X-Trace"), QString("ok")));
            chk("buildRequest: a clean carried header IS emitted",
                buildRequest(clean, "data=x").contains("X-Trace: ok\r\n"));
        }

        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("buildRequest: CRLF host -> empty", buildRequest(badHost, "data=x").isEmpty());
        chk("buildBody: CRLF host -> empty", buildBodyRequest(badHost, QByteArray("b"), "application/octet-stream").isEmpty());
        chk("buildCookie: CRLF host -> empty", buildCookieRequest(badHost, "rememberMe", "v").isEmpty());
        chk("buildField: CRLF host -> empty", buildFieldRequest(badHost, "__VIEWSTATE", "v").isEmpty());

        Request badPath = req; badPath.basePath = "/svc\r\nX: y";
        chk("buildRequest: CRLF path -> empty", buildRequest(badPath, "data=x").isEmpty());

        // Query CR/LF guard: buildRequest takes the query as a PARAM; the other
        // three splice req.query into the request-line target. A CR/LF in the
        // query would inject a header / split the request, so ALL must refuse it.
        chk("buildRequest: CRLF query param -> empty", buildRequest(req, "data=x\r\nX-Smuggled: 1").isEmpty());
        Request crlfQ = req; crlfQ.query = "a=1\r\nX-Smuggled: 1";
        chk("buildBody: CRLF req.query -> empty",
            buildBodyRequest(crlfQ, QByteArray("b"), "application/octet-stream").isEmpty());
        // audit-3: buildBody splices the ct arg into the Content-Type header -> guard it.
        chk("buildBody: CRLF ct -> empty",
            buildBodyRequest(req, QByteArray("b"), "application/xml\r\nX-Smuggled: 1").isEmpty());
        chk("buildCookie: CRLF req.query -> empty", buildCookieRequest(crlfQ, "rememberMe", "v").isEmpty());
        chk("buildField: CRLF req.query -> empty", buildFieldRequest(crlfQ, "__VIEWSTATE", "v").isEmpty());

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("Cookie"), QString("a=1\r\nX-Smuggled: 1")));
        chk("buildRequest: drops CRLF carried header",
            !buildRequest(injHdr, "data=x").contains("X-Smuggled"));

        // body builder defaults GET -> POST and frames Content-Type/Length+body
        const QByteArray b = buildBodyRequest(req, QByteArray("\xac\xed\x00\x05", 4), "application/x-java-serialized-object");
        chk("buildBody: GET promoted to POST", b.startsWith("POST /svc HTTP/1.1\r\n"));
        chk("buildBody: Content-Type", b.contains("Content-Type: application/x-java-serialized-object\r\n"));
        // cookie builder strips ; CR LF from the value
        const QByteArray c = buildCookieRequest(req, "rememberMe", "abc;def");
        chk("buildCookie: strips semicolon from value", c.contains("Cookie: rememberMe=abcdef\r\n"));
        // CR/LF in the cookie VALUE must be stripped (the hand-rolled remove('\r')/
        // remove('\n') is its ONLY header-injection defense -- the value is neither
        // crlf()-guarded nor percent-encoded). Only the ';' case was tested. Exact-
        // line assertion (a mere !contains("X-Injected: 1\r\n") is non-discriminating,
        // since the stripped value legitimately renders "...vX-Injected: 1\r\n").
        const QByteArray cc = buildCookieRequest(req, "rememberMe", "v\r\nX-Injected: 1");
        chk("buildCookie: strips CR/LF from the value (one Cookie line, no header split)",
            cc.contains("Cookie: rememberMe=vX-Injected: 1\r\n")
            && !cc.contains("Cookie: rememberMe=v\r\n"));
        // kindForFormat: engine-label -> finding-kind, incl. the fragile label!=kind
        // rows (Python->deser-pickle, .NET->deser-dotnet); never called by a test.
        chk("kindForFormat: Java/PHP/Ruby direct", kindForFormat("Java") == "deser-java"
            && kindForFormat("PHP") == "deser-php" && kindForFormat("Ruby") == "deser-ruby");
        chk("kindForFormat: Python -> deser-pickle (label != kind)", kindForFormat("Python") == "deser-pickle");
        chk("kindForFormat: .NET -> deser-dotnet (label != kind)", kindForFormat(".NET") == "deser-dotnet");
        chk("kindForFormat: unknown -> deser-unknown (default)", kindForFormat("nonsense") == "deser-unknown");
    }

    std::fprintf(stderr, "deser_probe_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
