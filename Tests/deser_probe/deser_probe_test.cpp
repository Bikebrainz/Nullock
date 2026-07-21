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
    }

    std::fprintf(stderr, "deser_probe_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
