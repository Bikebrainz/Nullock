// Regression corpus for the XPath injection probe's pure logic (no network):
//   - matchError: engine-specific fingerprints (trusted on any status) vs the
//     low-distinctiveness "generic" family (prose that a WAF block page can also
//     carry -- the audit's FP), now split out so it can be status-gated.
//   - isBlockStatus: the block-ish statuses a generic-only match is rejected on.
//   - buildRequest: CR/LF guards on method/host/path.
//
// Run via:  ctest -R xpath_injection -V

#include "xpath_injection.hpp"

#include <QCoreApplication>
#include <QByteArray>
#include <QString>

#include <cstdio>

using namespace Nullock::Core::XpathInjection;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}
QString eng(const char *body) { return matchError(QByteArray(body)).first; }
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    // ---- matchError: engine-specific (trusted on any status) -------------
    chk("sig: Java",    eng("javax.xml.xpath.XPathExpressionException: bad") == "Java");
    // Symmetric to the bare-.NET case below: the Java case above matches via the
    // "javax.xml.xpath" package prefix, so the bare "XPathExpressionException"
    // class-name alternative (Java's distinctive form, a substring of NOTHING in
    // the .NET sig) is otherwise unexercised. Removing it drops a bare Java XPath
    // stack trace to an empty (unattributed) hit -> a real injection reads clean.
    chk("sig: bare Java XPathExpressionException (no javax prefix)",
        eng("Caused by: XPathExpressionException: unexpected token") == "Java");
    chk("sig: .NET",    eng("System.Xml.XPath.XPathException") == ".NET");
    // The bare ".NET" class name "XPathException" (Java's distinctive form is the
    // longer XPathExpressionException) must attribute to .NET on its own -- the case
    // above matches via the "System.Xml.XPath" prefix, so the bare-class alternative
    // is otherwise unexercised. Removing it drops this to an empty (unattributed) hit.
    chk("sig: bare .NET XPathException (no System.Xml prefix)",
        eng("XPathException: unexpected token ']'") == ".NET");
    chk("sig: PHP",     eng("Warning: DOMXPath::query(): Invalid expression") == "PHP");
    chk("sig: Python",  eng("lxml.etree.XPathEvalError: Invalid predicate") == "Python");
    chk("sig: libxml2", eng("xmlXPathCompOpEval: parameter error") == "libxml2");
    // ---- matchError: GENERIC (status-gated) -- the WAF-block-prone phrasings -
    chk("sig: generic Error...XPath", eng("Error: XPath injection blocked by WAF") == "generic");
    chk("sig: generic Invalid expression token", eng("Parse error: Invalid expression token near ']'") == "generic");
    chk("sig: generic Invalid predicate", eng("Invalid predicate") == "generic");
    chk("sig: generic node-set", eng("Expression must evaluate to a node-set") == "generic");
    // Untested alternatives of each engine's alternation (a dropped branch would
    // silently stop attributing that library's error).
    chk("sig: Java saxon",      eng("net.sf.saxon.trans.XPathException: bad") == "Java");
    chk("sig: Java xalan",      eng("org.apache.xpath.XPathException at eval") == "Java");
    chk("sig: PHP evaluate",    eng("Warning: DOMXPath::evaluate(): Invalid expression") == "PHP");
    chk("sig: PHP SimpleXML",   eng("Warning: SimpleXMLElement::xpath(): Invalid") == "PHP");
    chk("sig: PHP xpath_eval",  eng("xpath_eval(): compilation failure") == "PHP");
    chk("sig: libxml2 unregistered function", eng("XPath error : Unregistered function") == "libxml2");
    chk("sig: libxml2 unregistered variable", eng("XPath error : Unregistered variable") == "libxml2");
    chk("sig: generic Warning...XPath", eng("Warning: XPath compilation blocked") == "generic");
    chk("sig: unrelated -> none", eng("<html>0 nodes</html>").isEmpty());

    // ---- isBlockStatus ---------------------------------------------------
    chk("block: 403", isBlockStatus(403));
    chk("block: 406", isBlockStatus(406));
    chk("block: 429", isBlockStatus(429));
    chk("block: 451", isBlockStatus(451));
    chk("block: 501", isBlockStatus(501));
    chk("block: 503", isBlockStatus(503));
    chk("block: 200 not", !isBlockStatus(200));
    chk("block: 500 not (real backend error)", !isBlockStatus(500));

    // ---- buildRequest: CR/LF guards -------------------------------------
    {
        Request req;
        req.host = "victim.tld"; req.method = "GET"; req.basePath = "/lookup";
        const QByteArray ok = buildRequest(req, "q=x");
        chk("build: request line", ok.startsWith("GET /lookup?q=x HTTP/1.1\r\n"));
        chk("build: Host", ok.contains("Host: victim.tld\r\n"));

        Request injHdr = req;
        injHdr.headers.append(qMakePair(QString("X-Foo"), QString("a\r\nX-Smuggled: 1")));
        chk("build: drops CRLF carried header", !buildRequest(injHdr, "q=x").contains("X-Smuggled"));

        // A carried Accept-Encoding must be dropped so the forced "identity" stands
        // alone -- else the server gzips and matchError scans compressed bytes,
        // missing every XPath engine-error signature (a real injection reads clean).
        // This drop was MISSING here though the ldap/xxe siblings have it.
        Request ae = req;
        ae.headers.append(qMakePair(QString("Accept-Encoding"), QString("gzip, deflate, br")));
        const QByteArray aeb = buildRequest(ae, "q=x");
        chk("build: carried Accept-Encoding dropped -> exactly one, identity",
            aeb.count("Accept-Encoding:") == 1
            && aeb.contains("Accept-Encoding: identity\r\n") && !aeb.contains("gzip"));

        Request badMethod = req; badMethod.method = "GET\r\nX: y";
        chk("build: CRLF method -> empty", buildRequest(badMethod, "q=x").isEmpty());
        Request badHost = req; badHost.host = "victim.tld\r\nX: y";
        chk("build: CRLF host -> empty", buildRequest(badHost, "q=x").isEmpty());
        Request badPath = req; badPath.basePath = "/lookup\r\nX: y";
        chk("build: CRLF path -> empty", buildRequest(badPath, "q=x").isEmpty());
        // audit-5: the query is spliced into the request line -> guard it too.
        chk("build: CRLF query -> empty", buildRequest(req, "q=x\r\nEvil: 1").isEmpty());
    }

    std::fprintf(stderr, "xpath_injection_test: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
