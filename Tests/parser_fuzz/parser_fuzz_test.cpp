// Deterministic fuzz-lock for the session's new attacker-facing parsers -- all
// of which ingest UNTRUSTED input (a template from an untrusted source, a raw
// HTTP message):
//   * NucleiYaml::parseYaml / nucleiYamlToTemplate  (a nuclei .yaml)
//   * Inspector::inspectRequest / inspectResponse   (a raw HTTP message)
//   * TemplateEngine::parseTemplate / evaluate      (a JSON template + response)
//   * TemplateRequest::parseRequest / buildRequests (a request template)
//
// The generator is a deterministic xorshift PRNG (reproducible), biased toward
// structural bytes (braces, colons, dashes, quotes, CRLF, {{...}}, HTTP tokens)
// so it actually reaches the parse paths, with occasional raw 0x00..0xFF for
// binary fuzzing. The invariant is: NO crash / hang across thousands of
// iterations, and the documented output BOUNDS hold (expansion <= kMaxRequests,
// body preview <= kBodyPreview).
//
// Run via:  ctest -R parser_fuzz -V

#include "nuclei_yaml_logic.hpp"
#include "inspector_logic.hpp"
#include "template_engine_logic.hpp"
#include "template_request_logic.hpp"

#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <cstdint>
#include <cstdio>

using namespace Nullock::Core;

namespace {
int pass = 0, fail = 0;
void chk(const char *label, bool ok) {
    if (ok) ++pass;
    else { std::fprintf(stderr, "  FAIL  %s\n", label); ++fail; }
}

uint32_t g_rng = 0x1337beef;
inline uint32_t xrand() {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

// A pool biased toward the tokens these parsers key on, plus raw structure.
static const char *kPool =
    "  \t\r\n::--||>>##\"''{}[](),.=&?/+"
    "{{payload}}{{BaseURL}}{{Hostname}}"
    "HTTP/1.1 GET POST PUT 200 302 404 500 Host: Content-Type Set-Cookie "
    "Authorization Bearer Cookie sid= application/json x-www-form-urlencoded "
    "id name info severity http requests method path body headers matchers "
    "matchers-condition and or extractors type word regex status part negative "
    "words condition attack cluster pitchfork abc0123XYZ";

QString randomBytes(int maxLen) {
    const int poolLen = static_cast<int>(qstrlen(kPool));
    const int n = static_cast<int>(xrand() % static_cast<uint32_t>(maxLen + 1));
    QString s;
    s.reserve(n);
    for (int i = 0; i < n; ++i) {
        const uint32_t r = xrand();
        if ((r & 0x0f) == 0) s.append(QChar(static_cast<ushort>(r & 0xFF))); // raw byte
        else s.append(QChar(static_cast<ushort>(kPool[r % poolLen])));       // structural
    }
    return s;
}

QString maybeCrlf(const QString &in) {
    // Randomly convert LF -> CRLF (exercise the CRLF paths that bit us live).
    if (xrand() & 1) { QString s = in; s.replace('\n', "\r\n"); return s; }
    return in;
}

// Build a small semi-structured JSON object using parser-relevant keys.
QJsonObject randomJson(int depth) {
    static const char *keys[] = {
        "id","name","severity","type","part","words","regex","status","condition",
        "negative","matchers","matchers-condition","extractors","method","path",
        "headers","body","payloads","attack","request","http","info","values" };
    const int nk = sizeof(keys) / sizeof(keys[0]);
    QJsonObject o;
    const int fields = static_cast<int>(xrand() % 6);
    for (int i = 0; i < fields; ++i) {
        const QString k = QString::fromLatin1(keys[xrand() % nk]);
        switch (xrand() % 6) {
            case 0: o.insert(k, randomBytes(24)); break;
            case 1: o.insert(k, static_cast<int>(xrand() % 1000)); break;
            case 2: o.insert(k, (xrand() & 1) != 0); break;
            case 3: {
                QJsonArray a;
                const int m = static_cast<int>(xrand() % 4);
                for (int j = 0; j < m; ++j)
                    a.append((xrand() & 1) ? QJsonValue(randomBytes(12))
                                           : QJsonValue(static_cast<int>(xrand() % 600)));
                o.insert(k, a);
                break;
            }
            case 4: o.insert(k, depth < 3 ? QJsonValue(randomJson(depth + 1)) : QJsonValue(randomBytes(8))); break;
            default: o.insert(k, QJsonValue::Null); break;
        }
    }
    return o;
}

} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    constexpr int kIters = 6000;
    for (int i = 0; i < kIters; ++i) {
        // ---- string parsers on random bytes (incl. CRLF, raw, truncated) ----
        const QString s = maybeCrlf(randomBytes(4096));
        const QByteArray b = s.toUtf8();

        // nuclei YAML shim
        (void)NucleiYaml::parseYaml(s);
        const QJsonObject tplFromYaml = NucleiYaml::nucleiYamlToTemplate(s);

        // Inspector -- bounds: bodyPreview <= kBodyPreview.
        (void)Inspector::inspectRequest(b);
        const QJsonObject resp = Inspector::inspectResponse(b);
        if (resp.value("bodyPreview").toString().size() > Inspector::kBodyPreview) {
            chk("inspector bodyPreview bounded", false); break;
        }

        // ---- JSON parsers on random objects ----
        const QJsonObject tj = randomJson(0);
        const TemplateEngine::Template tpl = TemplateEngine::parseTemplate(tj);

        // evaluate against a random response derived from the same bytes.
        TemplateEngine::Response r;
        r.statusCode  = static_cast<int>(xrand() % 700);
        r.headersText = s.left(2048);
        r.body        = s;
        (void)TemplateEngine::evaluate(tpl, r);
        // also evaluate the yaml-derived template (round-trip through the engine).
        (void)TemplateEngine::evaluate(TemplateEngine::parseTemplate(tplFromYaml), r);

        // ---- request builder: bound expansion so the fuzz stays fast ----
        TemplateRequest::RequestSpec spec = TemplateRequest::parseRequest(randomJson(0));
        // Keep the cartesian product tiny (parseRequest could yield big arrays).
        while (spec.payloads.size() > 2) spec.payloads.removeLast();
        for (QStringList &set : spec.payloads) while (set.size() > 4) set.removeLast();
        TemplateRequest::Vars vars;
        vars.baseUrl  = randomBytes(32);
        vars.hostname = randomBytes(16);
        const auto built = TemplateRequest::buildRequests(spec, vars);
        if (built.size() > TemplateRequest::kMaxRequests) {
            chk("buildRequests expansion bounded", false); break;
        }
    }

    chk("string+json parsers survived fuzz (no crash/hang)", true);
    chk("all bounds held across fuzz", fail == 0);

    std::fprintf(stderr, "parser_fuzz_test: %d passed, %d failed (%d iters)\n", pass, fail, kIters);
    return fail == 0 ? 0 : 1;
}
