#pragma once

// Template / signature match engine (nuclei-style) -- the "above Burp AND
// beyond" primitive: user-authored detection templates with matchers +
// extractors, evaluated against an HTTP response. Burp has no native
// template-driven scanning; this is the core of it.
//
// PURE: a template + a response's parts in, a match verdict + extracted values
// out. No I/O -- links against Qt6::Core alone. (Fetching the response and
// feeding it in is the caller's job.)
//
// SAFETY (same lessons as the grep/ReDoS work): every user regex is validity-
// checked (an invalid pattern is a safe no-match, never a throw), and the
// response text scanned is capped at kMaxScan so a huge body can't stall the
// evaluator. Parsing is DEFAULT-SAFE: a malformed template yields an empty
// template that matches nothing, never a crash.

#include <QJsonObject>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>

namespace Nullock::Core::TemplateEngine {

// Cap on the response text any single matcher/extractor scans.
constexpr int kMaxScan = 512 * 1024;

// One matcher. `type` is status | word | regex. For word/regex, `part` selects
// which response text to scan (body | header | all); `values` are the words or
// patterns; `condition` (and | or, default or) combines them. `negative`
// inverts the matcher's result. For status, `values` are HTTP status codes.
struct Matcher {
    QString     type;                 // "status" | "word" | "regex"
    QString     part = "body";        // "body" | "header" | "all"
    QStringList values;
    QString     condition = "or";     // "and" | "or" over values
    bool        negative = false;
};

// One extractor: apply each regex in `values` to the selected `part` and collect
// the first capture group (or whole match) under key `name`.
struct Extractor {
    QString     type = "regex";       // only "regex" for now
    QString     part = "body";        // "body" | "header" | "all"
    QString     name;
    QStringList values;               // regex patterns
};

// A detection template.
struct Template {
    QString          id;
    QString          name;
    QString          severity;
    QString          matchersCondition = "and";   // "and" | "or" across matchers
    QList<Matcher>   matchers;
    QList<Extractor> extractors;
};

// The response pieces a template evaluates against.
struct Response {
    int     statusCode = 0;
    QString headersText;   // "Name: Value\n" joined
    QString body;
};

struct MatchResult {
    bool                          matched = false;
    QMap<QString, QStringList>    extracted;   // name -> captured values
};

// Parse a template from JSON (default-safe). Shape:
//   { "id","name","severity","matchers-condition":"and|or",
//     "matchers":[ {"type","part","words|regex":[...],"condition","negative"} ],
//     "extractors":[ {"type":"regex","part","name","regex":[...]} ] }
// For matchers, the value array is read from "values", or "words" (word type),
// or "regex"/"patterns" (regex type), or "status" (status type) -- whichever is
// present -- so it accepts nuclei-ish field names.
Template parseTemplate(const QJsonObject &obj);

// Evaluate a template against a response.
MatchResult evaluate(const Template &tpl, const Response &resp);

} // namespace Nullock::Core::TemplateEngine
