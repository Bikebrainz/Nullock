#pragma once

// nuclei YAML -> Nullock template JSON shim. Lets Nullock ingest the huge
// existing library of nuclei .yaml templates and run them through the template
// engine (template_engine_logic / template_request_logic), which already speaks
// the JSON shape nuclei's matchers/extractors map onto.
//
// This is NOT a general YAML parser -- it handles the subset real nuclei HTTP
// templates use: indentation-based maps, block sequences ("- item"), sequences
// of maps ("- key: val" + aligned keys), double/single-quoted and bare scalars,
// integers, "[a, b]" flow sequences, and "# ..." comments. Block scalars (| >)
// and anchors/aliases are out of scope.
//
// PURE: a YAML string in, a QJsonObject (Nullock template) out. Qt6::Core only.
// DEFAULT-SAFE: malformed / unsupported YAML yields an empty (or best-effort
// partial) object -- never a throw. Bounded so a pathological input can't hang.

#include <QJsonObject>
#include <QJsonValue>
#include <QString>

namespace Nullock::Core::NucleiYaml {

// Parse the YAML subset into a nested QJsonValue (map/array/scalar). Exposed so
// it can be unit-tested directly; default-safe.
QJsonValue parseYaml(const QString &yaml);

// Convert a parsed nuclei document (or a raw YAML string) into a Nullock
// template object: { id, name, severity, matchers-condition, matchers[],
// extractors[], request:{method,path,headers,body} }. The first http/requests
// block is used. Returns an empty object on unusable input.
QJsonObject nucleiToTemplate(const QJsonValue &doc);
QJsonObject nucleiYamlToTemplate(const QString &yaml);

} // namespace Nullock::Core::NucleiYaml
