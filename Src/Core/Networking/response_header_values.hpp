#pragma once

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::ResponseHeaderValues {
using Headers = QList<QPair<QString, QString>>;

// Fetch's script/style MIME enforcement uses the first comma-delimited value.
bool nosniffForScriptsAndStyles(const Headers &headers);
// Chromium's document-sniffing gate requires a single complete nosniff value.
// A list can protect scripts/styles without preventing document sniffing.
bool nosniffForDocuments(const Headers &headers);
// Last recognized HTTP policy, skipping unknown letter/hyphen fallback tokens.
// Empty means absent, unrecognized, or malformed; browser defaults/inheritance apply.
QString referrerPolicy(const Headers &headers);
}
