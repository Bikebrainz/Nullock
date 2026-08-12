#pragma once

// Intruder save/resume serialization (Burp-parity: "save attack" / reload). An
// entire attack -- the target/template/payload config AND every result row --
// round-trips through JSON so an engagement can be persisted and reopened.
//
// PURE: structs in, JSON out (and back), no I/O and no engine dependency -- links
// against Qt6::Core alone. The Rule / ExtractSpec structs it references are
// header-only (from intruder_rules.hpp / intruder_grep.hpp), so this TU stays
// light enough to compile straight into a Qt6::Core-only unit test.
//
// SAFETY: fromJson/fromBytes are DEFAULT-SAFE -- malformed JSON, missing fields,
// or wrong types yield a valid SavedRun with sensible defaults, never a crash.
// The per-position combo (which may hold NULL entries meaning "leave this marker
// at its default") is preserved across the round-trip via JSON null, so resend()
// still reproduces the exact request after a load.

#include "intruder_rules.hpp"
#include "intruder_grep.hpp"

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QStringList>

namespace Nullock::Core::IntruderPersist {

// Bump when the on-disk shape changes incompatibly. fromJson tolerates unknown
// (future) versions by best-effort parsing rather than rejecting.
constexpr int kFormatVersion = 1;

// One persisted result row -- mirrors IntruderAttack's serialisable state.
struct ResultRow {
    int         id = 0;
    QStringList payloadValues;   // display values, one per position
    QStringList combo;           // raw combo; entries may be null (= default)
    int         statusCode = 0;
    int         responseSize = 0;
    int         elapsedMs = 0;
    QString     errorMessage;
    bool        complete = false;
    bool        matched = false;
    bool        reflected = false;   // a payload of this row echoed in the response
    QString     extracted;
};

// The full attack configuration -- everything setPayloads/setGrep*/etc. hold.
struct RunConfig {
    QString     host;
    int         port = 443;
    bool        tls = true;
    QString     requestTemplate;
    int         attackType = 0;
    QStringList payloadSets;                          // newline-joined block/pos
    QList<IntruderRules::Rule> rules;
    QStringList grepMatch;
    bool        grepPayloadReflection = false;   // flag rows whose payload reflects
    IntruderGrep::ExtractSpec grepExtract;
    int         concurrency = 10;
    int         throttleMs = 0;
};

// A complete saved attack: format version + config + result rows.
struct SavedRun {
    int       version = kFormatVersion;
    RunConfig config;
    QList<ResultRow> rows;
};

QJsonObject toJson(const SavedRun &run);
QByteArray  toBytes(const SavedRun &run);            // compact JSON bytes

SavedRun    fromJson(const QJsonObject &obj);        // default-safe
SavedRun    fromBytes(const QByteArray &bytes);      // default-safe (bad JSON -> empty run)

} // namespace Nullock::Core::IntruderPersist
