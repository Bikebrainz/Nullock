#pragma once

// Sensitive file / path exposure scanner. Probes a curated set of high-value
// paths (.git/config, .env, phpinfo.php, server-status, config backups, Spring
// Actuator, AWS creds, .DS_Store) and confirms each by a CONTENT signature, not
// a bare 200 -- so a catch-all server that 200s everything doesn't false-
// positive. Read-only GETs; identification, not exfiltration (the finding names
// the file, it doesn't dump its contents).

#include <QList>
#include <QPair>
#include <QString>

namespace Nullock::Core::ExposureScan {

struct Hit {
    QString path;
    QString severity;
    QString summary;
    int     status = 0;
    QString evidence;    // the matched signature fragment
};

struct Request {
    QString host;
    int     port = 443;
    bool    tls  = true;
    QString basePrefix = QStringLiteral("");   // optional path prefix
    QList<QPair<QString, QString>> headers;
};

struct Result {
    QList<Hit> hits;
    int     probed = 0;
    QString error;
};

// Probe the curated sensitive paths and return the confirmed exposures.
Result scan(const Request &req);

} // namespace Nullock::Core::ExposureScan
