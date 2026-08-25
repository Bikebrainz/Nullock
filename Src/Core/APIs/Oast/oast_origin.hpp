#pragma once

// The originating context of an OAST callback token, split into its own header
// (Qt6::Core only -- QString + int, no QtNetwork) so the pure persistence
// serializer in oast_logic can use it without dragging in the QtNetwork chain
// that oast_server.hpp / oast_correlator.hpp pull. See oast_correlator.hpp for
// how it is registered and correlated.

#include <QString>

namespace Nullock::Core {

struct OastOrigin {
    int     rowId = 0;     // history row that fired the payload (0 = manual)
    QString host;          // target host the payload was sent to
    QString param;         // parameter / location the token was embedded in
    QString url;           // the callback URL we embedded
    QString kind;          // probe kind, e.g. "ssrf-oast"
    QString note;          // optional free-text label (manual mints)
};

} // namespace Nullock::Core
