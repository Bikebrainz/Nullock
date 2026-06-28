#include "intercept_logic.hpp"

namespace Nullock::Proxy::InterceptLogic {

QByteArray resolveForwardBytes(const QByteArray &originalBytes, const QString &currentText) {
    // Unedited? Forward the captured bytes verbatim -- no lossy round-trip.
    // QString::fromUtf8 is deterministic, so an unedited GUI buffer compares
    // equal to the decode of the original bytes even when that decode contains
    // U+FFFD replacement characters: both sides hold the identical replacements,
    // so equality still holds and we take the verbatim path.
    if (currentText == QString::fromUtf8(originalBytes))
        return originalBytes;

    // Operator edited the text. Re-encode: lossless for an all-UTF-8 request;
    // for an edited binary body some fidelity is unavoidably lost, but that is
    // the operator's explicit action in the editor, not a silent passive defect.
    return currentText.toUtf8();
}

bool interceptQueueHasRoom(int outstanding) {
    if (outstanding < 0) return true;   // defensive: a bad count != "full"
    return outstanding < kMaxPendingIntercepts;
}

} // namespace Nullock::Proxy::InterceptLogic
