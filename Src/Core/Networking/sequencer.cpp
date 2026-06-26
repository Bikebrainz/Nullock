#include "sequencer.hpp"

// The Sequencer QObject is a thin Q_INVOKABLE wrapper; all the analysis logic
// is the free function analyzeTokens() in sequencer_logic.cpp. Keeping the logic
// out of this (QObject/moc) TU lets the unit test link analyzeTokens() against
// Qt6::Core alone -- referencing the QObject would otherwise drag in Networking's
// shared moc compilation (every QObject -> Repeater/Intruder -> ProxyModel).

namespace Nullock::Core {

QJsonObject Sequencer::analyze(const QStringList &tokens) const {
    return analyzeTokens(tokens);
}

} // namespace Nullock::Core
