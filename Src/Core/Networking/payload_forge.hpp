#pragma once

// Payload Forge: turns Nullock's *detections* into ready-to-run proof-of-concept
// payloads for authorized web-application testing. Given a technique and a
// resolved OAST callback domain, it emits the exact strings an operator pastes
// into a parameter to demonstrate impact (and to include in a report) for the
// same classes of bug the scanners already probe: SSTI, command injection, XXE,
// SQLi, reflected XSS, and JWT alg=none forgery.
//
// PURE: no network, no globals, no clock, no randomness -- forge() is a
// deterministic function of its arguments (the caller resolves the OAST domain
// and the reflection marker), so it links against Qt6::Core alone and is fully
// unit-testable. OOB payloads that would call back to an OAST domain are omitted
// when no domain is supplied, so nothing dangles at a placeholder.

#include <QList>
#include <QString>
#include <QStringList>

namespace Nullock::Core::PayloadForge {

// One generated payload, ready to paste into a request parameter.
struct Payload {
    QString technique;   // "ssti" | "cmdi" | "xxe" | "sqli" | "xss" | "jwt"
    QString variant;     // human label, e.g. "Jinja2 RCE" / "MySQL time-blind"
    QString payload;     // the payload string, placeholders already resolved
    QString note;        // what it proves / how to read the result
    bool    oob = false; // true if it calls back to the OAST domain
};

// Inputs the caller resolves before forging (kept out of the pure core so
// forge() stays deterministic and testable).
struct ForgeParams {
    QString oastDomain;  // e.g. "<token>.oast.example"; baked into OOB payloads.
                         // Empty => OOB payloads are omitted entirely.
    QString marker;      // reflection canary baked into XSS/JWT; defaults to
                         // "NULLOCK" when empty.
};

// Every technique forge() understands, in stable display order.
QStringList techniques();

// Generate payloads for one technique, or for all techniques when `technique`
// is empty or "all" (case-insensitive). Unknown techniques yield an empty list.
QList<Payload> forge(const QString &technique, const ForgeParams &params);

} // namespace Nullock::Core::PayloadForge
