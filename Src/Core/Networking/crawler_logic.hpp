#pragma once

// Pure crawler logic, split out of the Crawler QObject so it can be unit-tested
// against Qt6::Core alone (Crawler itself pulls QObject + proxy_server). These
// are deterministic functions over strings/URLs -- no I/O, no signals:
//   truncateBodyAtTag -- cap the scanned body WITHOUT splitting a tag mid-attr;
//   resolveBase       -- the effective base URL for a page, honoring <base href>;
//   extractRawLinks   -- href/src/action values, QUOTED or UNQUOTED;
//   canonicalLink     -- resolve + http(s) allowlist + fragment strip + a stable
//                        dedup key, returning "" for a non-crawlable link;
//   inDefaultScope    -- the FAIL-CLOSED default scope (the seed's own domain
//                        tree) used when no explicit scope checker is injected.

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QUrl>

namespace Nullock::Core::CrawlerLogic {

// Trim `body` to at most `maxBytes`, but never mid-tag: cut back to the last '>'
// before the cap so a straddling href value (and everything after it) isn't
// silently dropped by a byte-positional cut.
QByteArray truncateBodyAtTag(const QByteArray &body, int maxBytes);

// The base URL against which relative links on this page resolve: the first
// <base href> in the document (resolved against pageUrl if it's relative), or
// pageUrl itself when there's no usable <base>.
QUrl resolveBase(const QString &html, const QUrl &pageUrl);

// Every href / src / action value in the document -- handling double-quoted,
// single-quoted, AND unquoted (href=/admin) attribute syntax. Values are
// returned raw (un-resolved), trimmed, in document order.
QStringList extractRawLinks(const QString &html);

// Responsive-image srcset candidates: each comma-separated candidate's leading
// URL token (before its width/density descriptor). Raw, un-resolved.
QStringList extractSrcset(const QString &html);

// <meta http-equiv="refresh" content="0;url=/next"> redirect targets (the url=
// from the content attribute). Raw, un-resolved.
QStringList extractMetaRefresh(const QString &html);

// GET-form parameter surfaces: for each <form method=get action=X> carrying
// <input>/<select>/<textarea> name= fields, synthesize "action?n1=&n2=" (action
// empty => relative "?..." resolved against the page) so the parameterized
// endpoint enters the crawl. Raw, un-resolved.
QStringList extractFormGets(const QString &html);

// Resolve `href` against `base`, drop the fragment, and enforce an http/https
// scheme allow-list (so mailto:/tel:/javascript:/data:/blob: collapse to ""). On
// success returns a canonical dedup key (empty path normalized to "/") and sets
// `outHost` to the resolved host; returns "" (and clears outHost) otherwise.
QString canonicalLink(const QString &href, const QUrl &base, QString &outHost);

// Fail-closed default scope: with no explicit checker, a crawl must stay within
// the SEED's own domain tree. In scope iff host == seedHost, or host is the
// seed's apex (seedHost minus a single leading "www."), or a subdomain of that
// apex. Never broader than the seed's registrable domain, so it can't wander
// off-site by default.
bool inDefaultScope(const QString &host, const QString &seedHost);

// The effective port for a scheme/port pair: the explicit port when > 0, else the
// scheme default (443 for https, 80 otherwise). QUrl::port(-1) yields -1 for an
// absent port, which this resolves so origins compare by their real port.
int effectivePort(const QString &scheme, int port);

// Origin-aware fail-closed default scope (no injected checker). In scope iff the
// host is within the seed's domain tree (inDefaultScope) AND the port does not
// cross into a different service: a seed on a standard web port (80/443) admits
// any standard-web port on the in-tree host (so an http<->https hop stays in
// scope) but refuses a non-standard port (:8080/:8443/... is a different app ->
// scope creep); a seed pinned to a non-standard port admits only that exact port.
// Pure.
bool inDefaultScopeOrigin(const QString &scheme, const QString &host, int port,
                          const QString &seedScheme, const QString &seedHost, int seedPort);

} // namespace Nullock::Core::CrawlerLogic
