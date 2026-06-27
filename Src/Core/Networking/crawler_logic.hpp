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

} // namespace Nullock::Core::CrawlerLogic
