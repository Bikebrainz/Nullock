# Terms of Use

_Last updated: 2026-06-09_

## TL;DR

1. Nullock is a security testing tool. **Use it only on systems you
   own or have written permission to test.** Unauthorized use is
   illegal in most jurisdictions.
2. The software is provided "as is" under the MIT license. There is
   no warranty. We are not liable for damages, lost data, or anything
   else that goes wrong when you use it.
3. We don't host any backend service for the local Nullock app. There
   are no Terms of Service to violate beyond "follow the law."

## License

The Nullock source code is licensed under the MIT License (see
`LICENSE.md`).

## Acceptable use

Use of Nullock against:

- Systems you own
- Systems you have explicit written permission to test
- Bug bounty programs that explicitly permit your testing
- Your own browser, your own network, your own apps

is **permitted**.

Use of Nullock against:

- Systems you don't own and don't have permission to test
- "Just to see if it works" against random internet hosts
- Other people's email, banking, healthcare, or social media accounts

is **prohibited and likely illegal**. In the US this is the Computer
Fraud and Abuse Act (CFAA). In the UK this is the Computer Misuse
Act 1990. Equivalent laws exist worldwide. **You are responsible for
knowing the law in your jurisdiction.**

## No warranty

Nullock is provided "as is", without warranty of any kind, express
or implied. We make no guarantees about:

- Correctness of scanner findings
- Completeness of captured traffic
- Stability under arbitrary input
- Compatibility with any specific target application

If you base business decisions on Nullock's output (e.g. signing off
on a security audit), that's your judgment call. We don't carry
errors-and-omissions insurance for your engagement.

## No liability

Under no circumstances are the Nullock authors or contributors
liable for any damages arising from the use of this software,
including but not limited to:

- Data loss or corruption in your project files
- Crashes that lose unsaved work
- Misclassification of findings (false positives or negatives)
- Network outages caused by misconfigured scans
- Legal consequences of your testing activities

## Crypto / export

Nullock includes cryptographic functionality (TLS interception via a
local CA, HMAC, SHA256, AES via OpenSSL). It is freely available
under an OSS license; under US Export Administration Regulations
this likely qualifies for License Exception TSU (see 15 CFR §740.13).

If you redistribute Nullock, you are responsible for your own export
classification.

## Hosted services

If/when we offer hosted services (private OAST subdomains,
team-sync, enterprise tier), they will have their own Terms of
Service that you'll have to accept separately. **This document
covers the FOSS desktop app only.**

## Changes

We may update these terms. Material changes are flagged in the
release notes. Continued use after a change indicates acceptance.

## Contact

Open an issue at https://github.com/Bikebrainz/Nullock/issues with
the `legal` label.
