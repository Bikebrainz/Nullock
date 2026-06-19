# Release signing & notarization

The [`release`](.github/workflows/release.yml) workflow builds installers for
Windows, Linux and macOS on every `v*.*.*` tag. Code signing and Apple
notarization are **wired but optional**: every signing step is guarded by
`if: ${{ secrets.* != '' }}`, so until you add the certificates below, releases
build and upload **unsigned** (exactly as before). Add the secrets and the same
workflow signs automatically — no YAML change needed.

This is the one part of v3 that genuinely needs *you*: signing certificates are
issued to a legal identity and cost money. Everything else is already in place.

## Windows (Authenticode)

You need a code-signing certificate (OV or EV) from a CA such as DigiCert,
Sectigo, or SSL.com. Export it as a password-protected `.pfx`, then add two
repo secrets (Settings → Secrets and variables → Actions):

| Secret | Value |
| --- | --- |
| `WINDOWS_CERT_BASE64` | the `.pfx` file, base64-encoded |
| `WINDOWS_CERT_PASSWORD` | the `.pfx` export password |

Encode the pfx:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("nullock.pfx")) | Set-Content cert.b64
```

The workflow signs `NullockApp.exe` before packaging and the NSIS installer
after, timestamping via DigiCert's RFC-3161 server.

> EV certificates on a hardware token can't be exported to a `.pfx`; for those
> use the CA's cloud-signing service (e.g. DigiCert KeyLocker / Azure Trusted
> Signing) and swap the `signtool` invocation for their action — the rest of the
> job is unchanged.

## macOS (codesign + notarization)

You need an Apple Developer Program membership ($99/yr). From it:

1. A **Developer ID Application** certificate. Export it from Keychain Access as
   a password-protected `.p12`.
2. An **App Store Connect API key** (Users and Access → Integrations → Keys,
   role *Developer*): the `.p8` private key, its Key ID, and the Issuer ID.

Add these repo secrets:

| Secret | Value |
| --- | --- |
| `MACOS_CERT_BASE64` | the Developer ID `.p12`, base64-encoded (`base64 -i cert.p12`) |
| `MACOS_CERT_PASSWORD` | the `.p12` export password |
| `MACOS_SIGN_IDENTITY` | e.g. `Developer ID Application: Your Name (TEAMID)` |
| `AC_API_KEY_ID` | the API key's Key ID |
| `AC_API_ISSUER` | the Issuer ID (a UUID) |
| `AC_API_KEY` | the contents of the `.p8` file |

The workflow imports the cert into a throwaway keychain, `codesign`s the `.app`
with the hardened runtime, packs the `.dmg`, then `notarytool submit --wait`
and `stapler staple`s it.

> `MACOS_SIGN_IDENTITY` must match your certificate's common name exactly — run
> `security find-identity -v -p codesigning` locally to read it. If the `.app`
> path differs from what the `find` step locates, adjust the `codesign` step.

## Verifying a signed build

- Windows: right-click the `.exe` → Properties → Digital Signatures, or
  `signtool verify /pa Nullock-*.exe`.
- macOS: `codesign --verify --deep --strict Nullock.app` and
  `spctl -a -t open --context context:primary-signature Nullock-*.dmg`.
