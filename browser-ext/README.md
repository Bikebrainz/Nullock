# Nullock Companion (browser extension)

Enable proxy routing and download Nullock's CA certificate. Trusting that
certificate is a separate, manual operating-system or browser step.

## Install (developer mode)

1. Start Nullock locally:
   ```
   NullockApp --headless --proxy-port=8080 --control-port=17777
   ```
2. In Chrome / Edge / Brave, open `chrome://extensions`.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and pick the `browser-ext/` directory in this repo.
5. Click the Nullock icon in your toolbar -> **Enable Proxy**.
6. Click **Download CA cert**, then follow your OS's "trust this CA" path:
   - **Windows**: open the downloaded `ca.pem`, click *Install Certificate*,
     pick *Local Machine* -> *Trusted Root Certification Authorities*.
   - **macOS**: drag into Keychain Access, double-click, set *Trust* ->
     *Always Trust* for SSL.
   - **Linux**: `sudo cp ca.pem /usr/local/share/ca-certificates/nullock.crt && sudo update-ca-certificates`.
7. Restart the browser. Done.

## What the extension does

- `chrome.proxy.settings.set` with a fixed-servers config pointing at
  `127.0.0.1:8080` (configurable in Options). Localhost + `<local>` are
  bypassed so this extension's own control-API requests still work.
- Reads `/api/snapshot` for popup stats (rows captured,
  findings, current project).
- Provides one-click links to the Nullock UI and CA download.

The extension never sees or modifies any captured traffic; that all
lives inside Nullock itself. It's just glue to flip the browser's proxy
config without you having to dig through system settings.

## Permissions

- `proxy` -- to flip the browser's outbound proxy
- `storage` -- to remember your host/port across sessions
- `tabs` -- to open the UI and CA cert in new tabs
- Host permissions -- read the configured Nullock control server's status.

Status reads use the local control API. A remote control server that requires
bearer authentication is not supported by this companion's status display.

## Why not Firefox?

It's straightforward to port: Firefox supports the same `chrome.proxy`
namespace in WebExtensions, but the `proxy.settings.set` shape differs
slightly (Firefox prefers `browser.proxy.settings.set` with `value.proxy`
nested). PR welcome.
