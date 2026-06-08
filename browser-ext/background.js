// Nullock Companion -- background service worker.
//
// What this does:
//   1. Routes browser traffic through Nullock's proxy port (default 8080)
//      using the chrome.proxy.settings API. PAC-script-free; just sets
//      a fixed_servers config.
//   2. Watches the badge to indicate proxy on/off.
//   3. Listens for messages from the popup to flip on/off, change ports,
//      or jump to the CA cert install URL.
//
// The CA cert install is OS-specific (you can't actually trust a CA from
// inside the browser process in MV3). What we do instead: opening the
// /ca.pem URL triggers download; the user then follows the install path
// for their OS, but we present that path as a one-pager.

const DEFAULTS = {
  enabled: false,
  proxyHost: "127.0.0.1",
  proxyPort: 8080,
  controlPort: 17777,
  bypassList: ["localhost", "127.0.0.1", "<local>"],
};

async function getConfig() {
  const stored = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...stored };
}

async function applyProxy(enabled) {
  const cfg = await getConfig();
  if (enabled) {
    await chrome.proxy.settings.set({
      value: {
        mode: "fixed_servers",
        rules: {
          singleProxy: {
            scheme: "http",
            host: cfg.proxyHost,
            port: cfg.proxyPort,
          },
          bypassList: cfg.bypassList,
        },
      },
      scope: "regular",
    });
    chrome.action.setBadgeText({ text: "ON" });
    chrome.action.setBadgeBackgroundColor({ color: "#9d4edd" });
  } else {
    await chrome.proxy.settings.clear({ scope: "regular" });
    chrome.action.setBadgeText({ text: "" });
  }
  await chrome.storage.local.set({ enabled });
}

async function pingControl() {
  // Reachability probe so the popup can tell the user whether Nullock
  // is actually running. Returns the snapshot for quick stats.
  const cfg = await getConfig();
  try {
    const r = await fetch(`http://${cfg.proxyHost}:${cfg.controlPort}/api/snapshot`,
                          { credentials: "omit" });
    if (!r.ok) return { reachable: false, status: r.status };
    const j = await r.json();
    return {
      reachable: true,
      project: j.bootInfo?.project,
      proxyPort: j.bootInfo?.port,
      rows: (j.rows || []).length,
      findings: j.findingsCount || 0,
    };
  } catch (e) {
    return { reachable: false, error: String(e) };
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (msg.type === "getStatus") {
      const cfg = await getConfig();
      const ping = await pingControl();
      sendResponse({ ...cfg, ping });
    } else if (msg.type === "toggle") {
      const cfg = await getConfig();
      await applyProxy(!cfg.enabled);
      sendResponse({ enabled: !cfg.enabled });
    } else if (msg.type === "save") {
      await chrome.storage.local.set(msg.config);
      // Re-apply so the port change takes effect immediately.
      const cfg = await getConfig();
      if (cfg.enabled) await applyProxy(true);
      sendResponse({ ok: true });
    } else if (msg.type === "openCa") {
      const cfg = await getConfig();
      const url = `http://${cfg.proxyHost}:${cfg.controlPort}/ca.pem`;
      chrome.tabs.create({ url });
      sendResponse({ ok: true });
    }
  })();
  // async response
  return true;
});

// Restore state on browser start.
chrome.runtime.onStartup.addListener(async () => {
  const cfg = await getConfig();
  if (cfg.enabled) await applyProxy(true);
});

// First-install: leave proxy off, show the popup to walk through setup.
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    // No iconUrl -- browser falls back to default; icons can be added
    // later without re-rolling the extension.
    console.log("Nullock Companion installed. Click toolbar icon to enable.");
  }
});
