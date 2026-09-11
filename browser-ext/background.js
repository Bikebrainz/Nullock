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

function controlUrl(cfg, suffix = "") {
  const host = cfg.proxyHost.includes(":") ? `[${cfg.proxyHost.replace(/^\[|\]$/g, "")}]` : cfg.proxyHost;
  return new URL(`http://${host}:${cfg.controlPort}${suffix}`).href;
}

function validateConfig(input) {
  const cfg = { ...DEFAULTS, ...input };
  for (const key of ["proxyPort", "controlPort"]) {
    if (!Number.isInteger(cfg[key]) || cfg[key] < 1 || cfg[key] > 65535)
      throw new Error("Ports must be whole numbers between 1 and 65535.");
  }
  if (typeof cfg.proxyHost !== "string" || !cfg.proxyHost.trim() || /[\s/?#@]/.test(cfg.proxyHost))
    throw new Error("Enter a hostname or IP address without a scheme, path, or port.");
  if (!Array.isArray(cfg.bypassList) || cfg.bypassList.some(v => typeof v !== "string"))
    throw new Error("Enter one bypass host per line.");
  controlUrl(cfg); // rejects malformed IPv6 and host:port input
  return { proxyHost: cfg.proxyHost.trim(), proxyPort: cfg.proxyPort,
    controlPort: cfg.controlPort, bypassList: cfg.bypassList.map(v => v.trim()).filter(Boolean) };
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
    const r = await fetch(controlUrl(cfg, "/api/snapshot"),
                          { credentials: "omit", signal: AbortSignal.timeout(3000) });
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
      const previous = await getConfig();
      const cfg = validateConfig(msg.config);
      await chrome.storage.local.set(cfg);
      try {
        if (previous.enabled) await applyProxy(true);
      } catch (error) {
        await chrome.storage.local.set(previous);
        throw error;
      }
      sendResponse({ ok: true });
    } else if (msg.type === "openCa" || msg.type === "openUi") {
      const cfg = await getConfig();
      await chrome.tabs.create({ url: controlUrl(cfg, msg.type === "openCa" ? "/ca.pem" : "/") });
      sendResponse({ ok: true });
    } else {
      sendResponse({ ok: false, error: "Unknown companion action." });
    }
  })().catch(error => sendResponse({ ok: false, error: String(error.message || error) }));
  // async response
  return true;
});

// Restore state on browser start.
chrome.runtime.onStartup.addListener(async () => {
  try {
    const cfg = await getConfig();
    if (cfg.enabled) await applyProxy(true);
  } catch (error) {
    await chrome.action.setBadgeText({ text: "ERR" });
    console.error("Could not restore the Nullock proxy:", error);
  }
});

// First-install: leave proxy off, show the popup to walk through setup.
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    // No iconUrl -- browser falls back to default; icons can be added
    // later without re-rolling the extension.
    console.log("Nullock Companion installed. Click toolbar icon to enable.");
  }
});
