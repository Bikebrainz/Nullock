const $ = (id) => document.getElementById(id);

async function load() {
  const cfg = await new Promise((res) =>
    chrome.runtime.sendMessage({ type: "getStatus" }, res));
  $("proxyHost").value   = cfg.proxyHost;
  $("proxyPort").value   = cfg.proxyPort;
  $("controlPort").value = cfg.controlPort;
  $("bypassList").value  = (cfg.bypassList || []).join("\n");
}

$("save").onclick = async () => {
  await new Promise((res) =>
    chrome.runtime.sendMessage({
      type: "save",
      config: {
        proxyHost:   $("proxyHost").value.trim() || "127.0.0.1",
        proxyPort:   parseInt($("proxyPort").value, 10) || 8080,
        controlPort: parseInt($("controlPort").value, 10) || 17777,
        bypassList:  $("bypassList").value.split("\n").map(s => s.trim()).filter(Boolean),
      },
    }, res));
  $("saved").textContent = "saved";
  setTimeout(() => { $("saved").textContent = ""; }, 1500);
};

load();
