// Nullock Companion popup wiring.

const $ = (id) => document.getElementById(id);

async function refresh() {
  const status = await new Promise((res) =>
    chrome.runtime.sendMessage({ type: "getStatus" }, res));

  $("toggle").textContent  = status.enabled ? "Disable Proxy" : "Enable Proxy";
  $("toggle").className    = status.enabled ? "" : "primary";
  $("cfgProxy").textContent   = `${status.proxyHost}:${status.proxyPort}`;
  $("cfgControl").textContent = `${status.proxyHost}:${status.controlPort}`;

  if (status.ping?.reachable) {
    $("status").innerHTML = `<span class="ok">running</span>`;
    $("project").textContent  = status.ping.project || "default";
    $("rows").textContent     = status.ping.rows ?? "-";
    $("findings").textContent = status.ping.findings ?? "-";
  } else {
    $("status").innerHTML = `<span class="bad">not reachable</span>`;
    $("project").textContent  = "-";
    $("rows").textContent     = "-";
    $("findings").textContent = "-";
  }
}

$("toggle").onclick = async () => {
  await new Promise((res) =>
    chrome.runtime.sendMessage({ type: "toggle" }, res));
  await refresh();
};

$("ca").onclick = () => {
  chrome.runtime.sendMessage({ type: "openCa" });
  window.close();
};

$("ui").onclick = async () => {
  const status = await new Promise((res) =>
    chrome.runtime.sendMessage({ type: "getStatus" }, res));
  chrome.tabs.create({
    url: `http://${status.proxyHost}:${status.controlPort}/`,
  });
  window.close();
};

$("options").onclick = () => chrome.runtime.openOptionsPage();

refresh();
