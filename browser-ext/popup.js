// Nullock Companion popup wiring.

const $ = (id) => document.getElementById(id);
async function send(type) {
  const reply = await chrome.runtime.sendMessage({ type });
  if (!reply || reply.ok === false) throw new Error(reply?.error || "Companion did not respond.");
  return reply;
}
function showError(error) {
  $("status").textContent = error.message || String(error);
  $("status").className = "bad";
}

async function refresh() {
  const status = await send("getStatus");
  $("status").className = "";

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
  try { await send("toggle"); await refresh(); } catch (error) { showError(error); }
};

$("ca").onclick = async () => {
  try { await send("openCa"); window.close(); } catch (error) { showError(error); }
};

$("ui").onclick = async () => {
  try { await send("openUi"); window.close(); } catch (error) { showError(error); }
};

$("options").onclick = () => chrome.runtime.openOptionsPage();

refresh().catch(showError);
