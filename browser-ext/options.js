const $ = (id) => document.getElementById(id);
async function send(message) {
  const reply = await chrome.runtime.sendMessage(message);
  if (!reply || reply.ok === false) throw new Error(reply?.error || "Companion did not respond.");
  return reply;
}
function showError(error) {
  $("saved").textContent = error.message || String(error);
  $("saved").style.color = "#f87171";
}

async function load() {
  const cfg = await send({ type: "getStatus" });
  $("proxyHost").value   = cfg.proxyHost;
  $("proxyPort").value   = cfg.proxyPort;
  $("controlPort").value = cfg.controlPort;
  $("bypassList").value  = (cfg.bypassList || []).join("\n");
}

$("save").onclick = async () => {
  try {
    for (const id of ["proxyPort", "controlPort"]) {
      if (!$(id).reportValidity()) return;
    }
    await send({
      type: "save",
      config: {
        proxyHost:   $("proxyHost").value.trim() || "127.0.0.1",
        proxyPort:   Number($("proxyPort").value),
        controlPort: Number($("controlPort").value),
        bypassList:  $("bypassList").value.split("\n").map(s => s.trim()).filter(Boolean),
      },
    });
  $("saved").style.color = "#4ade80";
  $("saved").textContent = "saved";
  setTimeout(() => { $("saved").textContent = ""; }, 1500);
  } catch (error) { showError(error); }
};

load().catch(showError);
