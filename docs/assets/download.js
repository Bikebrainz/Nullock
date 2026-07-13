/* nullock — resolve the latest GitHub release's real asset URLs at page load,
   so every Download button points at the most recent build.
   Falls back to the Releases page if the API is unavailable. */
(function () {
  "use strict";

  var REPO = "Bikebrainz/Nullock";
  var LATEST_PAGE = "https://github.com/" + REPO + "/releases/latest";
  var API = "https://api.github.com/repos/" + REPO + "/releases/latest";

  // platform -> regex(es) to pick the right asset by filename
  var MATCHERS = {
    windows: [/win64.*\.exe$/i, /\.exe$/i, /\.msi$/i],
    "linux-deb": [/\.deb$/i],
    "linux-rpm": [/\.rpm$/i],
    "linux-appimage": [/\.appimage$/i],
    macos: [/darwin.*\.dmg$/i, /\.dmg$/i],
    linux: [/\.appimage$/i, /\.deb$/i] // generic "Linux" button preference
  };

  function pick(assets, keys) {
    for (var k = 0; k < keys.length; k++) {
      var res = MATCHERS[keys[k]];
      for (var i = 0; i < res.length; i++) {
        for (var a = 0; a < assets.length; a++) {
          if (res[i].test(assets[a].name)) return assets[a];
        }
      }
    }
    return null;
  }

  function detectOS() {
    var p = (navigator.userAgentData && navigator.userAgentData.platform) ||
            navigator.platform || navigator.userAgent || "";
    p = p.toLowerCase();
    if (p.indexOf("win") > -1) return "windows";
    if (p.indexOf("mac") > -1) return "macos";
    if (p.indexOf("linux") > -1 || p.indexOf("x11") > -1) return "linux";
    return null;
  }

  function applyFallback() {
    document.querySelectorAll("[data-dl]").forEach(function (el) {
      if (!el.getAttribute("href") || el.getAttribute("href") === "#") {
        el.setAttribute("href", LATEST_PAGE);
      }
    });
  }

  // Wire everything to the releases page immediately (safe default),
  // then upgrade to direct asset links if the API answers.
  applyFallback();

  fetch(API, { headers: { Accept: "application/vnd.github+json" } })
    .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
    .then(function (rel) {
      var assets = rel.assets || [];
      var tag = rel.tag_name || "";

      // version labels
      if (tag) {
        document.querySelectorAll("[data-version]").forEach(function (el) {
          el.textContent = tag.replace(/^v?/, "v");
        });
      }

      // per-platform download rows: <a data-dl="windows|linux-deb|...">
      document.querySelectorAll("[data-dl]").forEach(function (el) {
        var keys = el.getAttribute("data-dl").split(/\s+/);
        var asset = pick(assets, keys);
        if (asset) {
          el.setAttribute("href", asset.browser_download_url);
          var sz = el.querySelector("[data-dl-size]");
          if (sz && asset.size) sz.textContent = (asset.size / 1048576).toFixed(1) + " MB";
        } else {
          el.setAttribute("href", LATEST_PAGE);
        }
      });

      // primary hero button: best guess for the visitor's OS
      var os = detectOS();
      document.querySelectorAll("[data-dl-primary]").forEach(function (el) {
        var asset = os ? pick(assets, os === "linux" ? ["linux-appimage", "linux-deb"] : [os]) : null;
        el.setAttribute("href", asset ? asset.browser_download_url : LATEST_PAGE);
        if (os) {
          var lbl = el.querySelector("[data-dl-oslabel]");
          if (lbl) lbl.textContent = " for " + (os === "macos" ? "macOS" : os.charAt(0).toUpperCase() + os.slice(1));
        }
      });
    })
    .catch(function () { applyFallback(); });
})();
