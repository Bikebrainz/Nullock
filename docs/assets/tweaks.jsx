/* nullock — Tweaks panel. Writes to :root CSS custom properties. */
const { useTweaks, TweaksPanel, TweakSection, TweakSlider, TweakRadio, TweakColor } = window;

const NULLOCK_TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": ["#9d4edd", "#5a189a"],
  "glow": 0.18,
  "gradAngle": 135,
  "font": "system"
}/*EDITMODE-END*/;

function NullockTweaks() {
  const [t, setTweak] = useTweaks(NULLOCK_TWEAK_DEFAULTS);

  React.useEffect(() => {
    const r = document.documentElement.style;
    const [a, b] = t.accent;
    r.setProperty("--purple", a);
    r.setProperty("--purple-end", b);
  }, [t.accent]);

  React.useEffect(() => {
    document.documentElement.style.setProperty("--glow-strength", String(t.glow));
  }, [t.glow]);

  React.useEffect(() => {
    document.documentElement.style.setProperty("--grad-angle", t.gradAngle + "deg");
  }, [t.gradAngle]);

  React.useEffect(() => {
    const id = "nullock-inter-font";
    let link = document.getElementById(id);
    if (t.font === "inter") {
      if (!link) {
        link = document.createElement("link");
        link.id = id; link.rel = "stylesheet";
        link.href = "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap";
        document.head.appendChild(link);
      }
      document.documentElement.style.setProperty("--font-ui",
        '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif');
    } else {
      document.documentElement.style.setProperty("--font-ui",
        '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif');
    }
  }, [t.font]);

  return (
    <TweaksPanel>
      <TweakSection label="Accent" />
      <TweakColor label="Brand gradient" value={t.accent}
        options={[
          ["#9d4edd", "#5a189a"],
          ["#7c3aed", "#3b0764"],
          ["#22d3ee", "#0e7490"],
          ["#f472b6", "#9d174d"],
          ["#4ade80", "#15803d"]
        ]}
        onChange={(v) => setTweak("accent", v)} />
      <TweakSlider label="Gradient angle" value={t.gradAngle} min={0} max={360} step={5} unit="°"
        onChange={(v) => setTweak("gradAngle", v)} />
      <TweakSection label="Atmosphere" />
      <TweakSlider label="Ambient glow" value={t.glow} min={0} max={0.45} step={0.01}
        onChange={(v) => setTweak("glow", v)} />
      <TweakSection label="Type" />
      <TweakRadio label="UI font" value={t.font} options={["system", "inter"]}
        onChange={(v) => setTweak("font", v)} />
    </TweaksPanel>
  );
}

ReactDOM.createRoot(document.getElementById("tweaks-root")).render(<NullockTweaks />);
