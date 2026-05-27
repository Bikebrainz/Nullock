// ASCII animations: boot splash, traffic sparkline, intercept radar, braille spinner.

// ---------- Sparkline ----------
const SPARK_CHARS = " ▁▂▃▄▅▆▇█";

function AsciiSparkline({ width = 16, intensity = 1, label = "TRAFFIC" }) {
  const [bars, setBars] = React.useState(() => Array(width).fill(0));
  React.useEffect(() => {
    const id = setInterval(() => {
      setBars(prev => {
        const v = Math.max(0, Math.min(8, Math.floor(
          Math.random() * 6 * intensity + (Math.random() < 0.18 ? 4 : 0)
        )));
        return [...prev.slice(1), v];
      });
    }, 320);
    return () => clearInterval(id);
  }, [intensity]);
  return (
    <span className="ascii-spark" title={label}>
      <span className="ascii-spark-label">{label}</span>
      <span className="ascii-spark-bars">
        {bars.map((b, i) => (
          <span key={i} style={{ color: b >= 6 ? "var(--accent)" : b >= 3 ? "var(--text-2)" : "var(--dim)" }}>
            {SPARK_CHARS[b] || " "}
          </span>
        ))}
      </span>
    </span>
  );
}

// ---------- Braille spinner ----------
const BRAILLE = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];

function BrailleSpinner({ color = "var(--accent)" }) {
  const [i, setI] = React.useState(0);
  React.useEffect(() => {
    const id = setInterval(() => setI(x => (x + 1) % BRAILLE.length), 90);
    return () => clearInterval(id);
  }, []);
  return <span style={{ color, fontFamily: "var(--ff-mono)" }}>{BRAILLE[i]}</span>;
}

// ---------- ASCII radar ----------
const RADAR_FRAMES = [
`        . · . · .
     ·             ·
   .       ◉       .
     ·             ·
        ' · . · '`,
`        . · . · .
     ·             ·
   .       ◉━━━━   .
     ·             ·
        ' · . · '`,
`        . · . · .
     ·       |     ·
   .         ◉     .
     ·             ·
        ' · . · '`,
`        . · . · .
     ·             ·
   .   ━━━━◉       .
     ·             ·
        ' · . · '`,
`        . · . · .
     ·             ·
   .         ◉     .
     ·       |     ·
        ' · . · '`,
];

function AsciiRadar({ label = "AWAITING NEXT REQUEST" }) {
  const [f, setF] = React.useState(0);
  React.useEffect(() => {
    const id = setInterval(() => setF(x => (x + 1) % RADAR_FRAMES.length), 280);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="ascii-radar">
      <pre className="ascii-radar-art">{RADAR_FRAMES[f]}</pre>
      <div className="ascii-radar-label">▸ {label}</div>
      <div className="ascii-radar-sub">scanning :8888 · listening for outbound</div>
    </div>
  );
}

// ---------- Boot splash ----------
const NL_LOGO = [
  "███╗   ██╗██╗   ██╗██╗     ██╗      ██████╗  ██████╗██╗  ██╗",
  "████╗  ██║██║   ██║██║     ██║     ██╔═══██╗██╔════╝██║ ██╔╝",
  "██╔██╗ ██║██║   ██║██║     ██║     ██║   ██║██║     █████╔╝ ",
  "██║╚██╗██║██║   ██║██║     ██║     ██║   ██║██║     ██╔═██╗ ",
  "██║ ╚████║╚██████╔╝███████╗███████╗╚██████╔╝╚██████╗██║  ██╗",
  "╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝",
];

const BOOT_LINES = [
  { l: "loading root ca",                              v: "ok",       d: 320 },
  { l: "starting listener on :8888",                   v: "ok",       d: 280 },
  { l: "tls mitm · per-host leaf cert generation",     v: "ready",    d: 340 },
  { l: "h1 ↔ h2 transparent bridge",                   v: "ready",    d: 260 },
  { l: "websocket frame parser",                       v: "ready",    d: 220 },
  { l: "loading extensions",                           v: "3 ok",     d: 380 },
  { l: "project: acme-corp-2026.nlproj",               v: "attached", d: 300 },
  { l: "scope: 4 in · 3 out",                          v: "armed",    d: 240 },
];

function BootSplash({ onDone }) {
  const [logoRevealed, setLogoRevealed] = React.useState(0);
  const [linesShown, setLinesShown] = React.useState(0);
  const [phase, setPhase] = React.useState("logo"); // logo → boot → ready
  const [cursorOn, setCursorOn] = React.useState(true);

  // reveal logo rows
  React.useEffect(() => {
    if (phase !== "logo") return;
    if (logoRevealed >= NL_LOGO.length) {
      const t = setTimeout(() => setPhase("boot"), 280);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setLogoRevealed(r => r + 1), 70);
    return () => clearTimeout(t);
  }, [logoRevealed, phase]);

  // type out boot lines
  React.useEffect(() => {
    if (phase !== "boot") return;
    if (linesShown >= BOOT_LINES.length) {
      const t = setTimeout(() => setPhase("ready"), 420);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setLinesShown(n => n + 1), BOOT_LINES[linesShown]?.d || 240);
    return () => clearTimeout(t);
  }, [linesShown, phase]);

  // blinking cursor
  React.useEffect(() => {
    const id = setInterval(() => setCursorOn(c => !c), 420);
    return () => clearInterval(id);
  }, []);

  // auto-dismiss after ready
  React.useEffect(() => {
    if (phase !== "ready") return;
    const t = setTimeout(onDone, 1100);
    return () => clearTimeout(t);
  }, [phase, onDone]);

  const skip = (
    <button className="boot-skip" onClick={onDone}>
      <span className="kbd">ESC</span> SKIP
    </button>
  );

  return (
    <div className="boot-overlay" onKeyDown={e => e.key === "Escape" && onDone()} tabIndex={0} ref={el => el?.focus()}>
      <div className="boot-scan" />
      {skip}
      <div className="boot-stage">
        <pre className="boot-logo">
{NL_LOGO.slice(0, logoRevealed).join("\n")}
        </pre>
        <div className="boot-sub">
          <span className="dim">[</span> MITM PROXY <span className="dim">·</span> v0.4 <span className="dim">·</span> operator build <span className="dim">]</span>
        </div>

        <div className="boot-lines">
          {BOOT_LINES.slice(0, linesShown).map((line, i) => {
            const dots = ".".repeat(Math.max(2, 44 - line.l.length));
            return (
              <div key={i} className="boot-line">
                <span className="prompt">▸</span>
                <span className="lbl">{line.l}</span>
                <span className="dots">{dots}</span>
                <span className="val">{line.v}</span>
              </div>
            );
          })}
          {phase === "boot" && (
            <div className="boot-line typing">
              <span className="prompt">▸</span>
              <span className="lbl">{BOOT_LINES[linesShown]?.l || ""}</span>
              <span className="cursor">{cursorOn ? "█" : " "}</span>
            </div>
          )}
          {phase === "ready" && (
            <div className="boot-line ready">
              <span className="prompt">▸</span>
              <span className="lbl" style={{ color: "var(--accent)" }}>SYSTEM READY</span>
              <span className="dots">{".".repeat(28)}</span>
              <span className="val" style={{ color: "var(--accent)" }}>★</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { AsciiSparkline, BrailleSpinner, AsciiRadar, BootSplash });
