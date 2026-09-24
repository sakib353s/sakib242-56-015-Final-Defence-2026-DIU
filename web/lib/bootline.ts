import type { BootLine } from "./types";
import type { Theme } from "./theme";

let bootTheme: Theme = "dark";
export function setBootTheme(t: Theme): void {
  bootTheme = t;
}
export function getBootTheme(): Theme {
  return bootTheme;
}

const RESET = "\x1b[0m";
const DIM = "\x1b[2m";
const DARK = {
  ok: "\x1b[38;2;62;255;120m",
  warn: "\x1b[38;2;255;190;60m",
  fail: "\x1b[38;2;255;70;70m",
  hdr: "\x1b[38;2;60;235;255m",
  ts: "\x1b[38;2;150;168;182m",
  mid: "\x1b[38;2;148;163;176m",
};
const LIGHT = {
  ok: "\x1b[38;2;8;122;60m",
  warn: "\x1b[38;2;160;90;0m",
  fail: "\x1b[38;2;193;20;28m",
  hdr: "\x1b[38;2;9;106;128m",
  ts: "\x1b[38;2;85;103;116m",
  mid: "\x1b[38;2;85;103;116m",
};

/* server emits truecolor SGR; remap the known dark-mode values for light bg */
const RECODE_DARK_TO_LIGHT: Array<[RegExp, string]> = [
  [/38;2;62;255;120/g, "38;2;8;122;60"],
  [/38;2;0;255;65/g, "38;2;8;122;60"],
  [/38;2;255;190;60/g, "38;2;160;90;0"],
  [/38;2;255;176;0/g, "38;2;160;90;0"],
  [/38;2;255;70;70/g, "38;2;193;20;28"],
  [/38;2;255;42;42/g, "38;2;193;20;28"],
  [/38;2;60;235;255/g, "38;2;9;106;128"],
  [/38;2;0;229;255/g, "38;2;9;106;128"],
  [/38;2;150;168;182/g, "38;2;85;103;116"],
  [/38;2;148;163;176/g, "38;2;85;103;116"],
  [/38;2;205;218;228/g, "38;2;51;70;83"],
  [/48;2;0;229;255/g, "48;2;9;106;128"],
  [/38;2;8;11;16/g, "38;2;246;254;255"],
];

export function recode(s: string, theme: Theme = bootTheme): string {
  if (theme !== "light") return s;
  let out = s;
  for (const [re, rep] of RECODE_DARK_TO_LIGHT) out = out.replace(re, rep);
  return out;
}

// Mirrors backend BootLine.render() — status RAW prints the label verbatim
// (multi-line box-drawing / banner art); other statuses compose a leader row.
export function renderBootLine(l: BootLine, theme: Theme = bootTheme): string {
  const pal = theme === "light" ? LIGHT : DARK;
  if (l.status === "RAW") return `${recode(l.label, theme)}\r\n`;
  const col = `${pal.ts}[${l.ts}]${RESET}`;
  const scolor = l.status === "OK" ? pal.ok : l.status === "WARN" ? pal.warn : l.status === "FAIL" ? pal.fail : pal.hdr;
  const core = `${l.label} `;
  const leaders = "·".repeat(Math.max(1, 50 - core.length));
  return (
    `${col} ${core}${pal.mid}${leaders}${RESET} [${scolor} ${l.status} ${RESET}]` +
    (l.detail ? ` ${recode(l.detail, theme)}` : "") +
    "\r\n"
  );
}

export function xtermTheme(theme: Theme) {
  return theme === "light"
    ? {
        background: "#f8fafc",
        foreground: "#101820",
        cursor: "#0e8aa3",
        black: "#101820",
        red: "#c1141c",
        green: "#087a3c",
        yellow: "#a05a00",
        blue: "#0b6a80",
        magenta: "#7a3fa8",
        cyan: "#0b6a80",
        white: "#3a4a58",
        brightGreen: "#087a3c",
        brightYellow: "#a05a00",
        brightCyan: "#0e8aa3",
        selectionBackground: "rgba(14,138,163,0.25)",
      }
    : {
        background: "#06090E",
        foreground: "#EAF2F8",
        cursor: "#3CEBFF",
        black: "#0B0F14",
        red: "#FF4646",
        green: "#3EFF78",
        yellow: "#FFBE3C",
        blue: "#3CEBFF",
        magenta: "#B48CFF",
        cyan: "#3CEBFF",
        white: "#EAF2F8",
        brightGreen: "#3EFF78",
        brightYellow: "#FFBE3C",
        brightCyan: "#3CEBFF",
      };
}

export const NICE_BANNER = [
  "╔════════════════════════════════════════════════════════════════╗",
  "\x1b[38;2;0;229;255m║\x1b[0m                        \x1b[48;2;0;229;255;1;38;2;8;11;16m CYBERWATCH-BD \x1b[0m                         \x1b[38;2;0;229;255m║\x1b[0m",
  "\x1b[38;2;0;229;255m║\x1b[0m                                                                \x1b[38;2;0;229;255m║\x1b[0m",
  "\x1b[38;2;0;229;255m║\x1b[0m                    \x1b[1mMD RAFSHAN RAHMAN SAKIB\x1b[0m                     \x1b[38;2;0;229;255m║\x1b[0m",
  "\x1b[38;2;0;229;255m║\x1b[0m                           \x1b[38;2;0;255;65m242-56-015\x1b[0m                           \x1b[38;2;0;229;255m║\x1b[0m",
  "\x1b[38;2;0;229;255m║\x1b[0m                     \x1b[38;2;205;218;228mM.Sc in Cyber Security\x1b[0m                     \x1b[38;2;0;229;255m║\x1b[0m",
  "\x1b[38;2;0;229;255m║\x1b[0m                  \x1b[38;2;205;218;228mDepartment of Cyber Security\x1b[0m                  \x1b[38;2;0;229;255m║\x1b[0m",
  "\x1b[38;2;0;229;255m║\x1b[0m               \x1b[38;2;205;218;228mDaffodil International University\x1b[0m                \x1b[38;2;0;229;255m║\x1b[0m",
  "╚════════════════════════════════════════════════════════════════╝",
];

export const EGG = "sakib24256015";
