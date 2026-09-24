export type ThemePref = "dark" | "light" | "system";
export type Theme = "dark" | "light";

const KEY = "cwb-theme-pref";

export function getPref(): ThemePref {
  if (typeof window === "undefined") return "dark";
  const v = window.localStorage.getItem(KEY);
  return v === "light" || v === "system" ? v : "dark";
}

export function resolve(pref: ThemePref): Theme {
  if (pref !== "system") return pref;
  return typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
}

export function current(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export const THEME_EVENT = "cwb-theme";

export function apply(pref: ThemePref): Theme {
  const t = resolve(pref);
  document.documentElement.dataset.theme = t;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", t === "light" ? "#eaeef4" : "#070a12");
  window.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: t }));
  return t;
}

export function setPref(pref: ThemePref): Theme {
  try {
    window.localStorage.setItem(KEY, pref);
  } catch {
    /* private mode — apply still works for the session */
  }
  return apply(pref);
}

/** live-follow OS appearance while pref === system */
export function watchSystem(): () => void {
  const mq = window.matchMedia("(prefers-color-scheme: light)");
  const on = () => {
    if (getPref() === "system") apply("system");
  };
  mq.addEventListener("change", on);
  return () => mq.removeEventListener("change", on);
}

/** run once per page load (client) */
export function initTheme(): Theme {
  return apply(getPref());
}
