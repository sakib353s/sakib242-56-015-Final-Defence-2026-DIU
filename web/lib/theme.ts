export type ThemePref = "dark" | "light" | "system";
export type Theme = "dark" | "light";

/* v7 — the console ships ONE light theme. The dark/system vocabulary stays
   in the types so old stored values and component APIs don't break, but
   every resolver below always returns light. */

export function getPref(): ThemePref {
  return "light";
}

export function resolve(_pref: ThemePref): Theme {
  return "light";
}

export function current(): Theme {
  return "light";
}

export const THEME_EVENT = "cwb-theme";

export function apply(_pref: ThemePref): Theme {
  document.documentElement.dataset.theme = "light";
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", "#f5f7fb");
  window.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: "light" as Theme }));
  return "light";
}

export function setPref(_pref: ThemePref): Theme {
  return apply("light");
}

/** no-op: appearance no longer follows the OS */
export function watchSystem(): () => void {
  return () => {};
}

/** run once per page load (client) */
export function initTheme(): Theme {
  return apply("light");
}
