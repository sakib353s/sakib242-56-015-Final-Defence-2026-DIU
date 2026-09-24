"use client";

import { useEffect, useState } from "react";
import { THEME_EVENT, getPref, setPref, watchSystem, type Theme, type ThemePref } from "@/lib/theme";
import { Icon } from "./icons";

const NEXT: Record<ThemePref, ThemePref> = { dark: "light", light: "system", system: "dark" };
const LABEL: Record<ThemePref, string> = { dark: "Dark", light: "Light", system: "Auto" };
const ICON: Record<ThemePref, string> = { dark: "moon", light: "sun", system: "monitor" };

export function ThemeToggle({ className = "btn small", iconOnly = false }: { className?: string; iconOnly?: boolean }) {
  const [pref, setLocal] = useState<ThemePref>("dark");
  useEffect(() => {
    setLocal(getPref());
    const stop = watchSystem();
    const onTheme = () => setLocal(getPref());
    window.addEventListener(THEME_EVENT, onTheme);
    return () => {
      stop();
      window.removeEventListener(THEME_EVENT, onTheme);
    };
  }, []);
  return (
    <button
      type="button"
      className={className}
      aria-label={`appearance: ${LABEL[pref]} — click to change`}
      title={`Appearance: ${LABEL[pref]} · cycles Dark, Light, Auto`}
      onClick={() => setPref(NEXT[pref])}
    >
      <Icon name={ICON[pref]} size={15} />
      {iconOnly ? null : ` ${LABEL[pref]}`}
    </button>
  );
}

/** segmented control for /settings */
export function ThemeSelect() {
  const [pref, setLocal] = useState<ThemePref>("dark");
  const [now, setNow] = useState<Theme>("dark");
  useEffect(() => {
    setLocal(getPref());
    const stop = watchSystem();
    const onTheme = (e: Event) => setNow((e as CustomEvent<Theme>).detail);
    window.addEventListener(THEME_EVENT, onTheme);
    return () => {
      stop();
      window.removeEventListener(THEME_EVENT, onTheme);
    };
  }, []);
  return (
    <div className="tabs" role="radiogroup" aria-label="appearance">
      {(["dark", "light", "system"] as ThemePref[]).map((t) => (
        <button
          key={t}
          type="button"
          role="radio"
          aria-checked={pref === t}
          className={`tab${pref === t ? " on" : ""}`}
          onClick={() => setPref(t)}
        >
          {LABEL[t]}
        </button>
      ))}
      <span className="page-note" style={{ marginLeft: "auto", alignSelf: "center" }}>
        Currently showing {LABEL[now]} · saved on this device only
      </span>
    </div>
  );
}
