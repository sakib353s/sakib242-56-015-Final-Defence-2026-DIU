"use client";

/* v7 — light is the only theme: the toggle renders nothing and the settings
   control shows the single, fixed Light appearance. */

export function ThemeToggle(_props: { className?: string; iconOnly?: boolean }) {
  return null;
}

/** segmented control for /settings — single fixed option */
export function ThemeSelect() {
  return (
    <div className="tabs" role="radiogroup" aria-label="appearance">
      <button type="button" role="radio" aria-checked className="tab on">
        Light
      </button>
      <span className="page-note" style={{ marginLeft: "auto", alignSelf: "center" }}>
        Light is the only theme in this build
      </span>
    </div>
  );
}
