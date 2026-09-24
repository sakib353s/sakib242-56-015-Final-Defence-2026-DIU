"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { getRole } from "@/lib/auth";
import { visibleGroups, type NavGroup, type NavItem } from "@/lib/rbac";
import { Icon } from "./icons";
import { useMounted } from "./ui";

interface Row {
  item: NavItem;
  group: NavGroup;
}

function matches(row: Row, q: string) {
  if (!q) return true;
  const hay = `${row.item.label} ${row.item.desc} ${row.group.label} ${row.item.href}`.toLowerCase();
  return q.toLowerCase().split(/\s+/).every((part) => hay.includes(part));
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const router = useRouter();
  const mounted = useMounted();
  const [q, setQ] = useState("");
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const rows = useMemo<Row[]>(() => {
    const groups = visibleGroups(mounted ? getRole() : null);
    return groups.flatMap((g) => g.items.map((item) => ({ item, group: g })));
  }, [mounted]);

  const shown = useMemo(() => rows.filter((r) => matches(r, q)).slice(0, 40), [rows, q]);

  useEffect(() => {
    if (!open) return;
    setQ("");
    setCursor(0);
    inputRef.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setCursor((c) => Math.min(c + 1, Math.max(shown.length - 1, 0)));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setCursor((c) => Math.max(c - 1, 0));
      } else if (e.key === "Enter") {
        const row = shown[cursor];
        if (row) {
          e.preventDefault();
          onClose();
          router.push(row.item.href);
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, shown, cursor, onClose, router]);

  if (!open) return null;

  return (
    <div className="palette" role="presentation" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="palette-box" role="dialog" aria-modal="true" aria-label="go to a page">
        <div className="palette-input">
          <Icon name="search" size={16} />
          <input
            ref={inputRef}
            value={q}
            placeholder="Go to a page…"
            onChange={(e) => {
              setQ(e.target.value);
              setCursor(0);
            }}
            aria-label="search pages"
          />
          <span className="kbd">esc</span>
        </div>
        <div className="palette-list">
          {shown.length === 0 ? (
            <div className="context-empty">No page matches “{q}”.</div>
          ) : (
            shown.map((r, i) => (
              <button
                type="button"
                key={r.item.href}
                className={`palette-row${i === cursor ? " on" : ""}`}
                onMouseEnter={() => setCursor(i)}
                onClick={() => {
                  onClose();
                  router.push(r.item.href);
                }}
              >
                <Icon name={r.item.icon} size={16} />
                <span className="label">{r.item.label}</span>
                <span className="group">{r.group.label}</span>
              </button>
            ))
          )}
        </div>
        <div className="palette-foot">
          <span>↑ ↓ to move</span>
          <span>↵ to open</span>
          <span>esc to dismiss</span>
        </div>
      </div>
    </div>
  );
}
