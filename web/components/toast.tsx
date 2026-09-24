"use client";

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import type { Tone } from "@/lib/types";

export interface Toast {
  id: number;
  tone: Tone;
  title: string;
  text: string;
}

interface ToastApi {
  push: (t: { tone?: Tone; title: string; text?: string }) => void;
}

const Ctx = createContext<ToastApi>({ push: () => undefined });

export function useToast(): ToastApi {
  return useContext(Ctx);
}

let nextId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);

  const push = useCallback((t: { tone?: Tone; title: string; text?: string }) => {
    const item: Toast = { id: nextId++, tone: t.tone ?? "info", title: t.title, text: t.text ?? "" };
    setItems((prev) => [...prev.slice(-5), item]);
    window.setTimeout(() => setItems((prev) => prev.filter((x) => x.id !== item.id)), 6500);
  }, []);

  const api = useMemo(() => ({ push }), [push]);

  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="toast-stack" aria-live={items.some((t) => t.tone === "fail") ? "assertive" : "polite"} aria-atomic="false">
        {items.map((t) => (
          <div key={t.id} className={`toast ${t.tone}`}>
            <div className="tt">
              [ {t.tone.toUpperCase()} ] {t.title}
            </div>
            {t.text ? <div>{t.text}</div> : null}
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}
