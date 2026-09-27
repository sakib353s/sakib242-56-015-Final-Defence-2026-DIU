"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch, toProblem } from "@/lib/api";
import { getToken } from "@/lib/auth";
import { EGG, NICE_BANNER, recode, renderBootLine, setBootTheme, xtermTheme } from "@/lib/bootline";
import { THEME_EVENT, current } from "@/lib/theme";
import { ThemeToggle } from "@/components/theme";
import type { BootLine, BootToken } from "@/lib/types";
import { clock } from "@/lib/format";
import { Leader, LoaderRows } from "@/components/ui";
import type { Terminal as TermType } from "@xterm/xterm";
import type { FitAddon as FitType } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

type Phase = "arm" | "streaming" | "frozen" | "gate";

export default function BootPage() {
  const router = useRouter();
  const [mounted, setMounted] = useState(false);
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<TermType | null>(null);
  const fitRef = useRef<FitType | null>(null);
  const queueRef = useRef<string[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const runGen = useRef(0);
  const eggRef = useRef("");
  const instantRef = useRef(false);

  const [phase, setPhase] = useState<Phase>("arm");
  const [frozen, setFrozen] = useState<BootLine | null>(null);
  const [tokenOk, setTokenOk] = useState(false);
  const [wsOk, setWsOk] = useState(false);
  const [lastLine, setLastLine] = useState<BootLine | null>(null);
  const [lineCount, setLineCount] = useState(0);
  const [instant, setInstant] = useState(false);
  const [t0] = useState(() => Date.now());
  const [, setPulse] = useState(0);
  const [already, setAlready] = useState(false);

  instantRef.current = instant;

  const write = useCallback((s: string) => {
    termRef.current?.write(s);
  }, []);

  const replayBanner = useCallback(() => {
    write("\r\n");
    for (const b of NICE_BANNER) write(recode(b) + "\r\n");
    write("\r\n\x1b[38;2;14;138;163m[ easter egg ] nice.\x1b[0m\r\n\r\n");
  }, [write]);

  const start = useCallback(async () => {
    // generation token: handlers of the PREVIOUS socket fire their onclose
    // asynchronously after RE-ARM started and used to re-freeze the fresh run
    const gen = ++runGen.current;
    setPhase("arm");
    setFrozen(null);
    setTokenOk(false);
    setWsOk(false);
    setLineCount(0);
    setLastLine(null);
    wsRef.current?.close();
    write("\r\n\x1b[38;2;82;96;121m──── re-arming boot runner ────\x1b[0m\r\n");
    let tok: BootToken;
    try {
      tok = await apiFetch<BootToken>("/boot/token", { method: "POST" });
    } catch (e) {
      setFrozen({ seq: 0, ts: "0000.000", label: "boot token issuance failed", status: "FAIL", detail: toProblem(e).detail });
      setPhase("frozen");
      return;
    }
    setTokenOk(true);
    write(`\x1b[38;2;82;96;121m[boot] single-use token acquired (ttl ${tok.ttl_s}s) → /ws/boot\x1b[0m\r\n`);
    const base = (process.env.NEXT_PUBLIC_WS_BASE || "ws://127.0.0.1:8471").replace(/\/$/, "");
    if (runGen.current !== gen) return; // a newer re-arm superseded this one during the token fetch
    const ws = new WebSocket(`${base}/ws/boot?token=${encodeURIComponent(tok.boot_token)}`);
    wsRef.current = ws;
    setPhase("streaming");
    ws.onopen = () => setWsOk(true);
    ws.onmessage = (ev) => {
      if (runGen.current !== gen) return;
      let line: BootLine;
      try {
        line = JSON.parse(ev.data as string) as BootLine;
      } catch {
        return;
      }
      setLastLine(line);
      setLineCount((n) => n + 1);
      const rendered = renderBootLine(line);
      if (instantRef.current) write(rendered);
      else queueRef.current.push(rendered);
      if (line.status === "FAIL") {
        setFrozen(line);
        setPhase("frozen");
      } else {
        const plain = line.label.replace(/\x1b\[[0-9;]*m/g, "");
        if (plain.startsWith("READY") && plain.includes("attestation complete")) {
          setPhase("gate");
        }
      }
    };
    ws.onclose = () => {
      if (runGen.current !== gen) return;
      setWsOk(false);
      setPhase((p) => (p === "gate" ? p : p === "frozen" ? p : "frozen"));
      setFrozen((f) =>
        f ?? { seq: lineCount, ts: "9999.999", label: "boot transport closed before attestation complete", status: "FAIL", detail: "runner halted or token spent — re-arm" },
      );
    };
    ws.onerror = () => ws.close();
  }, [write, lineCount]);

  /* terminal bootstrap (client-only, dynamic import of xterm) */
  useEffect(() => {
    let disposed = false;
    let ro: ResizeObserver | null = null;
    (async () => {
      const [{ Terminal }, { FitAddon }, webglMod] = await Promise.all([
        import("@xterm/xterm"),
        import("@xterm/addon-fit"),
        import("@xterm/addon-webgl").catch(() => null),
      ]);
      if (disposed || !hostRef.current) return;
      const fam =
        getComputedStyle(document.documentElement).getPropertyValue("--font-jetbrains").trim() || "monospace";
      const term = new Terminal({
        cursorBlink: true,
        disableStdin: false,
        convertEol: true, // RAW boot lines carry multi-line box-drawing with bare \n
        scrollback: 5000,
        fontSize: 16,
        fontFamily: `${fam}, monospace`,
        minimumContrastRatio: 5,
        theme: xtermTheme(current()),
      });
      setBootTheme(current());
      const fit = new FitAddon();
      term.loadAddon(fit);
      if (webglMod) {
        try {
          term.loadAddon(new webglMod.WebglAddon());
        } catch {
          /* fall back to canvas/DOM renderer */
        }
      }
      term.open(hostRef.current);
      fit.fit();
      termRef.current = term;
      fitRef.current = fit;
      ro = new ResizeObserver(() => {
        try {
          fit.fit();
        } catch {
          // ignore mid-teardown resize
        }
      });
      ro.observe(hostRef.current);
      term.writeln("\x1b[38;2;82;96;121mterminal armed. awaiting boot runner…\x1b[0m");
      void start();
    })();
    return () => {
      disposed = true;
      ro?.disconnect();
      wsRef.current?.close();
      termRef.current?.dispose();
      termRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* paced renderer */
  useEffect(() => {
    const t = window.setInterval(() => {
      if (instantRef.current) return;
      const lines = queueRef.current.splice(0, queueRef.current.length);
      for (const l of lines) write(l);
    }, 24);
    return () => window.clearInterval(t);
  }, [write]);

  /* reduced motion → instant mode default */
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) setInstant(true);
    setAlready(!!getToken());
    setMounted(true);
    const pulse = window.setInterval(() => setPulse((n) => n + 1), 1000);
    return () => window.clearInterval(pulse);
  }, []);

  /* live theme swap: re-color xterm + re-attest so the log matches the palette */
  useEffect(() => {
    const onTheme = (e: Event) => {
      const t = (e as CustomEvent<"dark" | "light">).detail;
      setBootTheme(t);
      const term = termRef.current;
      if (term) term.options.theme = xtermTheme(t);
      void start(); // fresh attestation stream rendered in the new palette
    };
    window.addEventListener(THEME_EVENT, onTheme);
    return () => window.removeEventListener(THEME_EVENT, onTheme);
  }, [start]);

  /* easter egg: typed sequence replays the banner */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.length !== 1) return;
      eggRef.current = (eggRef.current + e.key).slice(-EGG.length);
      if (eggRef.current === EGG) {
        eggRef.current = "";
        replayBanner();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [replayBanner]);

  /* S8 hand-off: boot page is attestation only → dedicated /login page */
  useEffect(() => {
    if (phase !== "gate") return;
    const t = window.setTimeout(() => router.replace(already ? "/dashboard" : "/login"), 1800);
    return () => window.clearTimeout(t);
  }, [phase, already, router]);

  const elapsed = useMemo(() => {
    const s = Math.floor((Date.now() - t0) / 1000);
    return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  }, [t0, lastLine, lineCount]);

  return (
    <div className="boot-wrap">
      <div className="boot-top">
        <span>CYBERWATCH-BD — SECURITY ATTESTATION INSTRUMENT</span>
        <span style={{ marginLeft: "auto" }}>
          {mounted ? clock() : "··:··:··"} · elapsed {mounted ? elapsed : "··:··"} · lines {mounted ? lineCount : 0} ·{" "}
          {mounted && lastLine ? `seq ${lastLine.seq}/${lastLine.status}` : "seq ·"}
        </span>
        <button type="button" className="btn small" onClick={() => setInstant((v) => !v)} aria-pressed={instant}>
          MOTION: {instant ? "INSTANT" : "PACED"}
        </button>
        <button type="button" className="btn small" onClick={() => void start()}>
          [ RE-ARM ]
        </button>
        <ThemeToggle />
      </div>
      <div className="boot-stage">
        <div className="boot-termwrap">
          <div ref={hostRef} className="boot-term" aria-label="boot terminal" />
        </div>
        <aside className="boot-side">
          {already && phase !== "frozen" ? (
            <div style={{ marginBottom: 16 }}>
              <Leader label="session found" value="resume →" tone="info" />
              <button type="button" className="btn primary" style={{ marginTop: 8 }} onClick={() => router.replace("/dashboard")}>
                [ CONTINUE TO CONSOLE ]
              </button>
            </div>
          ) : null}

          {phase === "frozen" && frozen ? (
            <div className="boot-freeze" role="alert">
              <div className="bt">[ FAIL ] BOOT FROZEN — fail-closed halt</div>
              <div className="bd">{frozen.label}</div>
              <div className="bd" style={{ color: "var(--dim)" }}>
                {frozen.detail}
              </div>
              {/transport|token/.test(frozen.label + frozen.detail) ? (
                <div className="bd" style={{ color: "var(--dim)", fontSize: 10.5 }}>
                  if served from a non-default dev port, the backend WS origin allow-list
                  (CWB_CORS_ORIGINS, default: http://localhost:3000) refused /ws/boot — add this
                  origin there and re-arm
                </div>
              ) : null}
              <button type="button" className="btn danger" style={{ marginTop: 12 }} onClick={() => void start()}>
                [ RETRY · NEW BOOT TOKEN ]
              </button>
            </div>
          ) : null}

          <div className="gate-title">RUNNER STATUS</div>
          <LoaderRowsOnce done={tokenOk} label="POST /boot/token" />
          <LoaderRowsOnce done={wsOk} label="WS /ws/boot handshake" />
          <LoaderRowsOnce done={phase === "gate" || phase === "frozen"} label="S1…S8 attestation stream" />
          <LoaderRowsOnce done={phase === "gate"} label="SESSION minted → audit log" />

          {phase === "gate" ? (
            <div style={{ marginTop: 20 }}>
              <div className="gate-title">ATTESTATION COMPLETE</div>
              <div className="page-note">
                handing off to the authentication page ···
              </div>
            </div>
          ) : phase !== "frozen" ? (
            <LoaderRows lines={["awaiting S8 session mint", "auth gate sealed until attestation passes"]} />
          ) : (
            <div className="page-note">
              remediation: resolve the FAIL condition on the host, then re-arm. the runner never
              bypasses S1–S6/S8 gates.
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function LoaderRowsOnce({ done, label }: { done: boolean; label: string }) {
  return (
    <div className="leader" style={{ marginBottom: 2 }}>
      <span className="val">{label}</span>
      <span className="dots" aria-hidden>{".".repeat(Math.max(1, 38 - label.length))}</span>
      <span className={`val ${done ? "ok" : "dim"}`}>{done ? "[ OK ]" : "[ ··· ]"}</span>
    </div>
  );
}
