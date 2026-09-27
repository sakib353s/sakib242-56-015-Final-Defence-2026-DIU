"use client";
/* One tool per page, reached from the Tools section of the sidebar.
   Enter a target, run the tool, and review the results. Warrant, role and two-factor checks stay on the server. */
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { API_BASE, get, toProblem, tryRefresh } from "@/lib/api";
import { getToken } from "@/lib/auth";
import { Chip, EmptyRows, ErrBanner, Field, LoaderRows, Panel } from "@/components/ui";
import { useToast } from "@/components/toast";

interface ToolInfo {
  id: string;
  label: string;
  purpose: string;
  input: "domain" | "host" | "url";
  active: boolean;
  installed: boolean;
  size_mb?: number;
}
interface Row { [k: string]: string | number }
interface RunResult { tool: string; exit: number; count: number; rows: Row[]; raw_tail: string }

const PLACEHOLDER: Record<string, string> = {
  domain: "example.com",
  host: "127.0.0.1",
  url: "http://127.0.0.1:8471/",
};
const INPUT_LABEL: Record<string, string> = {
  domain: "domain name",
  host: "IP address or host",
  url: "URL",
};
const COLS = ["item", "port", "service", "severity", "status", "title", "tech", "matched", "matcher", "id", "param", "inject", "length", "words"];

type StreamEvent =
  | { k: "start"; tool: string; argv: string[]; timeout: number }
  | { k: "line"; v: string }
  | { k: "ping" }
  | { k: "result"; v: RunResult };

const MAX_LIVE_LINES = 3000;

export default function ToolPage() {
  const toast = useToast();
  const params = useParams<{ tool: string }>();
  const toolId = String(params?.tool ?? "");
  const [target, setTarget] = useState("");
  const [auth, setAuth] = useState(false);
  const [busy, setBusy] = useState(false);
  const [live, setLive] = useState<string[]>([]);
  const [result, setResult] = useState<RunResult | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const consoleRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    const el = consoleRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [live]);

  const tools = useQuery({ queryKey: ["tools"], queryFn: () => get<{ tools: ToolInfo[] }>("/tools") });
  const vers = useQuery({ queryKey: ["tools", "status"], queryFn: () => get<{ versions: Record<string, string> }>("/tools/status") });
  const cfg = useQuery({ queryKey: ["config"], queryFn: () => get<{ env: string; warrant_required: boolean }>("/config") });

  const list = tools.data?.tools ?? [];
  const tool = list.find((t) => t.id === toolId);
  const shown = (result?.rows ?? []).slice(0, 120);
  const cols = COLS.filter((c) => shown.some((r) => r[c] !== undefined && r[c] !== ""));

  const openStream = async (): Promise<Response> => {
    const headers: Record<string, string> = {
      "content-type": "application/json", accept: "text/event-stream",
    };
    const tok = getToken();
    if (tok) headers.authorization = `Bearer ${tok}`;
    const req = () => fetch(`${API_BASE}/tools/run/stream`, {
      method: "POST", credentials: "same-origin", headers,
      body: JSON.stringify({ tool: toolId, target: target.trim(), authorization_confirmed: auth }),
    });
    let res = await req();
    if (res.status === 401 && (await tryRefresh())) {
      const fresh = getToken();
      if (fresh) headers.authorization = `Bearer ${fresh}`;
      res = await req();
    }
    return res;
  };

  const fire = async () => {
    if (!tool || !target.trim() || busy || (tool.active && !auth)) return;
    setBusy(true);
    setLive([]);
    setResult(null);
    setErr("");
    try {
      const res = await openStream();
      if (!res.ok || !res.body) {
        const text = await res.text();
        let body: unknown = null;
        if (text) {
          try { body = JSON.parse(text); } catch { body = { title: `Non-JSON response (HTTP ${res.status})`, detail: text.slice(0, 300) }; }
        }
        throw toProblem(body);
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let cut = buf.indexOf("\n\n");
        while (cut >= 0) {
          const frame = buf.slice(0, cut);
          buf = buf.slice(cut + 2);
          cut = buf.indexOf("\n\n");
          const data = frame.split("\n").find((ln) => ln.startsWith("data: "));
          if (!data) continue;
          let ev: StreamEvent;
          try { ev = JSON.parse(data.slice(6)); } catch { continue; }
          if (ev.k === "line") setLive((prev) => [...prev.slice(-MAX_LIVE_LINES), ev.v]);
          else if (ev.k === "result") {
            setResult(ev.v);
            toast.push({ tone: ev.v.count ? "ok" : "warn", title: `${ev.v.tool} finished`, text: `${ev.v.count} results, exit code ${ev.v.exit}` });
          }
        }
      }
    } catch (e) {
      setResult(null);
      setErr(toProblem(e));
    } finally {
      setBusy(false);
    }
  };

  if (tools.isPending) {
    return (
      <div className="span-12">
        <LoaderRows lines={["Loading tool details"]} />
      </div>
    );
  }

  if (!tool) {
    return (
      <div className="span-12">
        <Panel title="Tool not found" tight>
          <EmptyRows what={`No tool named '${toolId}' is available`} />
          <div style={{ padding: 12 }}>
            <Link href="/tools" className="btn small">Back to tools</Link>
          </div>
        </Panel>
      </div>
    );
  }

  return (
    <>
      <div className="span-12">
        <Panel
          title={`Run ${tool.label}`}
          actions={
            <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <span className="watermark-note">Runs locally · authorization checked · logged</span>
              <Chip tone={tool.active ? "warn" : "ok"} label={tool.active ? "Sends traffic" : "Passive"} />
              <Link href="/tools" className="btn small">All tools</Link>
            </span>
          }
        >
          <div className="page-note" style={{ marginBottom: 10 }}>
            {tool.purpose} · version <span className="cell-id">{vers.data?.versions[tool.id] ?? "checking…"}</span>
            {tool.size_mb ? ` · about ${tool.size_mb} MB on disk` : ""}
          </div>
          {!tool.installed ? (
            <ErrBanner error={`${tool.label} is not installed on this server. Ask an administrator to install the tool bundle before running it.`} />
          ) : (
            <>
              <div className="runrow">
                <div style={{ flex: 1, minWidth: 240 }}>
                  <Field label={`Target (${INPUT_LABEL[tool.input] ?? tool.input})`}>
                    <input
                      className="text"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && fire()}
                      placeholder={PLACEHOLDER[tool.input]}
                      maxLength={2048}
                      autoFocus
                    />
                  </Field>
                </div>
                {tool.active ? (
                  <label className="checkline">
                    <input type="checkbox" checked={auth} onChange={(e) => setAuth(e.target.checked)} />
                    <span>I confirm an approved authorization covers this target</span>
                  </label>
                ) : null}
                <button type="button" className="btn primary" disabled={!target.trim() || busy || (tool.active && !auth)} onClick={fire}>
                  {busy ? `Running ${tool.label}…` : `Run ${tool.label}`}
                </button>
              </div>
              {tool.active ? (
                cfg.data && !cfg.data.warrant_required ? (
                  <p className="page-note">
                    Lab mode: warrant enforcement is relaxed (CWB_WARRANT_ENFORCE=auto/off) — your
                    confirmation above authorizes the run and the skip is recorded in the audit log.
                    Production always requires a live warrant from the{" "}
                    <Link href="/ledger">Authorization Ledger</Link>.
                  </p>
                ) : (
                  <p className="page-note">
                    Tools marked as active traffic need an approved vulnerability-scan authorization that
                    covers this target. The match is checked on the server, and every run is recorded in
                    the audit log. An administrator issues warrants on the{" "}
                    <Link href="/ledger">Authorization Ledger</Link> page — until one covers this target,
                    this tool will be refused with a 403.
                  </p>
                )
              ) : null}
            </>
          )}
          {err ? <ErrBanner error={err} /> : null}
        </Panel>
      </div>

      {busy || live.length ? (
        <div className="span-12">
          <Panel
            title={busy ? "Live output" : "Live output (finished)"}
            actions={busy ? <Chip tone="info" label="streaming" /> : null}
          >
            <pre ref={consoleRef} className="mono-dim" style={{ maxHeight: 400, overflowY: "auto", margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {live.length ? live.join("\n") : "Waiting for the tool to speak…"}
            </pre>
          </Panel>
        </div>
      ) : null}

      {result ? (
        <div className="span-12">
          <Panel title={`${result.count} results, exit code ${result.exit}`}>
            {shown.length ? (
              <table className="dtable">
                <thead>
                  <tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr>
                </thead>
                <tbody>
                  {shown.map((r, i) => (
                    <tr key={i}>{cols.map((c) => <td key={c}>{String(r[c] ?? "")}</td>)}</tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="page-note">The tool finished successfully and returned no results.</p>
            )}
            <details style={{ marginTop: 10 }}>
              <summary>Raw output</summary>
              <pre className="mono-dim">{result.raw_tail}</pre>
            </details>
          </Panel>
        </div>
      ) : null}
    </>
  );
}
