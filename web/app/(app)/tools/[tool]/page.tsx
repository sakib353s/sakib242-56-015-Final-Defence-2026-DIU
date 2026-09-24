"use client";
/* One tool per page, reached from the Tools section of the sidebar.
   Enter a target, run the tool, and review the results. Warrant, role and two-factor checks stay on the server. */
import { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMutation, useQuery } from "@tanstack/react-query";
import { get, post, toProblem } from "@/lib/api";
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
const COLS = ["item", "port", "service", "severity", "status", "title", "tech", "matched", "id", "param", "inject", "length", "words"];

export default function ToolPage() {
  const toast = useToast();
  const params = useParams<{ tool: string }>();
  const toolId = String(params?.tool ?? "");
  const [target, setTarget] = useState("");
  const [auth, setAuth] = useState(false);
  const [result, setResult] = useState<RunResult | null>(null);
  const [err, setErr] = useState("");

  const tools = useQuery({ queryKey: ["tools"], queryFn: () => get<{ tools: ToolInfo[] }>("/tools") });
  const vers = useQuery({ queryKey: ["tools", "status"], queryFn: () => get<{ versions: Record<string, string> }>("/tools/status") });
  const run = useMutation({
    mutationFn: (v: { tool: string; target: string }) =>
      post<RunResult>("/tools/run", { ...v, authorization_confirmed: auth }),
    onSuccess: (r) => {
      setResult(r);
      setErr("");
      toast.push({ tone: r.count ? "ok" : "warn", title: `${r.tool} finished`, text: `${r.count} results, exit code ${r.exit}` });
    },
    onError: (e) => {
      setResult(null);
      setErr(toProblem(e).detail || toProblem(e).message);
    },
  });

  const list = tools.data?.tools ?? [];
  const tool = list.find((t) => t.id === toolId);
  const busy = run.isPending;
  const shown = (result?.rows ?? []).slice(0, 120);
  const cols = COLS.filter((c) => shown.some((r) => r[c] !== undefined && r[c] !== ""));

  const fire = () => {
    if (tool && target.trim() && !busy && (!tool.active || auth)) run.mutate({ tool: tool.id, target: target.trim() });
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
                <p className="page-note">
                  Tools marked as active traffic need an approved vulnerability-scan authorization that
                  covers this target. The match is checked on the server, and every run is recorded in the
                  audit log.
                </p>
              ) : null}
            </>
          )}
          {err ? <ErrBanner error={err} /> : null}
        </Panel>
      </div>

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
