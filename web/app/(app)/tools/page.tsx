"use client";
/* Tool index. Each installed tool has its own page under the Tools section. */
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { get } from "@/lib/api";
import { Chip, LoaderRows, Panel } from "@/components/ui";

interface ToolInfo {
  id: string;
  label: string;
  purpose: string;
  input: "domain" | "host" | "url";
  active: boolean;
  installed: boolean;
  size_mb?: number;
}

export default function ToolsPage() {
  const tools = useQuery({ queryKey: ["tools"], queryFn: () => get<{ tools: ToolInfo[] }>("/tools") });
  const vers = useQuery({ queryKey: ["tools", "status"], queryFn: () => get<{ versions: Record<string, string> }>("/tools/status") });

  const list = tools.data?.tools ?? [];
  const installed = list.filter((t) => t.installed).length;

  return (
    <>
      <div className="span-12">
        <Panel
          title="Tool library"
          actions={
            tools.isPending ? (
              undefined
            ) : (
              <span style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <span className="watermark-note">Runs locally · authorization checked · logged</span>
                <span className="page-note">
                  {installed} of {list.length} installed
                </span>
              </span>
            )
          }
        >
          {tools.isPending ? (
            <LoaderRows lines={["Loading the tool list"]} />
          ) : (
            <div className="tiles">
              {list.map((t) => {
                const version = vers.data?.versions[t.id];
                return (
                  <Link key={t.id} href={`/tools/${t.id}`} className="tile" style={{ opacity: t.installed ? 1 : 0.6 }}>
                    <div className="name">{t.label}</div>
                    <div className="detail">{t.purpose}</div>
                    <div className="st">
                      {t.installed ? (
                        <Chip tone={t.active ? "warn" : "ok"} label={t.active ? "Sends traffic" : "Passive"} />
                      ) : (
                        <Chip tone="muted" label="Not installed" />
                      )}
                      <span className="tile-meta">
                        {t.installed ? (version ?? "checking version…") : "not installed"}
                      </span>
                    </div>
                  </Link>
                );
              })}
            </div>
          )}
          <p className="page-note" style={{ marginTop: 12 }}>
            Each tool opens its own page with a single target field, a run button, and the results below.
            Tools marked &quot;sends traffic&quot; need an approved authorization covering that target.
            The check runs on the server, and every execution is recorded in the audit log.
          </p>
        </Panel>
      </div>
    </>
  );
}
