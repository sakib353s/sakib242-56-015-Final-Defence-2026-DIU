"use client";

/* Bottom status bar: the latest audited action, the newest advisory, and whether
   those readings are live. Real feed and real WebSocket — no decorative motion. */

import { useQuery } from "@tanstack/react-query";
import { get } from "@/lib/api";
import { clock, fmtTs, humanAction, trunc } from "@/lib/format";
import { useWsHub, type StreamEvent } from "./chrome";

interface FeedItem {
  source: string;
  title: string;
  link: string;
  published: string;
}

interface Feed {
  source: string;
  items: FeedItem[];
  error: string | null;
}

export const useThreatFeed = () =>
  useQuery({
    queryKey: ["threatfeed"],
    queryFn: () => get<Feed>("/system/threatfeed"),
    staleTime: 600_000,
    refetchInterval: 900_000,
    refetchOnWindowFocus: false,
  });

const isSensitive = (e: StreamEvent) => e.action.includes("fail") || e.action.includes("block");

export function StatusActivity() {
  const hub = useWsHub();
  const feed = useThreatFeed();
  const events = hub.events ?? [];
  const last = events[events.length - 1];
  const top = feed.data?.items?.[0];

  return (
    <footer className="statusbar" aria-label="activity and advisories">
      <span className="sb-item" title={`${events.length} audited ${events.length === 1 ? "action" : "actions"} since sign-in`}>
        <span className={`sb-dot ${events.length ? "live" : "connecting"}`} aria-hidden />
        <b>{events.length} {events.length === 1 ? "action" : "actions"} this session</b>
      </span>
      <span className="sb-sep" aria-hidden />
      {last ? (
        <span className={`sb-item ${isSensitive(last) ? "sb-hot" : ""}`} title={`${last.actor} · ${fmtTs(new Date(last.ts_ms).toISOString())}`}>
          {clock(new Date(last.ts_ms))} · {humanAction(last.action)} · {trunc(last.actor, 16)}
          {last.object_ref ? ` · ${trunc(last.object_ref, 26)}` : ""}
        </span>
      ) : (
        <span className="sb-item">No actions recorded yet</span>
      )}
      <span className="sb-sep" aria-hidden />
      {top ? (
        <a className="sb-item" href={top.link} target="_blank" rel="noreferrer noopener" title={`${top.title} · published ${fmtTs(top.published)}`}>
          <span className={feed.data?.source === "live" ? "sb-ok" : "sb-warn"}>{top.source}</span>
          <span className="sb-link">{trunc(top.title, 64)}</span>
        </a>
      ) : (
        <span className="sb-item">{feed.isPending ? "Loading advisories…" : "Advisories unavailable"}</span>
      )}
      <span className="sb-spacer" />
      <span className="sb-item">Actions require authorization</span>
      <span className="sb-sep" aria-hidden />
      <span className="sb-item">Audit-logged</span>
      <span className="sb-sep" aria-hidden />
      <span className="sb-item">Cyber Security Order 2025 · ICT Act 2006</span>
    </footer>
  );
}
