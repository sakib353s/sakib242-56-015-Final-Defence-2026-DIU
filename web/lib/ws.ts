"use client";

import { useEffect, useRef, useState } from "react";
import { WS_BASE } from "./api";
import type { WsEnvelope } from "./types";

export type WsStatus = "live" | "connecting" | "down";

export function useCwbSocket(
  channel: "alerts" | "jobs",
  onEnvelope: (env: WsEnvelope) => void,
  enabled = true,
): WsStatus {
  const [status, setStatus] = useState<WsStatus>(enabled ? "connecting" : "down");
  const handler = useRef(onEnvelope);
  handler.current = onEnvelope;

  useEffect(() => {
    if (!enabled) {
      setStatus("down");
      return;
    }
    let ws: WebSocket | null = null;
    let timer: number | undefined;
    let retry: number | undefined;
    let closed = false;

    const connect = () => {
      if (closed) return;
      setStatus("connecting");
      try {
        ws = new WebSocket(`${WS_BASE}/ws/${channel}`);
      } catch {
        setStatus("down");
        return;
      }
      ws.onopen = () => {
        setStatus("live");
        timer = window.setInterval(() => {
          if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ ping: Date.now() }));
        }, 25000);
      };
      ws.onmessage = (ev) => {
        try {
          const env = JSON.parse(ev.data as string) as WsEnvelope;
          handler.current(env);
        } catch {
          // non-JSON frames are ignored — envelope contract is JSON
        }
      };
      ws.onclose = () => {
        if (timer !== undefined) window.clearInterval(timer);
        setStatus("down");
        if (!closed) retry = window.setTimeout(connect, 4000);
      };
      ws.onerror = () => ws?.close();
    };
    connect();
    return () => {
      closed = true;
      if (timer !== undefined) window.clearInterval(timer);
      if (retry !== undefined) window.clearTimeout(retry);
      ws?.close();
    };
  }, [channel, enabled]);

  return status;
}
