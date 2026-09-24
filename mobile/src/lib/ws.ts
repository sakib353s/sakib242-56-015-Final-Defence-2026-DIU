/** /ws/alerts live tail with auto-reconnect (exponential 1s→60s) and keepalive
 *  pings the gateway reads to hold the socket open. Envelope shape per
 *  gateway/wsmanager: {channel, seq, ts, type, payload, hmac}. 'alert.new'
 *  payloads are server AlertRow objects and land in the SQLite mirror. */
import { WS_BASE } from '../config/env';
import { upsertAlerts } from './db';
import type { AlertRow, WsEnvelope } from '../types';

export type WsState = 'off' | 'connecting' | 'online' | 'backoff';

type EnvelopeListener = (env: WsEnvelope<unknown>) => void;
type StateListener = (state: WsState) => void;

const KEEPALIVE_MS = 20_000;
const MAX_BACKOFF_MS = 60_000;

class AlertsSocket {
  state: WsState = 'off';
  lastError = '';
  private sock: WebSocket | null = null;
  private envListeners = new Set<EnvelopeListener>();
  private stateListeners = new Set<StateListener>();
  private attempt = 0;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private closing = false;

  connect(): void {
    if (this.state === 'online' || this.state === 'connecting') return;
    this.teardown();
    this.closing = false;
    this.setState('connecting');
    try {
      this.sock = new WebSocket(`${WS_BASE}/ws/alerts`);
    } catch (e) {
      this.lastError = String(e);
      this.scheduleReconnect();
      return;
    }
    this.sock.onopen = (): void => {
      this.attempt = 0;
      this.setState('online');
      this.pingTimer = setInterval(() => {
        try {
          this.sock?.send('ping');
        } catch {
          /* onclose will follow */
        }
      }, KEEPALIVE_MS);
    };
    this.sock.onmessage = (ev: WebSocketMessageEvent): void => {
      let env: WsEnvelope<unknown>;
      try {
        env = JSON.parse(String(ev.data)) as WsEnvelope<unknown>;
      } catch {
        return;
      }
      if (env.type === 'alert.new') {
        const row = env.payload as AlertRow;
        if (row && typeof row.id === 'string') {
          try {
            upsertAlerts([row]);
          } catch (e) {
            this.lastError = `mirror write failed: ${String(e)}`;
          }
        }
      }
      for (const fn of this.envListeners) fn(env);
    };
    this.sock.onerror = (): void => {
      this.lastError = 'socket error';
    };
    this.sock.onclose = (): void => {
      if (this.closing) {
        this.setState('off');
        return;
      }
      this.scheduleReconnect();
    };
  }

  disconnect(): void {
    this.closing = true;
    this.teardown();
    this.setState('off');
  }

  subscribe(fn: EnvelopeListener): () => void {
    this.envListeners.add(fn);
    return () => this.envListeners.delete(fn);
  }

  onState(fn: StateListener): () => void {
    this.stateListeners.add(fn);
    fn(this.state);
    return () => this.stateListeners.delete(fn);
  }

  private scheduleReconnect(): void {
    this.teardown();
    const delay = Math.min(1_000 * 2 ** this.attempt, MAX_BACKOFF_MS);
    this.attempt += 1;
    this.setState('backoff');
    this.reconnectTimer = setTimeout(() => this.connect(), delay);
  }

  private teardown(): void {
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.sock) {
      const s = this.sock;
      this.sock = null;
      s.onopen = null;
      s.onmessage = null;
      s.onerror = null;
      s.onclose = null;
      try {
        s.close();
      } catch {
        /* already dead */
      }
    }
  }

  private setState(next: WsState): void {
    if (this.state === next) return;
    this.state = next;
    for (const fn of this.stateListeners) fn(next);
  }
}

export const alertsSocket = new AlertsSocket();
