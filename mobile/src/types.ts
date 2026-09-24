/** Server row shapes (gateway REST + WS envelopes, SQLite-mirrored records). */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;

export interface AlertRow {
  id: string;
  source: string;
  signature: string;
  category: string | null;
  severity: Severity;
  src_ip: string | null;
  dest_ip: string | null;
  mitre: string | null;
  status: string; // new | acked
  ts: string;
  raw_json: string;
  ack_by: string | null;
  ack_at: string | null;
}

export type OutboxStatus = 'pending' | 'synced' | 'failed';

export interface AlertView extends AlertRow {
  /** sync badge derived from the outbox entry targeting this alert */
  sync: OutboxStatus | 'clean';
}

export interface OutboxRow {
  id: number;
  idempotency_key: string;
  endpoint: string;
  method: string;
  body_json: string;
  retry_count: number;
  next_attempt_at: string;
  status: OutboxStatus;
  created_at: string;
  synced_at: string | null;
  last_error: string | null;
}

export interface ModuleHealth {
  module: string;
  display: string;
  status: 'OK' | 'WARN' | 'FAIL' | string;
  detail: string;
}

export interface Warrant {
  id: string;
  kind: string;
  scope_json: string;
  purpose: string;
  warrant_ref: string;
  subject_name: string | null;
  valid_from: string;
  valid_until: string;
  revoked_at: string | null;
  created_at: string;
}

export interface PentestSession {
  id: string;
  warrant_id: string;
  target: string;
  status: string; // CREATED|RUNNING|COMPLETE|ABORTED
  phase: string; // recon|scan|exploit|post|report
  progress: number;
  findings_count: number;
  created_by: string;
  bound_session: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  aborted_reason: string | null;
  report_path: string | null;
}

export interface Finding {
  id: string;
  source: string;
  source_id: string;
  host: string;
  port: number | null;
  service: string | null;
  cve: string | null;
  severity: Severity;
  cvss: number | null;
  mitre: string | null;
  description: string;
  created_at: string;
}

export interface CaseSummary {
  id: string;
  case_type: string;
  status: string;
  created_at: string;
}

export interface TimelineEvent {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  evidence_ref: string;
  hash: string;
}

export interface CaseDetail {
  case: { id: string; case_type: string; narrative: string; status: string; created_at: string };
  complainant: Record<string, unknown>;
  timeline: TimelineEvent[];
}

export interface ComplaintLink {
  agency: string;
  report_id: string;
  name: string;
  created_at: string;
  download: string;
}

export interface WsEnvelope<T = Record<string, unknown>> {
  channel: string;
  seq: number;
  ts: string;
  type: string;
  payload: T;
  hmac: string;
}

export interface Principal {
  userId: string;
  username: string;
  role: string;
}
