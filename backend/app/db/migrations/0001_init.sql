-- CYBERWATCH-BD migration 0001 — initial schema (SQLite, WAL)
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('SUPER_ADMIN','ANALYST','READ_ONLY')),
  password_hash TEXT NOT NULL, totp_secret_enc TEXT, totp_enrolled INTEGER DEFAULT 0,
  failed_logins INTEGER DEFAULT 0, locked_until TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
  refresh_hash TEXT NOT NULL, created_at TEXT NOT NULL, last_seen TEXT NOT NULL,
  revoked_at TEXT, user_agent TEXT, ip TEXT
);
CREATE TABLE IF NOT EXISTS auth_ledger (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('pentest','vuln_scan','remediation','ipanon')),
  scope_json TEXT NOT NULL, purpose TEXT NOT NULL, warrant_ref TEXT NOT NULL,
  owner_user_id TEXT NOT NULL REFERENCES users(id), subject_name TEXT,
  valid_from TEXT NOT NULL, valid_until TEXT NOT NULL, revoked_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pentest_sessions (
  id TEXT PRIMARY KEY, warrant_id TEXT NOT NULL REFERENCES auth_ledger(id),
  target TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'CREATED',
  phase TEXT NOT NULL DEFAULT 'recon', progress REAL DEFAULT 0,
  findings_count INTEGER DEFAULT 0, created_by TEXT NOT NULL REFERENCES users(id),
  bound_session TEXT NOT NULL, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  aborted_reason TEXT, report_path TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, source_id TEXT NOT NULL,
  host TEXT NOT NULL, port INTEGER, service TEXT, cve TEXT, severity TEXT NOT NULL,
  cvss REAL, mitre TEXT, description TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vuln_scans (
  id TEXT PRIMARY KEY, warrant_id TEXT NOT NULL REFERENCES auth_ledger(id),
  target TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING', risk_score REAL,
  findings_count INTEGER DEFAULT 0, created_by TEXT NOT NULL REFERENCES users(id),
  bound_session TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT, report_path TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, signature TEXT NOT NULL, category TEXT,
  severity TEXT NOT NULL, src_ip TEXT, dest_ip TEXT, mitre TEXT,
  status TEXT NOT NULL DEFAULT 'new', ts TEXT NOT NULL, raw_json TEXT NOT NULL,
  ack_by TEXT, ack_at TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, alert_ref TEXT, playbook TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  payload_json TEXT NOT NULL, opened_at TEXT NOT NULL, closed_at TEXT
);
CREATE TABLE IF NOT EXISTS ip_blocks (
  id TEXT PRIMARY KEY, ip TEXT NOT NULL, rule TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
  deployed_via TEXT, expires_at TEXT, unblocked_at TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS osint_cases (
  id TEXT PRIMARY KEY, subject_type TEXT NOT NULL CHECK (subject_type IN ('email','domain','url','profile')),
  subject_hash TEXT NOT NULL, result_json TEXT NOT NULL, source TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leak_watch (
  id TEXT PRIMARY KEY, query_hash TEXT NOT NULL, source TEXT NOT NULL,
  hit_json TEXT, checked_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS docfingerprints (
  id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL REFERENCES users(id),
  filename TEXT NOT NULL, sha256 TEXT NOT NULL, md5 TEXT NOT NULL, watermark_id TEXT NOT NULL,
  size INTEGER NOT NULL, mime TEXT NOT NULL, stored_path TEXT NOT NULL,
  ownership_attested INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS crawlresults (
  id TEXT PRIMARY KEY, doc_id TEXT NOT NULL REFERENCES docfingerprints(id),
  url TEXT NOT NULL, snapshot_sha256 TEXT, verdict TEXT NOT NULL DEFAULT 'pending',
  detail TEXT, found_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS victim_cases (
  id TEXT PRIMARY KEY, case_type TEXT NOT NULL CHECK (case_type IN ('fraud','harassment','leak','other')),
  complainant_json_enc TEXT NOT NULL, narrative TEXT NOT NULL,
  consent_attested INTEGER NOT NULL, consent_doc_id TEXT,
  status TEXT NOT NULL DEFAULT 'OPEN', created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS victim_timeline (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES victim_cases(id),
  seq INTEGER NOT NULL, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  evidence_ref TEXT, payload_hash TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL,
  UNIQUE (case_id, seq)
);
CREATE TABLE IF NOT EXISTS remediation_jobs (
  id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id),
  host TEXT NOT NULL, asset_id TEXT, warrant_id TEXT NOT NULL REFERENCES auth_ledger(id),
  state TEXT NOT NULL DEFAULT 'DRAFT', script TEXT NOT NULL, diff_json TEXT NOT NULL,
  consent_json TEXT, apply_log TEXT, verify_result TEXT, snapshot_ref TEXT,
  created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hw_assets (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, host TEXT NOT NULL,
  ssh_port INTEGER DEFAULT 22, ssh_user TEXT, ssh_pass_enc TEXT, snmp_community_enc TEXT,
  ownership_attested INTEGER NOT NULL, disabled INTEGER DEFAULT 0, failed_checks INTEGER DEFAULT 0,
  tags TEXT DEFAULT '[]', last_check_json TEXT, last_check_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, ref_id TEXT, status TEXT NOT NULL DEFAULT 'queued',
  progress REAL DEFAULT 0, message TEXT, payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL, ts_ms INTEGER NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, object_ref TEXT NOT NULL,
  payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL, prev_hash TEXT NOT NULL,
  hmac TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS boot_tokens (
  token TEXT PRIMARY KEY, created_at TEXT NOT NULL, used_at TEXT
);
CREATE TABLE IF NOT EXISTS report_files (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL,
  kind TEXT NOT NULL, ref_id TEXT, created_by TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS event_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL, ts TEXT NOT NULL,
  type TEXT NOT NULL, payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS circuits (
  id TEXT PRIMARY KEY, session_warrant_id TEXT NOT NULL REFERENCES auth_ledger(id),
  bound_session TEXT NOT NULL, masked_ip TEXT, status TEXT NOT NULL DEFAULT 'building',
  started_at TEXT NOT NULL, stopped_at TEXT, last_heartbeat TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_src ON findings(source, source_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts_ms);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_ledger_window ON auth_ledger(valid_from, valid_until);
