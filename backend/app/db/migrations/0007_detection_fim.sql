-- CYBERWATCH-BD migration 0007 — SOC detection rules engine + File Integrity Monitoring

CREATE TABLE IF NOT EXISTS detection_rules (
  id TEXT PRIMARY KEY,
  rule_key TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  name TEXT NOT NULL,
  description TEXT,
  source TEXT NOT NULL CHECK (source IN ('suricata','fim','assessment','any')),
  matcher_json TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
  confidence REAL NOT NULL DEFAULT 0.6,
  correlate_json TEXT,
  suppress_json TEXT,
  mitre TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (rule_key, version)
);

CREATE TABLE IF NOT EXISTS fim_policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  path TEXT NOT NULL,
  recursive INTEGER NOT NULL DEFAULT 1,
  max_depth INTEGER NOT NULL DEFAULT 4,
  max_files INTEGER NOT NULL DEFAULT 5000,
  exclude_globs_json TEXT NOT NULL DEFAULT '[]',
  interval_s INTEGER NOT NULL DEFAULT 300,
  severity TEXT NOT NULL DEFAULT 'medium',
  enabled INTEGER NOT NULL DEFAULT 1,
  baseline_ready INTEGER NOT NULL DEFAULT 0,
  files_baseline INTEGER DEFAULT 0,
  last_scan_at TEXT,
  last_scan_status TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fim_baseline (
  id TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL REFERENCES fim_policies(id),
  file_path TEXT NOT NULL,
  sha256 TEXT,
  size INTEGER,
  mode INTEGER,
  uid INTEGER,
  gid INTEGER,
  mtime_ns INTEGER,
  last_seen_at TEXT NOT NULL,
  UNIQUE (policy_id, file_path)
);

CREATE TABLE IF NOT EXISTS fim_events (
  id TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL REFERENCES fim_policies(id),
  event_type TEXT NOT NULL CHECK (event_type IN
    ('create','modify','delete','rename','permission_change','ownership_change','hash_change')),
  file_path TEXT NOT NULL,
  prev_path TEXT,
  old_sha256 TEXT,
  new_sha256 TEXT,
  old_size INTEGER,
  new_size INTEGER,
  old_mode INTEGER,
  new_mode INTEGER,
  old_uid INTEGER,
  new_uid INTEGER,
  alert_id TEXT,
  detected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fim_ev_ts ON fim_events(detected_at);
CREATE INDEX IF NOT EXISTS idx_det_enabled ON detection_rules(enabled, source);

INSERT OR IGNORE INTO detection_rules
  (id, rule_key, version, name, description, source, matcher_json, severity, confidence,
   correlate_json, mitre, enabled, created_by, created_at, updated_at)
VALUES
  ('00000000-0000-7000-8000-00000000r001','scan-signature',1,
   'Recurring network scan signature','Same scanner repeating a scan-class Suricata alert','suricata',
   '{"signature_regex":"(scan|recon|probe|nmap|masscan)","src_ip_required":true}','medium',0.7,
   '{"key":"src_ip","window_s":300,"min_count":5,"escalate":"incident"}',
   'T1595',1,'system:seed',datetime('now'),datetime('now')),
  ('00000000-0000-7000-8000-00000000r002','critical-eve',1,
   'Critical IDS alert (EV1)','Any Suricata alert already rated CRITICAL','suricata',
   '{"severity":["CRITICAL"]}','critical',0.85,NULL,NULL,1,'system:seed',datetime('now'),datetime('now')),
  ('00000000-0000-7000-8000-00000000r003','fim-baseline-change',1,
   'Protected file modified or created','FIM baseline detected create/modify/hash change','fim',
   '{"event_type":["create","modify","hash_change"]}','medium',0.9,
   '{"key":"file_path","window_s":600,"min_count":3,"escalate":"incident"}',
   'T1565',1,'system:seed',datetime('now'),datetime('now')),
  ('00000000-0000-7000-8000-00000000r004','fim-permission-ownership',1,
   'Permission or ownership change on protected path','FIM detected chmod/chown class change','fim',
   '{"event_type":["permission_change","ownership_change"]}','high',0.85,NULL,'T1222',1,
   'system:seed',datetime('now'),datetime('now')),
  ('00000000-0000-7000-8000-00000000r005','fim-deletion',1,
   'Protected file deleted','Baseline file disappeared from monitored tree','fim',
   '{"event_type":["delete"]}','high',0.8,NULL,'T1070',1,
   'system:seed',datetime('now'),datetime('now'));
