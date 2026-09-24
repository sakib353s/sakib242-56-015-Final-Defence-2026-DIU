-- CYBERWATCH-BD migration 0004 — Security Assessment Studio + Evidence + Brain

CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY,
  warrant_id TEXT NOT NULL REFERENCES auth_ledger(id),
  target_raw TEXT NOT NULL,
  target_canonical TEXT NOT NULL,
  target_type TEXT NOT NULL CHECK (target_type IN ('ip','domain','url')),
  profile TEXT NOT NULL DEFAULT 'standard',
  status TEXT NOT NULL DEFAULT 'CREATED' CHECK (status IN (
    'CREATED','AUTHORIZED','PLANNED','QUEUED','DISPATCHED','RUNNING',
    'PARSING','VERIFYING','COMPLETED','FAILED','CANCELLED',
    'WORKER_LOST','UNKNOWN_RESULT','PARTIAL','BLOCKED_BY_POLICY'
  )),
  current_stage TEXT,
  progress REAL DEFAULT 0,
  findings_count INTEGER DEFAULT 0,
  observations_count INTEGER DEFAULT 0,
  risk_score REAL,
  risk_version TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  bound_session TEXT NOT NULL,
  job_id TEXT,
  worker_id TEXT,
  policy_version TEXT,
  action_versions_json TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  aborted_reason TEXT,
  report_path TEXT
);

CREATE TABLE IF NOT EXISTS assessment_stages (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL REFERENCES assessments(id),
  stage_key TEXT NOT NULL,
  label TEXT NOT NULL,
  seq INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
    'pending','running','completed','failed','skipped','degraded','unknown'
  )),
  engine TEXT,
  engine_version TEXT,
  started_at TEXT,
  finished_at TEXT,
  message TEXT,
  UNIQUE (assessment_id, seq)
);

CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL REFERENCES assessments(id),
  kind TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  target TEXT NOT NULL,
  confidence REAL DEFAULT 0.5,
  source_engine TEXT NOT NULL,
  source_version TEXT,
  provenance TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  evidence_ids_json TEXT DEFAULT '[]',
  state TEXT NOT NULL DEFAULT 'observed' CHECK (state IN (
    'observed','inferred','correlated','declared'
  )),
  collected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  assessment_id TEXT REFERENCES assessments(id),
  finding_id TEXT,
  observation_id TEXT,
  kind TEXT NOT NULL,
  ref TEXT NOT NULL,
  sha256 TEXT,
  size INTEGER,
  mime TEXT,
  storage_path TEXT,
  redacted INTEGER DEFAULT 0,
  description TEXT,
  produced_by TEXT NOT NULL,
  produced_version TEXT,
  captured_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessment_findings (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL REFERENCES assessments(id),
  fingerprint TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
  cvss REAL,
  confidence REAL DEFAULT 0.5,
  detection_state TEXT NOT NULL DEFAULT 'detected' CHECK (detection_state IN (
    'detected','probable','requires_validation','confirmed','false_positive','unconfirmed'
  )),
  lifecycle TEXT NOT NULL DEFAULT 'detected' CHECK (lifecycle IN (
    'detected','triaged','validating','confirmed','remediation_recommended',
    'approval_pending','remediation_applied','retesting','verified_fixed',
    'not_fixed','unable_to_verify','actioned_but_not_verified',
    'false_positive','not_reproducible'
  )),
  cve TEXT,
  cwe TEXT,
  mitre TEXT,
  host TEXT,
  port INTEGER,
  endpoint TEXT,
  parameter TEXT,
  technology TEXT,
  description TEXT NOT NULL,
  impact TEXT,
  remediation_hint TEXT,
  source_engine TEXT NOT NULL,
  source_version TEXT,
  evidence_ids_json TEXT DEFAULT '[]',
  observation_ids_json TEXT DEFAULT '[]',
  retest_def_json TEXT,
  before_snapshot_json TEXT,
  after_snapshot_json TEXT,
  verify_result TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS brain_decisions (
  id TEXT PRIMARY KEY,
  assessment_id TEXT REFERENCES assessments(id),
  finding_id TEXT,
  alert_id TEXT,
  incident_id TEXT,
  autonomy_level TEXT NOT NULL DEFAULT 'recommendation' CHECK (autonomy_level IN (
    'information_only','recommendation','preparation','approval_request',
    'approved_automation','bounded_autonomous_defense'
  )),
  classification TEXT,
  risk REAL,
  security_confidence REAL,
  model_confidence REAL,
  rationale_json TEXT NOT NULL,
  evidence_refs_json TEXT DEFAULT '[]',
  missing_evidence_json TEXT DEFAULT '[]',
  recommendations_json TEXT DEFAULT '[]',
  selected_action TEXT,
  policy_result TEXT,
  authorization_result TEXT,
  verification_state TEXT DEFAULT 'none',
  model_runtime TEXT,
  rule_pack_version TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);
CREATE INDEX IF NOT EXISTS idx_obs_assessment ON observations(assessment_id);
CREATE INDEX IF NOT EXISTS idx_obs_entity ON observations(entity_type, entity_value);
CREATE INDEX IF NOT EXISTS idx_ev_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_af_assessment ON assessment_findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_af_fp ON assessment_findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_bd_assessment ON brain_decisions(assessment_id);