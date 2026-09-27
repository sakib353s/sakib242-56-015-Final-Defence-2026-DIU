-- Align assessment_findings.lifecycle CHECK with the finding engine.
-- The 0004 CHECK froze an earlier lifecycle model: it lacked 'remediated' and
-- 'unconfirmed' — both produced by engine.ALLOWED_EDGES and offered as buttons
-- by the findings UI — while keeping five states the engine cannot emit
-- ('approval_pending','remediation_applied','retesting','not_fixed','unable_to_verify').
-- Every "→ Unconfirmed" / "→ Remediated" click therefore died on sqlite
-- IntegrityError ->_http 500. SQLite cannot alter a CHECK in place, so the
-- table is rebuilt. Data-copy is safe: live distinct values
-- (detected/confirmed/false_positive) are all inside the engine set.
-- Children (finding_transitions) reference the table by NAME, which the rename preserves.
PRAGMA foreign_keys=OFF;
BEGIN;
CREATE TABLE assessment_findings_new (
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
    'remediated','verified_fixed','false_positive','not_reproducible',
    'unconfirmed','actioned_but_not_verified'
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
  updated_at TEXT NOT NULL,
  triaged_by TEXT,
  triaged_at TEXT,
  confirmed_by TEXT,
  confirmed_at TEXT,
  remediation_plan_json TEXT,
  remediated_at TEXT,
  last_retest_at TEXT,
  last_retest_job_id TEXT,
  retest_count INTEGER DEFAULT 0
);
INSERT INTO assessment_findings_new SELECT * FROM assessment_findings;
DROP TABLE assessment_findings;
ALTER TABLE assessment_findings_new RENAME TO assessment_findings;
CREATE INDEX idx_af_assessment ON assessment_findings(assessment_id);
CREATE INDEX idx_af_fp ON assessment_findings(fingerprint);
COMMIT;
PRAGMA foreign_keys=ON;
