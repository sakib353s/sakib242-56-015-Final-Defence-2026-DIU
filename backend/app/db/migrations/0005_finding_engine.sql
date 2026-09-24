-- CYBERWATCH-BD migration 0005 — Finding Engine lifecycle + retest

CREATE TABLE IF NOT EXISTS finding_transitions (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES assessment_findings(id),
  from_lifecycle TEXT NOT NULL,
  to_lifecycle TEXT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT,
  evidence_ref TEXT,
  warrant_id TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ft_finding ON finding_transitions(finding_id, created_at);

ALTER TABLE assessment_findings ADD COLUMN triaged_by TEXT;
ALTER TABLE assessment_findings ADD COLUMN triaged_at TEXT;
ALTER TABLE assessment_findings ADD COLUMN confirmed_by TEXT;
ALTER TABLE assessment_findings ADD COLUMN confirmed_at TEXT;
ALTER TABLE assessment_findings ADD COLUMN remediation_plan_json TEXT;
ALTER TABLE assessment_findings ADD COLUMN remediated_at TEXT;
ALTER TABLE assessment_findings ADD COLUMN last_retest_at TEXT;
ALTER TABLE assessment_findings ADD COLUMN last_retest_job_id TEXT;
ALTER TABLE assessment_findings ADD COLUMN retest_count INTEGER DEFAULT 0;