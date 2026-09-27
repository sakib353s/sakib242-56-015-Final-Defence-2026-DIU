-- CYBERWATCH-BD migration 0006 — Threat Intelligence Engine (STIX-compatible domain)

CREATE TABLE IF NOT EXISTS ti_objects (
  id TEXT PRIMARY KEY,
  stix_type TEXT NOT NULL CHECK (stix_type IN (
    'indicator','malware','threat-actor','campaign','tool','attack-pattern',
    'infrastructure','vulnerability','report','observed-data','intrusion-set',
    'course-of-action','identity')),
  stix_id TEXT,
  name TEXT NOT NULL,
  description TEXT,
  pattern TEXT,
  pattern_type TEXT,
  valid_from TEXT,
  valid_until TEXT,
  confidence INTEGER,
  tlp TEXT CHECK (tlp IN ('CLEAR','GREEN','AMBER','RED') OR tlp IS NULL),
  labels_json TEXT DEFAULT '[]',
  kill_chain_json TEXT DEFAULT '[]',
  external_refs_json TEXT DEFAULT '[]',
  source TEXT NOT NULL,
  trust TEXT NOT NULL DEFAULT 'untrusted' CHECK (trust IN ('internal','untrusted')),
  provenance_json TEXT NOT NULL DEFAULT '{}',
  first_seen TEXT,
  last_seen TEXT,
  revoked INTEGER DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ti_relationships (
  id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL,
  source_kind TEXT NOT NULL DEFAULT 'ti_object' CHECK (source_kind IN
    ('ti_object','assessment','finding','alert','incident','asset')),
  source_type TEXT,
  relationship_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  target_kind TEXT NOT NULL DEFAULT 'ti_object' CHECK (target_kind IN
    ('ti_object','assessment','finding','alert','incident','asset')),
  target_type TEXT,
  description TEXT,
  confidence REAL DEFAULT 0.5,
  state TEXT NOT NULL DEFAULT 'declared' CHECK (state IN
    ('declared','observed','inferred','correlated')),
  provenance_json TEXT DEFAULT '{}',
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ti_observables (
  id TEXT PRIMARY KEY,
  ti_object_id TEXT NOT NULL REFERENCES ti_objects(id),
  observable_type TEXT NOT NULL CHECK (observable_type IN
    ('ipv4','ipv6','domain','url','hash','email')),
  value TEXT NOT NULL,
  value_hash TEXT NOT NULL,
  first_seen TEXT,
  last_seen TEXT,
  UNIQUE (ti_object_id, observable_type, value)
);

CREATE INDEX IF NOT EXISTS idx_ti_obs_lookup ON ti_observables(observable_type, value);
CREATE INDEX IF NOT EXISTS idx_ti_obj_type ON ti_objects(stix_type, revoked);
CREATE INDEX IF NOT EXISTS idx_ti_rel_source ON ti_relationships(source_id, source_kind);
CREATE INDEX IF NOT EXISTS idx_ti_rel_target ON ti_relationships(target_id, target_kind);