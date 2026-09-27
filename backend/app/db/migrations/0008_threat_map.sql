-- CYBERWATCH-BD migration 0008 — Threat Map event aggregation + geo cache

CREATE TABLE IF NOT EXISTS map_events (
  id TEXT PRIMARY KEY,
  layer TEXT NOT NULL CHECK (layer IN
    ('attack-observed','ti-infrastructure','asset-exposure','incident')),
  source_table TEXT NOT NULL,
  source_id TEXT NOT NULL,
  ip TEXT,
  entity TEXT NOT NULL,
  entity_kind TEXT,
  title TEXT NOT NULL,
  description TEXT,
  lat REAL,
  lon REAL,
  location_accuracy TEXT NOT NULL DEFAULT 'unknown' CHECK (location_accuracy IN
    ('ip-approx','manual','unknown')),
  location_source TEXT,
  country TEXT,
  city TEXT,
  severity TEXT,
  confidence REAL,
  state TEXT NOT NULL CHECK (state IN ('observed','inferred','correlated','ti-derived')),
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  evidence_ref TEXT,
  UNIQUE (source_table, source_id)
);
CREATE INDEX IF NOT EXISTS idx_map_seen ON map_events(last_seen);
CREATE INDEX IF NOT EXISTS idx_map_layer ON map_events(layer, severity);

CREATE TABLE IF NOT EXISTS geo_cache (
  ip TEXT PRIMARY KEY,
  lat REAL,
  lon REAL,
  country TEXT,
  city TEXT,
  source TEXT NOT NULL,
  resolved_at TEXT NOT NULL
);
