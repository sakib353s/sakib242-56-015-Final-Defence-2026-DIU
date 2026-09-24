-- CYBERWATCH-BD migration 0002 — Idempotency-Key support for at-least-once clients (P-04 mobile outbox)
CREATE TABLE IF NOT EXISTS idempotency_keys (
  key TEXT PRIMARY KEY,
  response_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
