-- 0010: 'Protected file modified or created' is precisely Stored Data
-- Manipulation (T1565.001), not the undifferentiated parent technique, so the
-- sub-technique profile graph gets real observations instead of only the parent.
UPDATE detection_rules SET mitre = 'T1565.001', updated_at = datetime('now')
WHERE id = '00000000-0000-7000-8000-00000000r003' AND rule_key = 'fim-baseline-change';
