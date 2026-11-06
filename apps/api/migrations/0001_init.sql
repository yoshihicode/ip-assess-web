-- 問い合わせ 1 件 = 1 行（同じ IP の問い合わせ履歴の集計にも使う）
CREATE TABLE assessments (
  id              TEXT PRIMARY KEY,
  ip              TEXT NOT NULL,
  version         INTEGER NOT NULL,
  created_at      TEXT NOT NULL,             -- ISO 8601 (UTC)
  priority        TEXT NOT NULL,
  infra_class     TEXT NOT NULL,
  infra_score     INTEGER NOT NULL,
  threat_level    TEXT NOT NULL,
  result_json     TEXT NOT NULL,             -- {"assessment": ..., "checks": ...}
  -- AI 評価: none / queued / deferred（上限超過で翌日）/ done / failed
  ai_status       TEXT NOT NULL DEFAULT 'none',
  ai_requested_at TEXT,
  ai_completed_at TEXT,
  ai_model        TEXT,
  ai_result       TEXT
);

CREATE INDEX idx_assessments_ip_created ON assessments (ip, created_at);
CREATE INDEX idx_assessments_ai ON assessments (ai_status, ai_requested_at);
