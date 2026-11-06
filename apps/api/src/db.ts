import type { Assessment, CheckResults } from '@ip-assess/core';
import type { AiEvaluation } from './ai';

export type AiStatus = 'none' | 'queued' | 'deferred' | 'done' | 'failed';

export interface StoredResult {
  assessment: Assessment;
  checks: CheckResults;
}

export interface AssessmentRow {
  id: string;
  ip: string;
  created_at: string;
  result_json: string;
  ai_status: AiStatus;
  ai_model: string | null;
  ai_result: string | null;
  ai_requested_at: string | null;
  ai_completed_at: string | null;
}

/** 日本時間の当日 0 時（UTC の ISO 文字列） */
export function startOfJstDay(now = new Date()): string {
  const jst = new Date(now.getTime() + 9 * 3600_000);
  jst.setUTCHours(0, 0, 0, 0);
  return new Date(jst.getTime() - 9 * 3600_000).toISOString();
}

export async function insertAssessment(db: D1Database, id: string, r: StoredResult, aiStatus: AiStatus, ai?: { model: string | null; result: string | null; requestedAt: string | null; completedAt: string | null }) {
  const a = r.assessment;
  await db.prepare(
    `INSERT INTO assessments (id, ip, version, created_at, priority, infra_class, infra_score, threat_level, result_json,
       ai_status, ai_requested_at, ai_completed_at, ai_model, ai_result)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    id, a.ip, a.version, a.assessedAt, a.priority, a.infraClass, a.infraScore, a.threat.level, JSON.stringify(r),
    aiStatus, ai?.requestedAt ?? null, ai?.completedAt ?? null, ai?.model ?? null, ai?.result ?? null,
  ).run();
}

export async function getAssessment(db: D1Database, id: string): Promise<AssessmentRow | null> {
  return db.prepare(
    `SELECT id, ip, created_at, result_json, ai_status, ai_model, ai_result, ai_requested_at, ai_completed_at
     FROM assessments WHERE id = ?`,
  ).bind(id).first<AssessmentRow>();
}

/** 同じ IP の直近の AI 評価（再利用して無料枠を節約する） */
export async function findRecentAi(db: D1Database, ip: string, sinceIso: string) {
  return db.prepare(
    `SELECT ai_model, ai_result, ai_completed_at, priority, threat_level FROM assessments
     WHERE ip = ? AND ai_status = 'done' AND ai_completed_at >= ? ORDER BY ai_completed_at DESC LIMIT 1`,
  ).bind(ip, sinceIso).first<{ ai_model: string; ai_result: string; ai_completed_at: string; priority: string; threat_level: string }>();
}

/** 当日（日本時間）に AI に投入した件数 */
export async function countAiToday(db: D1Database, now = new Date()): Promise<number> {
  const row = await db.prepare(
    `SELECT COUNT(*) AS n FROM assessments WHERE ai_status IN ('queued', 'done', 'failed') AND ai_requested_at >= ?`,
  ).bind(startOfJstDay(now)).first<{ n: number }>();
  return row?.n ?? 0;
}

export async function setAiStatus(db: D1Database, id: string, status: AiStatus, fields: { model?: string; result?: AiEvaluation; requestedAt?: string } = {}) {
  const now = new Date().toISOString();
  await db.prepare(
    `UPDATE assessments SET ai_status = ?,
       ai_model = COALESCE(?, ai_model),
       ai_result = COALESCE(?, ai_result),
       ai_requested_at = COALESCE(?, ai_requested_at),
       ai_completed_at = CASE WHEN ? IN ('done', 'failed') THEN ? ELSE ai_completed_at END
     WHERE id = ?`,
  ).bind(status, fields.model ?? null, fields.result ? JSON.stringify(fields.result) : null, fields.requestedAt ?? null, status, now, id).run();
}

export async function listDeferred(db: D1Database, limit: number): Promise<{ id: string; ip: string }[]> {
  const { results } = await db.prepare(
    `SELECT id, ip FROM assessments WHERE ai_status = 'deferred' ORDER BY created_at ASC LIMIT ?`,
  ).bind(limit).all<{ id: string; ip: string }>();
  return results;
}

export interface HistorySummary {
  total: number;
  last24h: number;
  last7d: number;
  last30d: number;
  first: string | null;
  recent: { id: string; createdAt: string; priority: string; threatLevel: string }[];
}

/** 同じ IP の問い合わせ状況 */
export async function getHistory(db: D1Database, ip: string, now = new Date()): Promise<HistorySummary> {
  const ago = (days: number) => new Date(now.getTime() - days * 86400_000).toISOString();
  const [counts, recent] = await db.batch([
    db.prepare(
      `SELECT COUNT(*) AS total,
         SUM(created_at >= ?) AS d1, SUM(created_at >= ?) AS d7, SUM(created_at >= ?) AS d30,
         MIN(created_at) AS first
       FROM assessments WHERE ip = ?`,
    ).bind(ago(1), ago(7), ago(30), ip),
    db.prepare(
      `SELECT id, created_at, priority, threat_level FROM assessments WHERE ip = ? ORDER BY created_at DESC LIMIT 20`,
    ).bind(ip),
  ]);
  const c = (counts!.results[0] ?? {}) as { total?: number; d1?: number; d7?: number; d30?: number; first?: string | null };
  return {
    total: c.total ?? 0,
    last24h: c.d1 ?? 0,
    last7d: c.d7 ?? 0,
    last30d: c.d30 ?? 0,
    first: c.first ?? null,
    recent: (recent!.results as { id: string; created_at: string; priority: string; threat_level: string }[]).map((r) => ({
      id: r.id, createdAt: r.created_at, priority: r.priority, threatLevel: r.threat_level,
    })),
  };
}
