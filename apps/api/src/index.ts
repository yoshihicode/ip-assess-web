import { Hono } from 'hono';
import {
  assess, CHECK_IDS, isGlobalUnicast, parseIp,
  type CheckId, type CheckResults, type ParsedIp,
} from '@ip-assess/core';
import type { AiJobMessage, Env } from './env';
import { cached } from './cache';
import { checkRdap } from './checks/rdap';
import { checkDns } from './checks/dns';
import { checkAsn } from './checks/asn';
import { checkDnsbl } from './checks/dnsbl';
import { checkIpsum, checkTor } from './checks/lists';
import { checkAsnDrop, checkDrop } from './checks/drop';
import { checkInternetDb } from './checks/internetdb';
import { checkGeofeed } from './checks/geofeed';
import { evaluateWithAi } from './ai';
import {
  countAiToday, findRecentAi, getAssessment, getHistory, insertAssessment, listDeferred, setAiStatus,
  type AiStatus, type StoredResult,
} from './db';

// チェック結果のキャッシュ時間（秒）
const CHECK_TTL: Record<CheckId, number> = {
  rdap: 21600, dns: 3600, asn: 21600, dnsbl: 1800, drop: 3600, asndrop: 3600, tor: 1800, ipsum: 3600, internetdb: 21600, geofeed: 21600,
};

const isFailed = (id: CheckId, v: unknown): boolean => {
  const o = v as Record<string, unknown>;
  if (id === 'dns') return o.ptrStatus === 'failed';
  if (id === 'dnsbl') return (o.lists as { status: string }[]).some((l) => l.status === 'failed');
  return o.status === 'failed';
};

function runCheck<K extends CheckId>(env: Env, ip: ParsedIp, id: K): Promise<CheckResults[K]> {
  const compute = async (): Promise<unknown> => {
    switch (id) {
      case 'rdap': return checkRdap(ip);
      case 'dns': return checkDns(ip, env.DOH_ENDPOINT);
      case 'asn': return checkAsn(ip, env.DOH_ENDPOINT);
      case 'dnsbl': return checkDnsbl(ip, env.DOH_ENDPOINT, env.SPAMHAUS_DQS_KEY);
      case 'drop': return checkDrop(ip);
      case 'asndrop': return checkAsnDrop(await runCheck(env, ip, 'asn'));
      case 'tor': return checkTor(ip);
      case 'ipsum': return checkIpsum(ip);
      case 'internetdb': return checkInternetDb(ip);
      case 'geofeed': return checkGeofeed(ip, await runCheck(env, ip, 'rdap'));
    }
  };
  return cached(`check:${id}:${ip.address}`, CHECK_TTL[id], compute, (v) => !isFailed(id, v)) as Promise<CheckResults[K]>;
}

async function runAllChecks(env: Env, ip: ParsedIp): Promise<CheckResults> {
  const values = await Promise.all(CHECK_IDS.map((id) => runCheck(env, ip, id)));
  return Object.fromEntries(CHECK_IDS.map((id, i) => [id, values[i]])) as unknown as CheckResults;
}

type ParsedResult = { ok: true; ip: ParsedIp } | { ok: false; error: 'invalid_ip' | 'not_global' };

function validateIp(input: string | undefined | null): ParsedResult {
  const ip = input ? parseIp(input) : null;
  if (!ip) return { ok: false, error: 'invalid_ip' };
  if (!isGlobalUnicast(ip)) return { ok: false, error: 'not_global' };
  return { ok: true, ip };
}

const app = new Hono<{ Bindings: Env }>().basePath('/api');

// 利用者単位のレート制限（Rate Limiting バインディングがある場合のみ）
app.use('*', async (c, next) => {
  if (c.env.RATE_LIMITER) {
    const key = c.req.header('cf-connecting-ip') ?? 'unknown';
    const { success } = await c.env.RATE_LIMITER.limit({ key });
    if (!success) return c.json({ error: 'rate_limited' }, 429);
  }
  await next();
});

app.get('/health', (c) => c.json({ ok: true }));

// 個々のチェック（画面はこれを並列に呼び、終わったものから表示する）
app.get('/checks/:id', async (c) => {
  const id = c.req.param('id') as CheckId;
  if (!CHECK_IDS.includes(id)) return c.json({ error: 'unknown_check' }, 404);
  const v = validateIp(c.req.query('ip'));
  if (!v.ok) return c.json({ error: v.error }, 400);
  return c.json(await runCheck(c.env, v.ip, id));
});

// 判定・保存・AI 評価の受付
app.post('/assessments', async (c) => {
  const body = await c.req.json<{ ip?: string }>().catch(() => ({} as { ip?: string }));
  const v = validateIp(body.ip);
  if (!v.ok) return c.json({ error: v.error }, 400);

  const checks = await runAllChecks(c.env, v.ip);
  const assessment = assess(v.ip, checks);
  const stored: StoredResult = { assessment, checks };
  const id = crypto.randomUUID();
  const db = c.env.DB;
  const now = new Date();

  // AI 評価: 24 時間以内に同じ IP・同じ結論の評価があれば再利用し、なければ日次上限まで投入する
  let aiStatus: AiStatus;
  if (!c.env.AI) {
    // Workers AI が使えない環境（ローカル実行）では AI 評価を行わない
    await insertAssessment(db, id, stored, 'none');
    const history = await getHistory(db, assessment.ip, now);
    return c.json({ id, assessment, history, ai: { status: 'none' } });
  }
  const recent = await findRecentAi(db, assessment.ip, new Date(now.getTime() - 86400_000).toISOString());
  if (recent && recent.priority === assessment.priority && recent.threat_level === assessment.threat.level) {
    aiStatus = 'done';
    await insertAssessment(db, id, stored, aiStatus, {
      model: recent.ai_model, result: recent.ai_result, requestedAt: null, completedAt: recent.ai_completed_at,
    });
  } else {
    const limit = Number(c.env.AI_DAILY_LIMIT) || 20;
    const used = await countAiToday(db, now);
    aiStatus = used < limit ? 'queued' : 'deferred';
    await insertAssessment(db, id, stored, aiStatus, {
      model: null, result: null, requestedAt: aiStatus === 'queued' ? now.toISOString() : null, completedAt: null,
    });
    if (aiStatus === 'queued') {
      try {
        await c.env.AI_QUEUE.send({ id });
      } catch {
        aiStatus = 'deferred';
        await setAiStatus(db, id, 'deferred');
      }
    }
  }

  const history = await getHistory(db, assessment.ip, now);
  return c.json({ id, assessment, history, ai: { status: aiStatus } });
});

// 保存済みの結果（共有リンク・再表示用）
app.get('/assessments/:id', async (c) => {
  const row = await getAssessment(c.env.DB, c.req.param('id'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  const stored = JSON.parse(row.result_json) as StoredResult;
  const history = await getHistory(c.env.DB, row.ip);
  return c.json({
    id: row.id,
    ...stored,
    history,
    ai: { status: row.ai_status, model: row.ai_model, result: row.ai_result ? JSON.parse(row.ai_result) : null, completedAt: row.ai_completed_at },
  });
});

// AI 評価の状態（画面からポーリングする）
app.get('/assessments/:id/ai', async (c) => {
  const row = await getAssessment(c.env.DB, c.req.param('id'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  return c.json({
    status: row.ai_status, model: row.ai_model,
    result: row.ai_result ? JSON.parse(row.ai_result) : null, completedAt: row.ai_completed_at,
  });
});

app.get('/history', async (c) => {
  const v = validateIp(c.req.query('ip'));
  if (!v.ok) return c.json({ error: v.error }, 400);
  return c.json(await getHistory(c.env.DB, v.ip.address));
});

app.onError((err, c) => {
  console.error(err);
  return c.json({ error: 'internal_error' }, 500);
});

async function processAiJob(env: Env, msg: Message<AiJobMessage>) {
  const row = await getAssessment(env.DB, msg.body.id);
  if (!row || row.ai_status === 'done') { msg.ack(); return; }
  try {
    const stored = JSON.parse(row.result_json) as StoredResult;
    const result = await evaluateWithAi(env, stored.assessment, stored.checks);
    await setAiStatus(env.DB, row.id, 'done', { model: env.AI_MODEL, result });
    msg.ack();
  } catch (e) {
    console.error('AI evaluation failed', row.id, e);
    if (msg.attempts >= 3) {
      await setAiStatus(env.DB, row.id, 'failed', { model: env.AI_MODEL });
      msg.ack();
    } else {
      msg.retry({ delaySeconds: 30 });
    }
  }
}

export default {
  fetch: app.fetch,

  async queue(batch: MessageBatch<AiJobMessage>, env: Env) {
    for (const msg of batch.messages) await processAiJob(env, msg);
  },

  // 日次: 前日に上限を超えて保留した AI 評価を、当日の上限まで投入する
  async scheduled(_event: ScheduledController, env: Env) {
    const limit = Number(env.AI_DAILY_LIMIT) || 20;
    const remaining = limit - (await countAiToday(env.DB));
    if (remaining <= 0) return;
    const jobs = await listDeferred(env.DB, remaining);
    if (jobs.length === 0) return;
    const now = new Date().toISOString();
    for (const j of jobs) await setAiStatus(env.DB, j.id, 'queued', { requestedAt: now });
    await env.AI_QUEUE.sendBatch(jobs.map((j) => ({ body: { id: j.id } })));
  },
} satisfies ExportedHandler<Env, AiJobMessage>;
