import { useCallback, useEffect, useRef, useState } from 'react';
import { CHECK_IDS, isGlobalUnicast, parseIp, type CheckId, type CheckResults } from '@ip-assess/core';
import {
  ApiError, createAssessment, fetchAi, fetchAssessment, fetchCheck,
  type AiState, type AssessmentResponse,
} from './api';

export type CheckState = 'pending' | 'done' | 'failed';

export interface RunState {
  ip: string | null;
  checks: Partial<CheckResults>;
  checkState: Partial<Record<CheckId, CheckState>>;
  result: AssessmentResponse | null;
  assessing: boolean;
  error: string | null;
}

const initial: RunState = { ip: null, checks: {}, checkState: {}, result: null, assessing: false, error: null };

const AI_POLL_MS = 5000;
const AI_POLL_MAX = 60;

/** チェック結果が「取得できず」か（進行状況の表示用） */
function isFailed(id: CheckId, v: unknown): boolean {
  const o = v as Record<string, unknown>;
  if (id === 'dns') return o.ptrStatus === 'failed';
  if (id === 'dnsbl') return (o.lists as { status: string }[]).every((l) => l.status !== 'listed' && l.status !== 'clean');
  return o.status === 'failed';
}

const errorCode = (e: unknown) => (e instanceof ApiError ? e.code : 'generic');

/** 各チェックを並列に呼び、終わったものから画面に反映する。すべて終わったら判定・保存を依頼する */
export function useAssessment() {
  const [state, setState] = useState<RunState>(initial);
  const runId = useRef(0);

  const pollAi = useCallback(async (id: string, run: number) => {
    for (let i = 0; i < AI_POLL_MAX; i++) {
      await new Promise((r) => setTimeout(r, AI_POLL_MS));
      if (run !== runId.current) return;
      let ai: AiState;
      try {
        ai = await fetchAi(id);
      } catch {
        continue;
      }
      if (run !== runId.current) return;
      setState((s) => (s.result ? { ...s, result: { ...s.result, ai } } : s));
      if (ai.status !== 'queued') return;
    }
  }, []);

  const run = useCallback(async (input: string) => {
    const parsed = parseIp(input);
    if (!parsed) { setState({ ...initial, error: 'invalid_ip' }); return; }
    if (!isGlobalUnicast(parsed)) { setState({ ...initial, error: 'not_global' }); return; }

    const run = ++runId.current;
    const ip = parsed.address;
    setState({ ...initial, ip, checkState: Object.fromEntries(CHECK_IDS.map((id) => [id, 'pending'])) });

    let fatal: string | null = null;
    await Promise.all(CHECK_IDS.map(async (id) => {
      try {
        const v = await fetchCheck(id, ip);
        if (run !== runId.current) return;
        setState((s) => ({
          ...s,
          checks: { ...s.checks, [id]: v },
          checkState: { ...s.checkState, [id]: isFailed(id, v) ? 'failed' : 'done' },
        }));
      } catch (e) {
        if (run !== runId.current) return;
        if (e instanceof ApiError && e.status === 429) fatal = 'rate_limited';
        setState((s) => ({ ...s, checkState: { ...s.checkState, [id]: 'failed' } }));
      }
    }));
    if (run !== runId.current) return;
    if (fatal) { setState((s) => ({ ...s, error: fatal })); return; }

    setState((s) => ({ ...s, assessing: true }));
    try {
      const result = await createAssessment(ip);
      if (run !== runId.current) return;
      setState((s) => ({ ...s, result, assessing: false }));
      if (result.ai.status === 'queued') void pollAi(result.id, run);
    } catch (e) {
      if (run !== runId.current) return;
      setState((s) => ({ ...s, assessing: false, error: errorCode(e) }));
    }
  }, [pollAi]);

  const load = useCallback(async (id: string) => {
    const run = ++runId.current;
    setState({ ...initial, assessing: true });
    try {
      const r = await fetchAssessment(id);
      if (run !== runId.current) return;
      setState({
        ip: r.assessment.ip,
        checks: r.checks,
        checkState: Object.fromEntries(CHECK_IDS.map((c) => [c, r.checks[c] && !isFailed(c, r.checks[c]) ? 'done' : 'failed'])),
        result: { id: r.id, assessment: r.assessment, history: r.history, ai: r.ai },
        assessing: false,
        error: null,
      });
      if (r.ai.status === 'queued') void pollAi(r.id, run);
    } catch (e) {
      if (run !== runId.current) return;
      setState({ ...initial, error: errorCode(e) });
    }
  }, [pollAi]);

  // 画面を離れたら進行中の処理の結果を捨てる
  useEffect(() => () => { runId.current++; }, []);

  return { state, run, load };
}
