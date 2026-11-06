// セッション（Turnstile による Bot 対策）の管理
//   調査を始める前に ensureSession() を呼ぶ。期限切れ（401）の場合は api.ts が自動で取り直して 1 回だけ再試行する

import { ApiError, createSession, fetchConfig, setSessionRefresher } from './api';
import { getTurnstileToken, mountTurnstile } from './turnstile';

let configPromise: Promise<{ turnstileSiteKey: string | null }> | null = null;
const getConfig = () => (configPromise ??= fetchConfig().catch((e) => { configPromise = null; throw e; }));

let mounted: Promise<void> | null = null;
let expiresAt = 0;
let inflight: Promise<void> | null = null;

/** ページ表示時にウィジェットを配置する。Turnstile が無効なら何もしない */
export function initBotCheck(container: HTMLElement, lang: string): void {
  mounted ??= getConfig()
    .then((c) => (c.turnstileSiteKey ? mountTurnstile(container, c.turnstileSiteKey, lang) : undefined))
    .catch((e) => { mounted = null; throw e; });
}

export async function ensureSession(force = false): Promise<void> {
  const cfg = await getConfig();
  if (!cfg.turnstileSiteKey) return;
  // 期限の 1 分前からは取り直す
  if (!force && expiresAt - 60_000 > Date.now()) return;
  inflight ??= (async () => {
    try {
      if (!mounted) throw new Error('not mounted');
      await mounted;
      const token = await getTurnstileToken();
      const r = await createSession(token);
      expiresAt = r.expiresAt ?? 0;
    } catch (e) {
      expiresAt = 0;
      throw e instanceof ApiError ? e : new ApiError('bot_check_failed', 403);
    }
  })().finally(() => { inflight = null; });
  return inflight;
}

setSessionRefresher(() => ensureSession(true));
