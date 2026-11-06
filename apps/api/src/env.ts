export interface AiJobMessage {
  id: string;
}

export interface Env {
  DB: D1Database;
  /** ローカル実行（env.local）では未定義 */
  AI?: Ai;
  AI_QUEUE: Queue<AiJobMessage>;
  RATE_LIMITER?: RateLimit;
  AI_DAILY_LIMIT: string;
  AI_MODEL: string;
  AI_LANGUAGE: string;
  DOH_ENDPOINT: string;
  SPAMHAUS_DQS_KEY?: string;
  /** Turnstile のサイトキー（公開値）。空なら Bot 対策は無効 */
  TURNSTILE_SITE_KEY?: string;
  /** Turnstile のシークレットキー（wrangler secret） */
  TURNSTILE_SECRET_KEY?: string;
  /** セッション Cookie の署名鍵（wrangler secret） */
  SESSION_SECRET?: string;
}
