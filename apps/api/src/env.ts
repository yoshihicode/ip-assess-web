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
}
