// Turnstile（Cloudflare の Bot 対策）とセッション
//   1. 画面が Turnstile のトークンを POST /api/session に送る
//   2. siteverify で検証できたら、署名付きのセッション Cookie（30 分）を発行する
//   3. 以降の API はセッション Cookie を必須にする
//   Turnstile のトークンは 1 回しか検証できないため、1 回の調査（11 リクエスト）ごとではなくセッション単位で確認する

import type { Context, MiddlewareHandler } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import type { Env } from './env';

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
export const SESSION_COOKIE = 'ia_session';
export const SESSION_TTL_SECONDS = 1800;

/** TURNSTILE_SITE_KEY が設定されている場合のみ有効 */
export const turnstileEnabled = (env: Env) => !!env.TURNSTILE_SITE_KEY;

const enc = new TextEncoder();
const b64url = (buf: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

async function hmacKey(secret: string) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function signSession(secret: string, now = Date.now()): Promise<{ value: string; expiresAt: number }> {
  const expiresAt = now + SESSION_TTL_SECONDS * 1000;
  const payload = b64url(enc.encode(JSON.stringify({ exp: expiresAt })));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(payload));
  return { value: `${payload}.${b64url(sig)}`, expiresAt };
}

export async function verifySession(secret: string, value: string | undefined, now = Date.now()): Promise<boolean> {
  if (!value) return false;
  const [payload, sig] = value.split('.');
  if (!payload || !sig) return false;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), fromB64url(sig), enc.encode(payload));
    if (!ok) return false;
    const { exp } = JSON.parse(new TextDecoder().decode(fromB64url(payload))) as { exp?: unknown };
    return typeof exp === 'number' && exp > now;
  } catch {
    return false;
  }
}

export async function verifyTurnstile(secret: string, token: string, remoteIp?: string): Promise<{ success: boolean; errors: string[] }> {
  const res = await fetch(SITEVERIFY_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ secret, response: token, ...(remoteIp ? { remoteip: remoteIp } : {}) }),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) return { success: false, errors: [`siteverify HTTP ${res.status}`] };
  const j = await res.json<{ success?: boolean; 'error-codes'?: string[] }>();
  return { success: j.success === true, errors: j['error-codes'] ?? [] };
}

function misconfigured(env: Env) {
  return !env.TURNSTILE_SECRET_KEY || !env.SESSION_SECRET;
}

/** POST /api/session */
export async function createSession(c: Context<{ Bindings: Env }>) {
  const env = c.env;
  if (!turnstileEnabled(env)) return c.json({ enabled: false });
  if (misconfigured(env)) return c.json({ error: 'turnstile_misconfigured' }, 500);
  const body = await c.req.json<{ token?: string }>().catch(() => ({} as { token?: string }));
  if (!body.token || body.token.length > 2048) return c.json({ error: 'bot_check_failed' }, 403);
  const r = await verifyTurnstile(env.TURNSTILE_SECRET_KEY!, body.token, c.req.header('cf-connecting-ip'));
  if (!r.success) {
    console.warn('Turnstile verification failed', r.errors);
    return c.json({ error: 'bot_check_failed' }, 403);
  }
  const { value, expiresAt } = await signSession(env.SESSION_SECRET!);
  setCookie(c, SESSION_COOKIE, value, {
    httpOnly: true, secure: true, sameSite: 'Strict', path: '/api', maxAge: SESSION_TTL_SECONDS,
  });
  return c.json({ enabled: true, expiresAt });
}

/** セッションを必須にするミドルウェア（Turnstile が無効なら何もしない） */
export const requireSession: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  const env = c.env;
  if (!turnstileEnabled(env)) return next();
  // 設定漏れのときは保護なしで動かさない（フェイルクローズ）
  if (misconfigured(env)) return c.json({ error: 'turnstile_misconfigured' }, 500);
  if (!(await verifySession(env.SESSION_SECRET!, getCookie(c, SESSION_COOKIE)))) {
    return c.json({ error: 'session_required' }, 401);
  }
  await next();
};
