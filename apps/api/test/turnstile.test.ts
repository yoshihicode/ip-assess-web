import { describe, expect, it } from 'vitest';
import { signSession, verifySession, SESSION_TTL_SECONDS } from '../src/turnstile';

describe('セッション Cookie', () => {
  const secret = 'test-secret';
  it('署名したセッションは期限内なら有効', async () => {
    const now = Date.now();
    const { value, expiresAt } = await signSession(secret, now);
    expect(expiresAt).toBe(now + SESSION_TTL_SECONDS * 1000);
    expect(await verifySession(secret, value, now + 1000)).toBe(true);
  });
  it('期限切れは無効', async () => {
    const now = Date.now();
    const { value } = await signSession(secret, now);
    expect(await verifySession(secret, value, now + SESSION_TTL_SECONDS * 1000 + 1)).toBe(false);
  });
  it('別の鍵・改ざん・不正な形式は無効', async () => {
    const { value } = await signSession(secret);
    expect(await verifySession('other-secret', value)).toBe(false);
    const [payload, sig] = value.split('.');
    const forged = btoa(JSON.stringify({ exp: Date.now() + 10 ** 9 })).replace(/=+$/, '');
    expect(await verifySession(secret, `${forged}.${sig}`)).toBe(false);
    expect(await verifySession(secret, `${payload}.`)).toBe(false);
    expect(await verifySession(secret, 'garbage')).toBe(false);
    expect(await verifySession(secret, undefined)).toBe(false);
  });
});
