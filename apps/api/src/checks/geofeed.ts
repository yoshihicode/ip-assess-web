import { matchGeofeed, type GeofeedResult, type ParsedIp, type RdapResult } from '@ip-assess/core';

const MAX_BYTES = 20_000_000;

// Geofeed（運営者が自己申告する利用地）。URL は RDAP から取得する
export async function checkGeofeed(ip: ParsedIp, rdap: RdapResult): Promise<GeofeedResult> {
  const base = { fetchedAt: new Date().toISOString(), url: rdap.geofeedUrl, prefix: null, country: null, region: null, city: null };
  if (rdap.status === 'failed') return { ...base, source: 'RDAP', status: 'failed', error: 'RDAP unavailable' };
  if (!rdap.geofeedUrl) return { ...base, source: 'RDAP', status: 'not_published' };
  const url = rdap.geofeedUrl;
  try {
    const res = await fetch(url, {
      cf: { cacheTtl: 43200, cacheEverything: true },
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),
    });
    if (!res.url.startsWith('https://')) throw new Error('redirected to non-https URL');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (Number(res.headers.get('content-length') ?? 0) > MAX_BYTES) throw new Error('geofeed too large');
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new Error('geofeed too large');
    const m = matchGeofeed(text, ip);
    return m ? { ...base, source: url, status: 'found', ...m } : { ...base, source: url, status: 'not_listed' };
  } catch (e) {
    return { ...base, source: url, status: 'failed', error: e instanceof Error ? e.message : String(e) };
  }
}
