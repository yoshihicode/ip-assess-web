import { matchDrop, parseDrop, type DropList, type DropResult, type ParsedIp } from '@ip-assess/core';
import { cachedText } from '../cache';

export const DROP_URLS = {
  4: 'https://www.spamhaus.org/drop/drop_v4.json',
  6: 'https://www.spamhaus.org/drop/drop_v6.json',
} as const;

// 解析済みの一覧を isolate 内に保持する（同じ本文なら再解析しない）
const parsed = new Map<string, { text: string; list: DropList }>();

// Spamhaus DROP（犯罪者が管理するネットワーク）。DNS ではなく HTTP で一覧を取得するため、公開リゾルバの制限を受けない
export async function checkDrop(ip: ParsedIp): Promise<DropResult> {
  const url = DROP_URLS[ip.version];
  const base = { fetchedAt: new Date().toISOString(), source: url, cidr: null, sblid: null, listUpdated: null, copyright: null, terms: null };
  try {
    // DROP の更新頻度は高くないため 1 時間キャッシュ（Spamhaus は頻繁な取得を推奨していない）
    const text = await cachedText(url, 3600, (t) => t.includes('"type":"metadata"'));
    let entry = parsed.get(url);
    if (!entry || entry.text !== text) {
      entry = { text, list: parseDrop(text) };
      parsed.set(url, entry);
    }
    const { list } = entry;
    const meta = { listUpdated: list.updated, copyright: list.copyright, terms: list.terms };
    const hit = matchDrop(list, ip);
    return hit
      ? { ...base, ...meta, status: 'listed', cidr: hit.cidr, sblid: hit.sblid }
      : { ...base, ...meta, status: 'not_listed' };
  } catch (e) {
    return { ...base, status: 'failed', error: e instanceof Error ? e.message : String(e) };
  }
}
