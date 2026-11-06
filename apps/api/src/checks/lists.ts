import type { IpsumResult, ParsedIp, TorResult } from '@ip-assess/core';
import { cachedText } from '../cache';

export const TOR_URL = 'https://check.torproject.org/torbulkexitlist';
export const IPSUM_URL = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt';

// Tor 出口ノード（取得失敗時に「該当なし」と誤表示しないよう、取得の成否を先に確認する）
export async function checkTor(ip: ParsedIp): Promise<TorResult> {
  const base = { fetchedAt: new Date().toISOString(), source: TOR_URL };
  try {
    const text = await cachedText(TOR_URL, 1800, (t) => /^\d+\.\d+\.\d+\.\d+$/m.test(t));
    const listed = `\n${text}\n`.includes(`\n${ip.address}\n`);
    return { ...base, status: listed ? 'listed' : 'not_listed' };
  } catch (e) {
    return { ...base, status: 'failed', error: e instanceof Error ? e.message : String(e) };
  }
}

// IPsum（30 以上の公開ブラックリストの集約。毎日更新、IPv4 のみ）
//   約 2MB のため、行の分割はせず文字列検索で該当行だけを取り出す（CPU 時間の節約）
export async function checkIpsum(ip: ParsedIp): Promise<IpsumResult> {
  const base = { fetchedAt: new Date().toISOString(), source: IPSUM_URL, count: 0, updated: null };
  if (ip.version !== 4) return { ...base, status: 'unsupported' };
  try {
    const text = await cachedText(IPSUM_URL, 43200, (t) => t.startsWith('# IPsum'));
    const updated = /^# Last update: *(.+)$/m.exec(text.slice(0, 2000))?.[1]?.trim() ?? null;
    const needle = `\n${ip.address}\t`;
    const at = text.indexOf(needle);
    let count = 0;
    if (at >= 0) {
      const end = text.indexOf('\n', at + needle.length);
      count = Number(text.slice(at + needle.length, end < 0 ? undefined : end).trim()) || 0;
    }
    return { ...base, status: 'ok', count, updated };
  } catch (e) {
    return { ...base, status: 'failed', error: e instanceof Error ? e.message : String(e) };
  }
}
