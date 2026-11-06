import type { InternetDbResult, ParsedIp } from '@ip-assess/core';

// Shodan InternetDB（公開ポート・タグ・既知の脆弱性。API キー不要、週 1 回更新）
//   200: データあり / 404: データなし / その他: 取得失敗
//   ※非商用は無料、企業内利用は可、商用製品への組み込みは別途ライセンスが必要
export async function checkInternetDb(ip: ParsedIp): Promise<InternetDbResult> {
  const source = `https://internetdb.shodan.io/${ip.address}`;
  const base = { fetchedAt: new Date().toISOString(), source, ports: [], tags: [], vulns: [], cpes: [], hostnames: [] };
  try {
    const res = await fetch(source, { signal: AbortSignal.timeout(10000) });
    if (res.status === 404) return { ...base, status: 'no_data' };
    if (!res.ok) return { ...base, status: 'failed', error: `HTTP ${res.status}` };
    const j = await res.json<Record<string, unknown>>();
    const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
    return {
      ...base,
      status: 'found',
      ports: (Array.isArray(j.ports) ? j.ports.filter((p): p is number => typeof p === 'number') : []).sort((a, b) => a - b),
      tags: strs(j.tags),
      vulns: strs(j.vulns).sort(),
      cpes: strs(j.cpes),
      hostnames: strs(j.hostnames),
    };
  } catch (e) {
    return { ...base, status: 'failed', error: e instanceof Error ? e.message : String(e) };
  }
}
