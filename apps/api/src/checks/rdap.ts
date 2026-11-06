import { emptyRdap, parseRdap, type ParsedIp, type RdapResult } from '@ip-assess/core';

// APNIC の RDAP に問い合わせ、他の RIR の管理であればリダイレクトに従う
export async function checkRdap(ip: ParsedIp): Promise<RdapResult> {
  const url = `https://rdap.apnic.net/ip/${ip.address}`;
  const fetchedAt = new Date().toISOString();
  try {
    const res = await fetch(url, {
      headers: { accept: 'application/rdap+json, application/json' },
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    });
    // 実際に回答した RIR の URL を証跡として記録する
    const source = res.url || url;
    if (!res.ok) return emptyRdap(source, fetchedAt, `HTTP ${res.status}`);
    return parseRdap(await res.text(), source, fetchedAt);
  } catch (e) {
    return emptyRdap(url, fetchedAt, e instanceof Error ? e.message : String(e));
  }
}
