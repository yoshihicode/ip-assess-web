import { reverseDnsName, parseIp, type DnsResult, type ParsedIp } from '@ip-assess/core';
import { dnsQuery, resolverLabel } from '../doh';

const MAX_PTR_NAMES = 5;

// リゾルバ自体が正常かを確認する（SERVFAIL の原因が相手側か実行環境側かの切り分け）
//   ルートサーバーの A レコードはルートゾーンに含まれるため、正常なリゾルバなら必ず解決できる
async function resolverHealthy(endpoint: string): Promise<boolean> {
  const r = await dnsQuery(endpoint, 'a.root-servers.net', 'A');
  return r.kind === 'ok';
}

// 逆引き（PTR）と FCrDNS（逆引きした名前を正引きして元の IP に戻るかの検証）
export async function checkDns(ip: ParsedIp, endpoint: string): Promise<DnsResult> {
  const base = { fetchedAt: new Date().toISOString(), source: reverseDnsName(ip), resolver: resolverLabel(endpoint) };
  let healthy: boolean | undefined;
  const isHealthy = async () => (healthy ??= await resolverHealthy(endpoint));

  const ptr = await dnsQuery(endpoint, reverseDnsName(ip), 'PTR');
  if (ptr.kind === 'nxdomain') return { ...base, ptrStatus: 'none', ptrNames: [], ptr: null, fcrdns: 'na' };
  if (ptr.kind === 'servfail') {
    if (await isHealthy()) return { ...base, ptrStatus: 'broken', ptrNames: [], ptr: null, fcrdns: 'na' };
    return { ...base, ptrStatus: 'failed', ptrNames: [], ptr: null, fcrdns: 'unknown', error: 'resolver health check failed' };
  }
  if (ptr.kind === 'error') return { ...base, ptrStatus: 'failed', ptrNames: [], ptr: null, fcrdns: 'unknown', error: ptr.message };

  const names = ptr.records;
  let fwdFailed = false;
  let fwdServfail = false;
  for (const name of names.slice(0, MAX_PTR_NAMES)) {
    const fwd = await dnsQuery(endpoint, name, ip.version === 4 ? 'A' : 'AAAA');
    if (fwd.kind === 'ok' && fwd.records.some((r) => parseIp(r)?.address === ip.address)) {
      return { ...base, ptrStatus: 'found', ptrNames: names, ptr: name, fcrdns: 'verified' };
    }
    if (fwd.kind === 'servfail') {
      // 相手側の正引きが壊れている場合は「一致しない」扱い。リゾルバ異常なら判定不能
      if (await isHealthy()) fwdServfail = true;
      else fwdFailed = true;
    }
    if (fwd.kind === 'error') fwdFailed = true;
  }
  const fcrdns = fwdFailed ? 'unknown' : fwdServfail ? 'not_verified_servfail' : 'not_verified';
  return { ...base, ptrStatus: 'found', ptrNames: names, ptr: names[0] ?? null, fcrdns };
}
