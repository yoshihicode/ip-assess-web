import {
  buildDnsblDefinitions, publicZone, reverseLabel,
  type DnsblDefinition, type DnsblListResult, type DnsblResult, type ParsedIp,
} from '@ip-assess/core';
import { cached } from '../cache';
import { dnsQuery, resolverLabel } from '../doh';

// RFC 5782 のテスト用アドレス。正常なリストなら必ず掲載として応答する
const TEST_V4 = '2.0.0.127';

type Health = 'healthy' | 'refused' | 'unhealthy' | 'failed';

async function listHealth(def: DnsblDefinition, endpoint: string): Promise<Health> {
  return cached(`dnsbl-health:${def.zone}:${endpoint}`, 3600, async (): Promise<Health> => {
    const r = await dnsQuery(endpoint, `${TEST_V4}.${def.zone}`, 'A');
    if (r.kind === 'error' || r.kind === 'servfail') return 'failed';
    if (r.kind === 'nxdomain') return 'unhealthy';
    if (def.isRefusal && r.records.some(def.isRefusal)) return 'refused';
    return r.records.some((c) => c.startsWith('127.')) ? 'healthy' : 'unhealthy';
  }, (h) => h !== 'failed');
}

async function queryList(def: DnsblDefinition, ip: ParsedIp, endpoint: string): Promise<DnsblListResult> {
  const base = { id: def.id, label: def.label, zone: publicZone(def.zone), kind: def.kind, codes: [] as string[], categories: [] as string[], policyOnly: false };
  if (!def.configured) return { ...base, status: 'not_configured' };
  if (ip.version === 6 && !def.ipv6) return { ...base, status: 'unsupported' };

  const [health, r] = await Promise.all([
    listHealth(def, endpoint),
    dnsQuery(endpoint, `${reverseLabel(ip)}.${def.zone}`, 'A'),
  ]);
  if (r.kind === 'error' || r.kind === 'servfail') return { ...base, status: 'failed' };
  if (r.kind === 'ok' && def.isRefusal && r.records.some(def.isRefusal)) return { ...base, status: 'refused', codes: r.records };
  if (health === 'refused') return { ...base, status: 'refused' };
  // テスト用アドレスに応答しないリストの「未掲載」は信用しない
  if (health !== 'healthy') return { ...base, status: health === 'failed' ? 'failed' : 'unhealthy' };
  if (r.kind === 'nxdomain') return { ...base, status: 'clean' };

  const codes = [...new Set(r.records)].sort();
  const categories = [...new Set(codes.map(def.categorize).filter((c): c is string => !!c))];
  const policyOnly = categories.length > 0 && categories.every((c) => def.policyCategories?.includes(c));
  return { ...base, status: 'listed', codes, categories, policyOnly };
}

export async function checkDnsbl(ip: ParsedIp, endpoint: string, spamhausDqsKey?: string): Promise<DnsblResult> {
  const defs = buildDnsblDefinitions({ spamhausDqsKey });
  const lists = await Promise.all(defs.map((d) => queryList(d, ip, endpoint)));
  return {
    fetchedAt: new Date().toISOString(),
    source: `${defs.filter((d) => d.configured).map((d) => publicZone(d.zone)).join(', ')} (via ${resolverLabel(endpoint)})`,
    lists,
  };
}
