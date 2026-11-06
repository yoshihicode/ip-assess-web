import { parseCymruAsName, parseCymruOrigin, reverseLabel, type AsnResult, type ParsedIp } from '@ip-assess/core';
import { dnsQuery } from '../doh';

// Team Cymru IP to ASN Mapping（DNS 経由）
export async function checkAsn(ip: ParsedIp, endpoint: string): Promise<AsnResult> {
  const zone = ip.version === 4 ? 'origin.asn.cymru.com' : 'origin6.asn.cymru.com';
  const base = {
    fetchedAt: new Date().toISOString(),
    source: `Team Cymru IP to ASN Mapping (${zone})`,
    asn: null, otherAsns: [], name: null, prefix: null, country: null, allocated: null,
  };
  const origin = await dnsQuery(endpoint, `${reverseLabel(ip)}.${zone}`, 'TXT');
  if (origin.kind === 'nxdomain') return { ...base, status: 'not_announced' };
  if (origin.kind !== 'ok') {
    return { ...base, status: 'failed', error: origin.kind === 'error' ? origin.message : 'SERVFAIL' };
  }
  const parsed = parseCymruOrigin(origin.records);
  if (!parsed || parsed.asn === null) return { ...base, status: 'failed', error: 'unexpected TXT format' };

  const nameRes = await dnsQuery(endpoint, `AS${parsed.asn}.asn.cymru.com`, 'TXT');
  const name = nameRes.kind === 'ok' ? parseCymruAsName(nameRes.records) : null;
  return { ...base, status: 'found', ...parsed, name };
}
