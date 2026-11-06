import type { CheckResults, RdapResult } from '../src';

const meta = { fetchedAt: '2026-11-06T00:00:00.000Z', source: 'test' };

export function rdap(over: Partial<RdapResult> = {}): RdapResult {
  return {
    ...meta, status: 'found', name: 'TEST-NET', handle: 'H1', country: 'JP', type: 'ALLOCATED PORTABLE', port43: 'whois.nic.ad.jp',
    range: null, cidrs: [], registered: null, lastChanged: null, rir: { id: 'JPNIC', country: 'JP' }, addresses: [], holder: null,
    remarks: [], abuseContacts: [], entities: [], emails: [], domains: [], geofeedUrl: null, ...over,
  };
}

/** すべて「該当なし・取得成功」の結果を作り、必要な項目だけ上書きする */
export function results(over: Partial<CheckResults> = {}): CheckResults {
  return {
    rdap: rdap(),
    dns: { ...meta, ptrStatus: 'found', ptrNames: ['host.example.jp'], ptr: 'host.example.jp', fcrdns: 'verified', resolver: 'test' },
    asn: { ...meta, status: 'found', asn: 64500, otherAsns: [], name: 'TEST-AS', prefix: '192.0.2.0/24', country: 'JP', allocated: '2000-01-01' },
    dnsbl: {
      ...meta,
      lists: [
        { id: 'spamhaus', label: 'Spamhaus ZEN', zone: 'zen.spamhaus.org', kind: 'threat', status: 'clean', codes: [], categories: [], policyOnly: false },
        { id: 'spamcop', label: 'SpamCop', zone: 'bl.spamcop.net', kind: 'spam', status: 'clean', codes: [], categories: [], policyOnly: false },
      ],
    },
    drop: { ...meta, status: 'not_listed', cidr: null, sblid: null, listUpdated: '2026-11-06T00:00:00.000Z', copyright: '(c) 2026 The Spamhaus Project SLU', terms: null },
    asndrop: { ...meta, status: 'not_listed', checkedAsns: [64500], matches: [], listUpdated: '2026-11-06T00:00:00.000Z', copyright: '(c) 2026 The Spamhaus Project SLU', terms: null },
    tor: { ...meta, status: 'not_listed' },
    ipsum: { ...meta, status: 'ok', count: 0, updated: null },
    internetdb: { ...meta, status: 'no_data', ports: [], tags: [], vulns: [], cpes: [], hostnames: [] },
    geofeed: { ...meta, status: 'not_published', url: null, prefix: null, country: null, region: null, city: null },
    ...over,
  };
}
