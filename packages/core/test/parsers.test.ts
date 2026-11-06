import { describe, expect, it } from 'vitest';
import { matchAsnDrop, parseAsnDrop, matchDrop, parseDrop, buildDnsblDefinitions, matchGeofeed, parseCymruAsName, parseCymruOrigin, parseIp, parseRdap, publicZone } from '../src';

describe('Team Cymru', () => {
  it('最も細かいプレフィックスを採用し、別のオリジン AS を数える', () => {
    const r = parseCymruOrigin([
      '"2914 | 103.11.0.0/16 | JP | apnic | 2012-01-01"',
      '"64500 | 103.11.121.0/24 | JP | apnic | 2012-01-01"',
      '"2914 | 103.11.120.0/22 | JP | apnic | 2012-01-01"',
    ]);
    expect(r).toEqual({ asn: 64500, otherAsns: [2914], prefix: '103.11.121.0/24', country: 'JP', allocated: '2012-01-01' });
  });
  it('AS 名', () => {
    expect(parseCymruAsName(['15169 | US | arin | 2000-03-30 | GOOGLE, US'])).toBe('GOOGLE, US');
  });
});

describe('Geofeed', () => {
  const csv = [
    '# comment',
    '69.5.0.0/16,US,US-CA,Los Angeles,',
    '69.5.174.0/24,JP,JP-13,Tokyo,',
    '2.0.0.0/7,FR,,,',
    '2400:1000::/32,JP,JP-27,Osaka,',
    '2400::/12,SG,,,\r',
  ].join('\n');
  it('最も細かいプレフィックスの行を採用する', () => {
    expect(matchGeofeed(csv, parseIp('69.5.174.26')!)).toEqual({ prefix: '69.5.174.0/24', country: 'JP', region: 'JP-13', city: 'Tokyo' });
    expect(matchGeofeed(csv, parseIp('69.5.1.1')!)?.city).toBe('Los Angeles');
  });
  it('先頭オクテットが異なる短いプレフィックスも見落とさない', () => {
    expect(matchGeofeed(csv, parseIp('3.1.1.1')!)?.country).toBe('FR');
    expect(matchGeofeed(csv, parseIp('240a::1')!)?.country).toBe('SG');
    expect(matchGeofeed(csv, parseIp('2400:1000::5')!)?.city).toBe('Osaka');
  });
  it('該当なし', () => {
    expect(matchGeofeed(csv, parseIp('8.8.8.8')!)).toBeNull();
  });
});

describe('DNSBL の定義', () => {
  const spamhaus = buildDnsblDefinitions().find((d) => d.id === 'spamhaus')!;
  it('Spamhaus の応答コード', () => {
    expect(['127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.9', '127.0.0.11'].map(spamhaus.categorize)).toEqual(['SBL', 'CSS', 'XBL', 'DROP', 'PBL']);
    expect(spamhaus.isRefusal!('127.255.255.254')).toBe(true);
  });
  it('ZEN は DQS キーがある場合のみ使う', () => {
    expect(spamhaus.configured).toBe(false);
    expect(buildDnsblDefinitions({ spamhausDqsKey: 'k' }).find((x) => x.id === 'spamhaus')!.configured).toBe(true);
  });
  it('DQS キーは表示用のゾーン名に含めない', () => {
    const d = buildDnsblDefinitions({ spamhausDqsKey: 'secretkey' }).find((x) => x.id === 'spamhaus')!;
    expect(d.zone).toBe('secretkey.zen.dq.spamhaus.net');
    expect(publicZone(d.zone)).not.toContain('secretkey');
  });
});

describe('RDAP', () => {
  const raw = JSON.stringify({
    handle: '69.5.174.0 - 69.5.174.255', name: 'HYDRA-NET', type: 'ASSIGNED PA', country: 'gb', port43: 'whois.arin.net',
    startAddress: '69.5.174.0', endAddress: '69.5.174.255',
    cidr0_cidrs: [{ v4prefix: '69.5.174.0', length: 24 }],
    events: [{ eventAction: 'registration', eventDate: '2025-10-01T00:00:00Z' }, { eventAction: 'last changed', eventDate: '2025-10-02T00:00:00Z' }],
    links: [{ rel: 'geofeed', href: 'https://example.net/geofeed.csv' }],
    remarks: [{ description: ['Customer range'] }],
    notices: [{ description: ['Terms of service: contact tos@arin.net'] }],
    entities: [
      {
        handle: 'ORG-1', roles: ['registrant'],
        vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Hydra Communications'], ['kind', {}, 'text', 'org'],
          ['adr', { label: '1 Main St\nSuite 100\nLondon' }, 'text', ['', '', '', '', '', '', '']]]],
        entities: [
          { handle: 'ABUSE-1', roles: ['abuse'], vcardArray: ['vcard', [['fn', {}, 'text', 'Abuse Desk'], ['kind', {}, 'text', 'group'], ['email', {}, 'text', 'abuse@zare.com']]] },
        ],
      },
      {
        handle: 'P-1', roles: ['technical'],
        vcardArray: ['vcard', [['fn', {}, 'text', 'John Doe'], ['kind', {}, 'text', 'individual'],
          ['adr', { cc: 'us' }, 'text', ['PO Box 12', '', '123 St', 'Town', 'CA', '90000', 'United States']]]],
      },
    ],
  });
  const r = parseRdap(raw, 'https://rdap.arin.net/registry/ip/69.5.174.26', '2026-11-06T00:00:00Z');

  it('トップレベルの値', () => {
    expect(r).toMatchObject({
      name: 'HYDRA-NET', country: 'GB', type: 'ASSIGNED PA', cidrs: ['69.5.174.0/24'],
      range: { start: '69.5.174.0', end: '69.5.174.255' }, registered: '2025-10-01T00:00:00Z', lastChanged: '2025-10-02T00:00:00Z',
      rir: { id: 'ARIN', country: 'US' }, geofeedUrl: 'https://example.net/geofeed.csv', remarks: ['Customer range'],
    });
  });
  it('入れ子のエンティティの Abuse 連絡先', () => {
    expect(r.abuseContacts).toEqual([{ emails: ['abuse@zare.com'], name: 'Abuse Desk', handle: 'ABUSE-1' }]);
  });
  it('住所（label 優先、なければ構造化要素）と代表住所', () => {
    expect(r.addresses.map((a) => [a.kind, a.address, a.country])).toEqual([
      ['org', '1 Main St Suite 100 London', ''],
      ['individual', 'PO Box 12, 123 St, Town, CA, 90000, United States', 'US'],
    ]);
    expect(r.holder?.name).toBe('Hydra Communications');
  });
  it('メールとドメインは応答全体から集める', () => {
    expect(r.emails).toEqual(['abuse@zare.com', 'tos@arin.net']);
    expect(r.domains).toEqual(['arin.net', 'zare.com']);
  });
  it('https 以外の geofeed URL は使わない', () => {
    const x = parseRdap(JSON.stringify({ links: [{ rel: 'geofeed', href: 'http://example.net/g.csv' }] }), 'u', 't');
    expect(x.geofeedUrl).toBeNull();
  });
});

describe('Spamhaus DROP', () => {
  const text = [
    '{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"arin"}',
    '{"cidr":"192.0.2.128/25","sblid":"SBL2","rir":"arin"}',
    '{"cidr":"2001:678:254::/48","sblid":"SBL3","rir":"ripencc"}',
    '{"type":"metadata","timestamp":1793897042,"size":100,"records":3,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}',
  ].join('\n');
  const list = parseDrop(text);
  it('メタデータ（© 表記と更新日時）', () => {
    expect(list).toMatchObject({ copyright: '(c) 2026 The Spamhaus Project SLU', updated: new Date(1793897042000).toISOString() });
    expect(list.entries).toHaveLength(3);
  });
  it('最も細かいエントリを返す', () => {
    expect(matchDrop(list, parseIp('192.0.2.200')!)?.sblid).toBe('SBL2');
    expect(matchDrop(list, parseIp('192.0.2.1')!)?.sblid).toBe('SBL1');
    expect(matchDrop(list, parseIp('2001:678:254::1')!)?.sblid).toBe('SBL3');
    expect(matchDrop(list, parseIp('198.51.100.1')!)).toBeNull();
  });
  it('メタデータ行のない（途中で切れた）ファイルはエラー', () => {
    expect(() => parseDrop('{"cidr":"192.0.2.0/24","sblid":"SBL1"}')).toThrow();
  });
});

describe('Spamhaus ASN-DROP', () => {
  const text = [
    '{"asn":64500,"rir":"arin","domain":"bad.example","cc":"US","asname":"BAD-AS"}',
    '{"asn":64501,"rir":"ripencc","cc":"NL","asname":"WORSE-AS"}',
    '{"type":"metadata","timestamp":1793943842,"size":100,"records":2,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}',
  ].join('\n');
  const list = parseAsnDrop(text);
  it('メタデータとエントリ', () => {
    expect(list.copyright).toBe('(c) 2026 The Spamhaus Project SLU');
    expect(list.entries.get(64500)).toEqual({ asn: 64500, asname: 'BAD-AS', cc: 'US', domain: 'bad.example' });
    expect(list.entries.get(64501)?.domain).toBeNull();
  });
  it('オリジン AS と別のオリジン AS を照合する', () => {
    expect(matchAsnDrop(list, [15169, 64501]).map((e) => e.asn)).toEqual([64501]);
    expect(matchAsnDrop(list, [15169])).toEqual([]);
  });
  it('メタデータ行のない（途中で切れた）ファイルはエラー', () => {
    expect(() => parseAsnDrop('{"asn":64500}')).toThrow();
  });
});
