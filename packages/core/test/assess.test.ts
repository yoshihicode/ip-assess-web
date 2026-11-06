import { describe, expect, it } from 'vitest';
import { assess, parseIp } from '../src';
import { rdap, results } from './helpers';

const ip = parseIp('192.0.2.10')!;
const ind = (a: ReturnType<typeof assess>, id: string, key?: string) => a.indicators.find((i) => i.id === id && (key === undefined || i.key === key))!;

describe('assess', () => {
  it('国内一般回線（ASN）は -5 で LOW。LOW は安全ではない旨の注意を付ける', () => {
    const a = assess(ip, results({ asn: { ...results().asn, asn: 4713, name: 'OCN NTT Communications' } }));
    expect(ind(a, 'consumer_isp')).toMatchObject({ state: 'safe', points: -5, params: { kind: 'asn', value: 'AS4713' } });
    expect(a).toMatchObject({ priority: 'LOW', infraClass: 'consumer_isp', infraScore: -5, note: 'low_not_safe', confidence: 'FULL' });
  });

  it('国内 ISP でもブラックリスト掲載なら HIGH（2 軸を合算しない）', () => {
    const base = results();
    const a = assess(ip, results({
      asn: { ...base.asn, asn: 4713 },
      dnsbl: { ...base.dnsbl, lists: [{ ...base.dnsbl.lists[0]!, status: 'listed', codes: ['127.0.0.4'], categories: ['XBL'] }] },
    }));
    expect(a.infraScore).toBe(-5);
    expect(a.priority).toBe('HIGH');
    expect(a.threat).toEqual({ level: 'DETECTED', signals: ['Spamhaus ZEN XBL'] });
  });

  it('Spamhaus PBL のみは脅威にしない', () => {
    const base = results();
    const a = assess(ip, results({
      dnsbl: { ...base.dnsbl, lists: [{ ...base.dnsbl.lists[0]!, status: 'listed', codes: ['127.0.0.10'], categories: ['PBL'], policyOnly: true }] },
    }));
    expect(ind(a, 'dnsbl', 'spamhaus').state).toBe('info');
    expect(a.threat.level).toBe('NONE_FOUND');
  });

  it('迷惑メール専用リストは情報表示のみ', () => {
    const base = results();
    const a = assess(ip, results({
      dnsbl: { ...base.dnsbl, lists: [base.dnsbl.lists[0]!, { ...base.dnsbl.lists[1]!, status: 'listed', codes: ['127.0.0.2'], categories: ['Spam source'] }] },
    }));
    expect(ind(a, 'dnsbl', 'spamcop').state).toBe('info');
    expect(a.threat.level).toBe('NONE_FOUND');
  });

  it('ホスティング ASN + PA + 逆引きなし = 5 点で HIGH', () => {
    const a = assess(ip, results({
      rdap: rdap({ type: 'ASSIGNED PA' }),
      asn: { ...results().asn, asn: 16509, name: 'AMAZON-02' },
      dns: { ...results().dns, ptrStatus: 'none', ptrNames: [], ptr: null, fcrdns: 'na' },
    }));
    expect(ind(a, 'datacenter')).toMatchObject({ state: 'hit', points: 3 });
    expect(ind(a, 'pa').points).toBe(1);
    expect(ind(a, 'no_ptr')).toMatchObject({ state: 'hit', points: 1 });
    expect(a).toMatchObject({ infraScore: 5, priority: 'HIGH', infraClass: 'datacenter' });
  });

  it('逆引きなしは、他にリスク要因がなければ加点しない', () => {
    const a = assess(ip, results({ dns: { ...results().dns, ptrStatus: 'broken', ptrNames: [], ptr: null, fcrdns: 'na' } }));
    expect(ind(a, 'no_ptr')).toMatchObject({ state: 'info', points: 0 });
  });

  it('IP 転貸: 運営者ドメインが 2 つ以上', () => {
    const a = assess(ip, results({ rdap: rdap({ domains: ['a.example', 'b.example'] }) }));
    expect(ind(a, 'sublease')).toMatchObject({ state: 'hit', points: 3 });
    expect(a.priority).toBe('MEDIUM');
  });

  it('私書箱: 組織の住所なら加点、個人の住所だけなら Info', () => {
    const org = { kind: 'org', name: 'X', roles: ['registrant'], handle: 'h', address: '1 St Suite 100', country: 'US' };
    expect(ind(assess(ip, results({ rdap: rdap({ addresses: [org] }) })), 'pobox')).toMatchObject({ state: 'hit', points: 2 });
    expect(ind(assess(ip, results({ rdap: rdap({ addresses: [{ ...org, kind: 'individual' }] }) })), 'pobox')).toMatchObject({ state: 'info', points: 0 });
  });

  it('検証済みクローラーは LOW、FCrDNS 不一致のクローラー PTR は脅威', () => {
    const verified = assess(ip, results({ dns: { ...results().dns, ptr: 'crawl-1.googlebot.com', ptrNames: ['crawl-1.googlebot.com'] } }));
    expect(verified).toMatchObject({ priority: 'LOW', infraClass: 'crawler', note: 'verified_crawler' });
    const spoofed = assess(ip, results({ dns: { ...results().dns, ptr: 'crawl-1.googlebot.com', ptrNames: ['crawl-1.googlebot.com'], fcrdns: 'not_verified' } }));
    expect(spoofed.threat.signals).toContain('Spoofed crawler PTR');
    expect(spoofed.priority).toBe('HIGH');
  });

  it('未検証の PTR では国内 ISP と判定しない（なりすまし防止）', () => {
    const a = assess(ip, results({ dns: { ...results().dns, ptr: 'p1.ocn.ne.jp', ptrNames: ['p1.ocn.ne.jp'], fcrdns: 'not_verified' } }));
    expect(ind(a, 'consumer_isp').state).toBe('none');
  });

  it('IPsum は 3 件以上で脅威、1〜2 件は Info', () => {
    expect(assess(ip, results({ ipsum: { ...results().ipsum, count: 3 } })).threat.level).toBe('DETECTED');
    const a = assess(ip, results({ ipsum: { ...results().ipsum, count: 2 } }));
    expect(ind(a, 'ipsum').state).toBe('info');
    expect(a.threat.level).toBe('NONE_FOUND');
  });

  it('Shodan: VPN タグは +3、プロキシ用ポートと乗っ取りタグは脅威', () => {
    const a = assess(ip, results({ internetdb: { ...results().internetdb, status: 'found', ports: [22, 1080], tags: ['vpn', 'compromised'] } }));
    expect(ind(a, 'vpn').points).toBe(3);
    expect(a.threat.signals).toEqual(['Shodan: compromised', 'Proxy service exposed']);
  });

  it('評判チェックが失敗し、検出もなければ UNKNOWN・PARTIAL（Clean と表示しない）', () => {
    const base = results();
    const a = assess(ip, results({
      tor: { ...base.tor, status: 'failed' },
      dnsbl: { ...base.dnsbl, lists: [{ ...base.dnsbl.lists[0]!, status: 'refused' }] },
    }));
    expect(a.threat.level).toBe('UNKNOWN');
    expect(a.confidence).toBe('PARTIAL');
    expect(a.unavailable).toEqual(['DNSBL (Spamhaus ZEN)', 'Tor Exit Node']);
    expect(ind(a, 'tor').state).toBe('unknown');
  });

  it('Spamhaus DROP 掲載は脅威シグナル（国内 ISP でも HIGH）', () => {
    const base = results();
    const a = assess(ip, results({ asn: { ...base.asn, asn: 4713 }, drop: { ...base.drop, status: 'listed', cidr: '192.0.2.0/24', sblid: 'SBL1' } }));
    expect(a.threat.signals).toEqual(['Spamhaus DROP SBL1']);
    expect(a.priority).toBe('HIGH');
    expect(ind(a, 'drop').params.copyright).toContain('Spamhaus');
  });

  it('DROP の取得に失敗したら UNKNOWN・PARTIAL', () => {
    const a = assess(ip, results({ drop: { ...results().drop, status: 'failed' } }));
    expect(a.threat.level).toBe('UNKNOWN');
    expect(a.unavailable).toEqual(['Spamhaus DROP']);
  });

  it('DQS キー未設定の ZEN は対象外とし、PARTIAL にしない', () => {
    const base = results();
    const a = assess(ip, results({ dnsbl: { ...base.dnsbl, lists: [{ ...base.dnsbl.lists[0]!, status: 'not_configured' }] } }));
    expect(ind(a, 'dnsbl', 'spamhaus').state).toBe('na');
    expect(a).toMatchObject({ confidence: 'FULL', threat: { level: 'NONE_FOUND' } });
  });

  it('Spamhaus ASN-DROP 掲載は脅威シグナル', () => {
    const base = results();
    const a = assess(ip, results({ asndrop: { ...base.asndrop, status: 'listed', matches: [{ asn: 64500, asname: 'BAD-AS', cc: 'US', domain: null }] } }));
    expect(a.threat.signals).toEqual(['Spamhaus ASN-DROP AS64500']);
    expect(a.priority).toBe('HIGH');
    expect(ind(a, 'asn_drop').params.asns).toEqual(['AS64500 (BAD-AS)']);
  });

  it('ASN-DROP: 経路なしは対象外、照合できなければ UNKNOWN・PARTIAL', () => {
    expect(ind(assess(ip, results({ asndrop: { ...results().asndrop, status: 'no_asn' } })), 'asn_drop').state).toBe('na');
    const a = assess(ip, results({ asndrop: { ...results().asndrop, status: 'failed' } }));
    expect(a.threat.level).toBe('UNKNOWN');
    expect(a.unavailable).toEqual(['Spamhaus ASN-DROP']);
  });

  it('Tor 出口ノード', () => {
    const a = assess(ip, results({ tor: { ...results().tor, status: 'listed' } }));
    expect(a).toMatchObject({ priority: 'HIGH', infraClass: 'tor' });
  });

  it('申告所在地の不一致', () => {
    const a = assess(ip, results({ geofeed: { ...results().geofeed, status: 'found', country: 'JP' }, rdap: rdap({ country: 'GB' }) }));
    expect(a.location).toBe('differ');
  });

  it('仮想ロケーションは Web 版では対象外', () => {
    expect(ind(assess(ip, results()), 'virtual_location').state).toBe('na');
  });
});
