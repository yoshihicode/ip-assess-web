import { describe, expect, it } from 'vitest';
import { isGlobalUnicast, parseIp, parsePrefix, prefixContains, reverseDnsName, reverseLabel } from '../src';

describe('parseIp', () => {
  it('IPv4 を受け付ける', () => {
    expect(parseIp('8.8.8.8')).toMatchObject({ version: 4, address: '8.8.8.8' });
    expect(parseIp(' 203.0.113.10 ')?.address).toBe('203.0.113.10');
  });

  it('不正な IPv4 を拒否する', () => {
    for (const s of ['256.1.1.1', '1.2.3', '01.2.3.4', '1.2.3.4/24', '1.2.3.4; rm -rf /', '']) expect(parseIp(s)).toBeNull();
  });

  it('IPv6 を RFC 5952 の形式に正規化する', () => {
    expect(parseIp('2001:4860:4860:0000:0000:0000:0000:8888')?.address).toBe('2001:4860:4860::8888');
    expect(parseIp('2001:DB8:0:0:1:0:0:1')?.address).toBe('2001:db8::1:0:0:1');
    expect(parseIp('::1')?.address).toBe('::1');
    expect(parseIp('2001:db8:0:1:1:1:1:1')?.address).toBe('2001:db8:0:1:1:1:1:1');
  });

  it('不正な IPv6 を拒否する', () => {
    for (const s of ['2001:db8::1::1', '2001:db8:::1', '12345::', 'fe80::1%eth0', '1:2:3:4:5:6:7:8:9']) expect(parseIp(s)).toBeNull();
  });

  it('IPv4 射影アドレスは IPv4 として扱う', () => {
    expect(parseIp('::ffff:192.0.2.1')).toMatchObject({ version: 4, address: '192.0.2.1' });
  });
});

describe('逆引き名', () => {
  it('IPv4', () => {
    const ip = parseIp('203.0.113.10')!;
    expect(reverseLabel(ip)).toBe('10.113.0.203');
    expect(reverseDnsName(ip)).toBe('10.113.0.203.in-addr.arpa');
  });
  it('IPv6 はニブル表記', () => {
    expect(reverseDnsName(parseIp('2001:db8::567:89ab')!)).toBe(
      'b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa',
    );
  });
});

describe('プレフィックス', () => {
  it('包含判定', () => {
    const p = parsePrefix('69.5.174.0/24')!;
    expect(prefixContains(p, parseIp('69.5.174.26')!)).toBe(true);
    expect(prefixContains(p, parseIp('69.5.175.1')!)).toBe(false);
    expect(prefixContains(parsePrefix('2400::/12')!, parseIp('240a:1::1')!)).toBe(true);
  });
  it('不正なプレフィックス', () => {
    expect(parsePrefix('1.2.3.0/33')).toBeNull();
    expect(parsePrefix('1.2.3.0/x')).toBeNull();
  });
});

describe('isGlobalUnicast', () => {
  it.each([
    ['8.8.8.8', true], ['10.0.0.1', false], ['192.168.1.1', false], ['100.64.0.1', false], ['127.0.0.1', false],
    ['203.0.113.10', false], ['224.0.0.1', false], ['2001:4860:4860::8888', true], ['2001:db8::1', false],
    ['fe80::1', false], ['fc00::1', false], ['::1', false],
  ])('%s -> %s', (ip, expected) => {
    expect(isGlobalUnicast(parseIp(ip)!)).toBe(expected);
  });
});
