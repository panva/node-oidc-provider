import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  ipv4ToInt,
  expandIPv6,
  isSpecialUseIPv4,
  isSpecialUseIPv6,
  isSpecialUseIP,
} from '../../lib/helpers/fetch_request.js';

describe('ipv4ToInt', () => {
  it('converts 0.0.0.0', { timeout: 3000 }, () => {
    assert.equal(ipv4ToInt('0.0.0.0'), 0x00000000);
  });

  it('converts 255.255.255.255', { timeout: 3000 }, () => {
    assert.equal(ipv4ToInt('255.255.255.255'), 0xffffffff);
  });

  it('converts 127.0.0.1', { timeout: 3000 }, () => {
    assert.equal(ipv4ToInt('127.0.0.1'), 0x7f000001);
  });

  it('converts 192.168.1.1', { timeout: 3000 }, () => {
    assert.equal(ipv4ToInt('192.168.1.1'), 0xc0a80101);
  });

  it('converts 10.0.0.1', { timeout: 3000 }, () => {
    assert.equal(ipv4ToInt('10.0.0.1'), 0x0a000001);
  });

  it('converts 172.16.0.1', { timeout: 3000 }, () => {
    assert.equal(ipv4ToInt('172.16.0.1'), 0xac100001);
  });

  it('converts 1.2.3.4', { timeout: 3000 }, () => {
    assert.equal(ipv4ToInt('1.2.3.4'), 0x01020304);
  });

  it('returns unsigned 32-bit values for high addresses', { timeout: 3000 }, () => {
    // Ensures >>> 0 works correctly — result must be positive
    assert.equal(ipv4ToInt('240.0.0.0'), 0xf0000000);
    ((value) => { assert.equal(typeof value, 'number'); assert.ok(value > 0); })(ipv4ToInt('240.0.0.0'));
    assert.equal(ipv4ToInt('128.0.0.0'), 0x80000000);
    ((value) => { assert.equal(typeof value, 'number'); assert.ok(value > 0); })(ipv4ToInt('128.0.0.0'));
  });
});

describe('expandIPv6', () => {
  it('expands a full address with no shortening', { timeout: 3000 }, () => {
    assert.equal(expandIPv6('2001:0db8:0000:0000:0000:0000:0000:0001'), '20010db8000000000000000000000001');
  });

  it('pads short groups', { timeout: 3000 }, () => {
    assert.equal(expandIPv6('2001:db8:0:0:0:0:0:1'), '20010db8000000000000000000000001');
  });

  it('expands :: at the start', { timeout: 3000 }, () => {
    assert.equal(expandIPv6('::1'), '00000000000000000000000000000001');
  });

  it('expands :: alone (unspecified address)', { timeout: 3000 }, () => {
    assert.equal(expandIPv6('::'), '00000000000000000000000000000000');
  });

  it('expands :: at the end', { timeout: 3000 }, () => {
    assert.equal(expandIPv6('fe80::'), 'fe800000000000000000000000000000');
  });

  it('expands :: in the middle', { timeout: 3000 }, () => {
    assert.equal(expandIPv6('fe80::1'), 'fe800000000000000000000000000001');
  });

  it('expands :: with groups on both sides', { timeout: 3000 }, () => {
    assert.equal(expandIPv6('2001:db8::ff00:42:8329'), '20010db8000000000000ff0000428329');
  });

  it('handles fully specified link-local', { timeout: 3000 }, () => {
    assert.equal(expandIPv6('fe80:0000:0000:0000:0000:0000:0000:0001'), 'fe800000000000000000000000000001');
  });
});

describe('isSpecialUseIPv4', () => {
  // --- Should be blocked ---

  describe('0.0.0.0/8 — "This network"', () => {
    it('blocks 0.0.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('0.0.0.0'), true));
    it('blocks 0.255.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('0.255.255.255'), true));
    it('allows 1.0.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('1.0.0.0'), false));
  });

  describe('10.0.0.0/8 — Private-Use', () => {
    it('blocks 10.0.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('10.0.0.0'), true));
    it('blocks 10.0.0.1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('10.0.0.1'), true));
    it('blocks 10.255.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('10.255.255.255'), true));
    it('allows 11.0.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('11.0.0.0'), false));
  });

  describe('100.64.0.0/10 — Shared Address Space', () => {
    it('blocks 100.64.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('100.64.0.0'), true));
    it('blocks 100.127.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('100.127.255.255'), true));
    it('allows 100.128.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('100.128.0.0'), false));
    it('allows 100.63.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('100.63.255.255'), false));
  });

  describe('127.0.0.0/8 — Loopback', () => {
    it('blocks 127.0.0.1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('127.0.0.1'), true));
    it('blocks 127.255.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('127.255.255.255'), true));
    it('allows 128.0.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('128.0.0.0'), false));
  });

  describe('169.254.0.0/16 — Link Local', () => {
    it('blocks 169.254.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('169.254.0.0'), true));
    it('blocks 169.254.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('169.254.255.255'), true));
    it('allows 169.255.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('169.255.0.0'), false));
    it('allows 169.253.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('169.253.255.255'), false));
  });

  describe('172.16.0.0/12 — Private-Use', () => {
    it('blocks 172.16.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('172.16.0.0'), true));
    it('blocks 172.16.0.1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('172.16.0.1'), true));
    it('blocks 172.31.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('172.31.255.255'), true));
    it('allows 172.32.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('172.32.0.0'), false));
    it('allows 172.15.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('172.15.255.255'), false));
  });

  describe('192.0.0.0/24 — IETF Protocol Assignments', () => {
    it('blocks 192.0.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.0.0.0'), true));
    it('blocks 192.0.0.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.0.0.255'), true));
    it('allows 192.0.1.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.0.1.0'), false));
  });

  describe('192.0.2.0/24 — Documentation (TEST-NET-1)', () => {
    it('blocks 192.0.2.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.0.2.0'), true));
    it('blocks 192.0.2.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.0.2.255'), true));
    it('allows 192.0.3.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.0.3.0'), false));
  });

  describe('192.168.0.0/16 — Private-Use', () => {
    it('blocks 192.168.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.168.0.0'), true));
    it('blocks 192.168.0.1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.168.0.1'), true));
    it('blocks 192.168.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.168.255.255'), true));
    it('allows 192.169.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.169.0.0'), false));
  });

  describe('198.18.0.0/15 — Benchmarking', () => {
    it('blocks 198.18.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('198.18.0.0'), true));
    it('blocks 198.19.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('198.19.255.255'), true));
    it('allows 198.20.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('198.20.0.0'), false));
    it('allows 198.17.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('198.17.255.255'), false));
  });

  describe('198.51.100.0/24 — Documentation (TEST-NET-2)', () => {
    it('blocks 198.51.100.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('198.51.100.0'), true));
    it('blocks 198.51.100.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('198.51.100.255'), true));
    it('allows 198.51.101.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('198.51.101.0'), false));
  });

  describe('203.0.113.0/24 — Documentation (TEST-NET-3)', () => {
    it('blocks 203.0.113.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('203.0.113.0'), true));
    it('blocks 203.0.113.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('203.0.113.255'), true));
    it('allows 203.0.114.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('203.0.114.0'), false));
  });

  describe('240.0.0.0/4 — Reserved', () => {
    it('blocks 240.0.0.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('240.0.0.0'), true));
    it('blocks 255.255.255.254', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('255.255.255.254'), true));
    it('blocks 255.255.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('255.255.255.255'), true));
    it('allows 239.255.255.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('239.255.255.255'), false));
  });

  describe('192.31.196.0/24 — AS112-v4', () => {
    it('blocks 192.31.196.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.31.196.0'), true));
    it('blocks 192.31.196.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.31.196.255'), true));
    it('allows 192.31.197.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.31.197.0'), false));
  });

  describe('192.52.193.0/24 — AMT', () => {
    it('blocks 192.52.193.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.52.193.0'), true));
    it('blocks 192.52.193.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.52.193.255'), true));
    it('allows 192.52.194.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.52.194.0'), false));
  });

  describe('192.88.99.0/24 — Deprecated (6to4 Relay Anycast)', () => {
    it('blocks 192.88.99.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.88.99.0'), true));
    it('blocks 192.88.99.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.88.99.255'), true));
    it('allows 192.88.100.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.88.100.0'), false));
  });

  describe('192.175.48.0/24 — Direct Delegation AS112 Service', () => {
    it('blocks 192.175.48.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.175.48.0'), true));
    it('blocks 192.175.48.255', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.175.48.255'), true));
    it('allows 192.175.49.0', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('192.175.49.0'), false));
  });

  // --- Should be allowed (public addresses) ---

  describe('public/global addresses', () => {
    it('allows 8.8.8.8', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('8.8.8.8'), false));
    it('allows 1.1.1.1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('1.1.1.1'), false));
    it('allows 93.184.216.34', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('93.184.216.34'), false));
    it('allows 142.250.80.46', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('142.250.80.46'), false));
    it('allows 104.16.132.229', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv4('104.16.132.229'), false));
  });
});

describe('isSpecialUseIPv6', () => {
  // --- Explicit special cases ---

  describe('::1 — Loopback', () => {
    it('blocks ::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('::1'), true));
  });

  describe(':: — Unspecified', () => {
    it('blocks ::', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('::'), true));
  });

  // --- IPv4-mapped addresses ---

  describe('::ffff:0:0/96 — IPv4-mapped', () => {
    it('blocks ::ffff:127.0.0.1 (loopback)', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('::ffff:127.0.0.1'), true));
    it('blocks ::ffff:10.0.0.1 (private)', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('::ffff:10.0.0.1'), true));
    it('blocks ::ffff:192.168.1.1 (private)', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('::ffff:192.168.1.1'), true));
    it('blocks ::ffff:172.16.0.1 (private)', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('::ffff:172.16.0.1'), true));
    it('allows ::ffff:8.8.8.8 (public)', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('::ffff:8.8.8.8'), false));
    it('allows ::ffff:1.1.1.1 (public)', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('::ffff:1.1.1.1'), false));
    it('is case-insensitive', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('::FFFF:10.0.0.1'), true));
  });

  // --- Prefix-matched ranges ---

  describe('64:ff9b::/96 — IPv4-IPv6 Translation', () => {
    it('blocks 64:ff9b::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('64:ff9b::1'), true));
    it('blocks 64:ff9b::ffff:ffff', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('64:ff9b::ffff:ffff'), true));
    it('allows 64:ff9a::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('64:ff9a::1'), false));
  });

  describe('64:ff9b:1::/48 — IPv4-IPv6 Translation', () => {
    it('blocks 64:ff9b:1::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('64:ff9b:1::1'), true));
    it('allows 64:ff9b:2::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('64:ff9b:2::1'), false));
  });

  describe('100::/64 — Discard-Only', () => {
    it('blocks 100::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('100::1'), true));
    it('blocks 100::ffff:ffff:ffff:ffff', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('100::ffff:ffff:ffff:ffff'), true));
    it('allows 100:0:0:1::1', { timeout: 3000 }, () => {
      // 100:0:0:1::/64 is Dummy IPv6 Prefix, but 100:0:0:2::1 should be allowed
      assert.equal(isSpecialUseIPv6('100:0:0:2::1'), false);
    });
  });

  describe('100:0:0:1::/64 — Dummy IPv6 Prefix', () => {
    it('blocks 100:0:0:1::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('100:0:0:1::1'), true));
    it('blocks 100:0:0:1:ffff:ffff:ffff:ffff', { timeout: 3000 }, () => {
      assert.equal(isSpecialUseIPv6('100:0:0:1:ffff:ffff:ffff:ffff'), true);
    });
  });

  describe('2001::/23 — IETF Protocol Assignments', () => {
    it('blocks 2001:0:0:0:0:0:0:1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('2001:0:0:0:0:0:0:1'), true));
    it('blocks 2001:01ff:ffff:ffff:ffff:ffff:ffff:ffff', { timeout: 3000 }, () => {
      assert.equal(isSpecialUseIPv6('2001:01ff:ffff:ffff:ffff:ffff:ffff:ffff'), true);
    });
    it('allows 2001:0200::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('2001:0200::1'), false));
  });

  describe('2001:db8::/32 — Documentation', () => {
    it('blocks 2001:db8::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('2001:db8::1'), true));
    it('blocks 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', { timeout: 3000 }, () => {
      assert.equal(isSpecialUseIPv6('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'), true);
    });
    it('allows 2001:db9::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('2001:db9::1'), false));
  });

  describe('2002::/16 — 6to4', () => {
    it('blocks 2002::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('2002::1'), true));
    it('blocks 2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff', { timeout: 3000 }, () => {
      assert.equal(isSpecialUseIPv6('2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), true);
    });
    it('allows 2003::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('2003::1'), false));
  });

  describe('2620:4f:8000::/48 — Direct Delegation AS112 Service', () => {
    it('blocks 2620:4f:8000::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('2620:4f:8000::1'), true));
    it('allows 2620:4f:8001::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('2620:4f:8001::1'), false));
  });

  describe('3fff::/20 — Documentation', () => {
    it('blocks 3fff:0::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('3fff:0::1'), true));
    it('blocks 3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff', { timeout: 3000 }, () => {
      assert.equal(isSpecialUseIPv6('3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff'), true);
    });
    it('allows 3fff:1000::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('3fff:1000::1'), false));
  });

  describe('5f00::/16 — Segment Routing (SRv6) SIDs', () => {
    it('blocks 5f00::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('5f00::1'), true));
    it('allows 5f01::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('5f01::1'), false));
  });

  describe('fc00::/7 — Unique-Local', () => {
    it('blocks fc00::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('fc00::1'), true));
    it('blocks fd00::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('fd00::1'), true));
    it('blocks fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', { timeout: 3000 }, () => {
      assert.equal(isSpecialUseIPv6('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), true);
    });
    it('allows fe00::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('fe00::1'), false));
    it('allows fb00::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('fb00::1'), false));
  });

  describe('fe80::/10 — Link-Local Unicast', () => {
    it('blocks fe80::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('fe80::1'), true));
    it('blocks fe80::1%eth0 style (without zone id)', { timeout: 3000 }, () => {
      // Node's socket.remoteAddress won't include zone ids,
      // but test the fe80-febf range boundaries
      assert.equal(isSpecialUseIPv6('fe9f::1'), true);
      assert.equal(isSpecialUseIPv6('feaf::1'), true);
      assert.equal(isSpecialUseIPv6('febf::1'), true);
    });
    it('allows fec0::1 (outside /10)', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('fec0::1'), false));
  });

  // --- Case insensitivity ---

  describe('case insensitivity', () => {
    it('blocks FC00::1 (uppercase)', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('FC00::1'), true));
    it('blocks FE80::1 (uppercase)', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('FE80::1'), true));
    it('blocks 2001:DB8::1 (mixed case)', { timeout: 3000 }, () => assert.equal(isSpecialUseIPv6('2001:DB8::1'), true));
  });

  // --- Public/global addresses should be allowed ---

  describe('public/global addresses', () => {
    it('allows 2607:f8b0:4004:800::200e (Google)', { timeout: 3000 }, () => {
      assert.equal(isSpecialUseIPv6('2607:f8b0:4004:800::200e'), false);
    });
    it('allows 2606:4700::6810:84e5 (Cloudflare)', { timeout: 3000 }, () => {
      assert.equal(isSpecialUseIPv6('2606:4700::6810:84e5'), false);
    });
    it('allows 2620:1ec:c11::200 (random global)', { timeout: 3000 }, () => {
      assert.equal(isSpecialUseIPv6('2620:1ec:c11::200'), false);
    });
  });
});

describe('isSpecialUseIP', () => {
  describe('dispatches IPv4', () => {
    it('blocks 127.0.0.1', { timeout: 3000 }, () => assert.equal(isSpecialUseIP('127.0.0.1'), true));
    it('blocks 10.0.0.1', { timeout: 3000 }, () => assert.equal(isSpecialUseIP('10.0.0.1'), true));
    it('blocks 192.168.1.1', { timeout: 3000 }, () => assert.equal(isSpecialUseIP('192.168.1.1'), true));
    it('allows 8.8.8.8', { timeout: 3000 }, () => assert.equal(isSpecialUseIP('8.8.8.8'), false));
  });

  describe('dispatches IPv6', () => {
    it('blocks ::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIP('::1'), true));
    it('blocks fe80::1', { timeout: 3000 }, () => assert.equal(isSpecialUseIP('fe80::1'), true));
    it('blocks ::ffff:192.168.1.1', { timeout: 3000 }, () => assert.equal(isSpecialUseIP('::ffff:192.168.1.1'), true));
    it('allows 2607:f8b0:4004:800::200e', { timeout: 3000 }, () => {
      assert.equal(isSpecialUseIP('2607:f8b0:4004:800::200e'), false);
    });
  });
});
