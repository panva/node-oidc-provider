import { expect } from 'chai';

import {
  ipv4ToInt,
  expandIPv6,
  isSpecialUseIPv4,
  isSpecialUseIPv6,
  isSpecialUseIP,
} from '../../lib/helpers/fetch_request.js';

describe('ipv4ToInt', () => {
  it('converts 0.0.0.0', () => {
    expect(ipv4ToInt('0.0.0.0')).to.equal(0x00000000);
  });

  it('converts 255.255.255.255', () => {
    expect(ipv4ToInt('255.255.255.255')).to.equal(0xffffffff);
  });

  it('converts 127.0.0.1', () => {
    expect(ipv4ToInt('127.0.0.1')).to.equal(0x7f000001);
  });

  it('converts 192.168.1.1', () => {
    expect(ipv4ToInt('192.168.1.1')).to.equal(0xc0a80101);
  });

  it('converts 10.0.0.1', () => {
    expect(ipv4ToInt('10.0.0.1')).to.equal(0x0a000001);
  });

  it('converts 172.16.0.1', () => {
    expect(ipv4ToInt('172.16.0.1')).to.equal(0xac100001);
  });

  it('converts 1.2.3.4', () => {
    expect(ipv4ToInt('1.2.3.4')).to.equal(0x01020304);
  });

  it('returns unsigned 32-bit values for high addresses', () => {
    // Ensures >>> 0 works correctly — result must be positive
    expect(ipv4ToInt('240.0.0.0')).to.equal(0xf0000000);
    expect(ipv4ToInt('240.0.0.0')).to.be.above(0);
    expect(ipv4ToInt('128.0.0.0')).to.equal(0x80000000);
    expect(ipv4ToInt('128.0.0.0')).to.be.above(0);
  });
});

describe('expandIPv6', () => {
  it('expands a full address with no shortening', () => {
    expect(expandIPv6('2001:0db8:0000:0000:0000:0000:0000:0001'))
      .to.equal('20010db8000000000000000000000001');
  });

  it('pads short groups', () => {
    expect(expandIPv6('2001:db8:0:0:0:0:0:1'))
      .to.equal('20010db8000000000000000000000001');
  });

  it('expands :: at the start', () => {
    expect(expandIPv6('::1'))
      .to.equal('00000000000000000000000000000001');
  });

  it('expands :: alone (unspecified address)', () => {
    expect(expandIPv6('::'))
      .to.equal('00000000000000000000000000000000');
  });

  it('expands :: at the end', () => {
    expect(expandIPv6('fe80::'))
      .to.equal('fe800000000000000000000000000000');
  });

  it('expands :: in the middle', () => {
    expect(expandIPv6('fe80::1'))
      .to.equal('fe800000000000000000000000000001');
  });

  it('expands :: with groups on both sides', () => {
    expect(expandIPv6('2001:db8::ff00:42:8329'))
      .to.equal('20010db8000000000000ff0000428329');
  });

  it('handles fully specified link-local', () => {
    expect(expandIPv6('fe80:0000:0000:0000:0000:0000:0000:0001'))
      .to.equal('fe800000000000000000000000000001');
  });
});

describe('isSpecialUseIPv4', () => {
  // --- Should be blocked ---

  describe('0.0.0.0/8 — "This network"', () => {
    it('blocks 0.0.0.0', () => expect(isSpecialUseIPv4('0.0.0.0')).to.be.true);
    it('blocks 0.255.255.255', () => expect(isSpecialUseIPv4('0.255.255.255')).to.be.true);
    it('allows 1.0.0.0', () => expect(isSpecialUseIPv4('1.0.0.0')).to.be.false);
  });

  describe('10.0.0.0/8 — Private-Use', () => {
    it('blocks 10.0.0.0', () => expect(isSpecialUseIPv4('10.0.0.0')).to.be.true);
    it('blocks 10.0.0.1', () => expect(isSpecialUseIPv4('10.0.0.1')).to.be.true);
    it('blocks 10.255.255.255', () => expect(isSpecialUseIPv4('10.255.255.255')).to.be.true);
    it('allows 11.0.0.0', () => expect(isSpecialUseIPv4('11.0.0.0')).to.be.false);
  });

  describe('100.64.0.0/10 — Shared Address Space', () => {
    it('blocks 100.64.0.0', () => expect(isSpecialUseIPv4('100.64.0.0')).to.be.true);
    it('blocks 100.127.255.255', () => expect(isSpecialUseIPv4('100.127.255.255')).to.be.true);
    it('allows 100.128.0.0', () => expect(isSpecialUseIPv4('100.128.0.0')).to.be.false);
    it('allows 100.63.255.255', () => expect(isSpecialUseIPv4('100.63.255.255')).to.be.false);
  });

  describe('127.0.0.0/8 — Loopback', () => {
    it('blocks 127.0.0.1', () => expect(isSpecialUseIPv4('127.0.0.1')).to.be.true);
    it('blocks 127.255.255.255', () => expect(isSpecialUseIPv4('127.255.255.255')).to.be.true);
    it('allows 128.0.0.0', () => expect(isSpecialUseIPv4('128.0.0.0')).to.be.false);
  });

  describe('169.254.0.0/16 — Link Local', () => {
    it('blocks 169.254.0.0', () => expect(isSpecialUseIPv4('169.254.0.0')).to.be.true);
    it('blocks 169.254.255.255', () => expect(isSpecialUseIPv4('169.254.255.255')).to.be.true);
    it('allows 169.255.0.0', () => expect(isSpecialUseIPv4('169.255.0.0')).to.be.false);
    it('allows 169.253.255.255', () => expect(isSpecialUseIPv4('169.253.255.255')).to.be.false);
  });

  describe('172.16.0.0/12 — Private-Use', () => {
    it('blocks 172.16.0.0', () => expect(isSpecialUseIPv4('172.16.0.0')).to.be.true);
    it('blocks 172.16.0.1', () => expect(isSpecialUseIPv4('172.16.0.1')).to.be.true);
    it('blocks 172.31.255.255', () => expect(isSpecialUseIPv4('172.31.255.255')).to.be.true);
    it('allows 172.32.0.0', () => expect(isSpecialUseIPv4('172.32.0.0')).to.be.false);
    it('allows 172.15.255.255', () => expect(isSpecialUseIPv4('172.15.255.255')).to.be.false);
  });

  describe('192.0.0.0/24 — IETF Protocol Assignments', () => {
    it('blocks 192.0.0.0', () => expect(isSpecialUseIPv4('192.0.0.0')).to.be.true);
    it('blocks 192.0.0.255', () => expect(isSpecialUseIPv4('192.0.0.255')).to.be.true);
    it('allows 192.0.1.0', () => expect(isSpecialUseIPv4('192.0.1.0')).to.be.false);
  });

  describe('192.0.2.0/24 — Documentation (TEST-NET-1)', () => {
    it('blocks 192.0.2.0', () => expect(isSpecialUseIPv4('192.0.2.0')).to.be.true);
    it('blocks 192.0.2.255', () => expect(isSpecialUseIPv4('192.0.2.255')).to.be.true);
    it('allows 192.0.3.0', () => expect(isSpecialUseIPv4('192.0.3.0')).to.be.false);
  });

  describe('192.168.0.0/16 — Private-Use', () => {
    it('blocks 192.168.0.0', () => expect(isSpecialUseIPv4('192.168.0.0')).to.be.true);
    it('blocks 192.168.0.1', () => expect(isSpecialUseIPv4('192.168.0.1')).to.be.true);
    it('blocks 192.168.255.255', () => expect(isSpecialUseIPv4('192.168.255.255')).to.be.true);
    it('allows 192.169.0.0', () => expect(isSpecialUseIPv4('192.169.0.0')).to.be.false);
  });

  describe('198.18.0.0/15 — Benchmarking', () => {
    it('blocks 198.18.0.0', () => expect(isSpecialUseIPv4('198.18.0.0')).to.be.true);
    it('blocks 198.19.255.255', () => expect(isSpecialUseIPv4('198.19.255.255')).to.be.true);
    it('allows 198.20.0.0', () => expect(isSpecialUseIPv4('198.20.0.0')).to.be.false);
    it('allows 198.17.255.255', () => expect(isSpecialUseIPv4('198.17.255.255')).to.be.false);
  });

  describe('198.51.100.0/24 — Documentation (TEST-NET-2)', () => {
    it('blocks 198.51.100.0', () => expect(isSpecialUseIPv4('198.51.100.0')).to.be.true);
    it('blocks 198.51.100.255', () => expect(isSpecialUseIPv4('198.51.100.255')).to.be.true);
    it('allows 198.51.101.0', () => expect(isSpecialUseIPv4('198.51.101.0')).to.be.false);
  });

  describe('203.0.113.0/24 — Documentation (TEST-NET-3)', () => {
    it('blocks 203.0.113.0', () => expect(isSpecialUseIPv4('203.0.113.0')).to.be.true);
    it('blocks 203.0.113.255', () => expect(isSpecialUseIPv4('203.0.113.255')).to.be.true);
    it('allows 203.0.114.0', () => expect(isSpecialUseIPv4('203.0.114.0')).to.be.false);
  });

  describe('240.0.0.0/4 — Reserved', () => {
    it('blocks 240.0.0.0', () => expect(isSpecialUseIPv4('240.0.0.0')).to.be.true);
    it('blocks 255.255.255.254', () => expect(isSpecialUseIPv4('255.255.255.254')).to.be.true);
    it('blocks 255.255.255.255', () => expect(isSpecialUseIPv4('255.255.255.255')).to.be.true);
    it('allows 239.255.255.255', () => expect(isSpecialUseIPv4('239.255.255.255')).to.be.false);
  });

  describe('192.31.196.0/24 — AS112-v4', () => {
    it('blocks 192.31.196.0', () => expect(isSpecialUseIPv4('192.31.196.0')).to.be.true);
    it('blocks 192.31.196.255', () => expect(isSpecialUseIPv4('192.31.196.255')).to.be.true);
    it('allows 192.31.197.0', () => expect(isSpecialUseIPv4('192.31.197.0')).to.be.false);
  });

  describe('192.52.193.0/24 — AMT', () => {
    it('blocks 192.52.193.0', () => expect(isSpecialUseIPv4('192.52.193.0')).to.be.true);
    it('blocks 192.52.193.255', () => expect(isSpecialUseIPv4('192.52.193.255')).to.be.true);
    it('allows 192.52.194.0', () => expect(isSpecialUseIPv4('192.52.194.0')).to.be.false);
  });

  describe('192.88.99.0/24 — Deprecated (6to4 Relay Anycast)', () => {
    it('blocks 192.88.99.0', () => expect(isSpecialUseIPv4('192.88.99.0')).to.be.true);
    it('blocks 192.88.99.255', () => expect(isSpecialUseIPv4('192.88.99.255')).to.be.true);
    it('allows 192.88.100.0', () => expect(isSpecialUseIPv4('192.88.100.0')).to.be.false);
  });

  describe('192.175.48.0/24 — Direct Delegation AS112 Service', () => {
    it('blocks 192.175.48.0', () => expect(isSpecialUseIPv4('192.175.48.0')).to.be.true);
    it('blocks 192.175.48.255', () => expect(isSpecialUseIPv4('192.175.48.255')).to.be.true);
    it('allows 192.175.49.0', () => expect(isSpecialUseIPv4('192.175.49.0')).to.be.false);
  });

  // --- Should be allowed (public addresses) ---

  describe('public/global addresses', () => {
    it('allows 8.8.8.8', () => expect(isSpecialUseIPv4('8.8.8.8')).to.be.false);
    it('allows 1.1.1.1', () => expect(isSpecialUseIPv4('1.1.1.1')).to.be.false);
    it('allows 93.184.216.34', () => expect(isSpecialUseIPv4('93.184.216.34')).to.be.false);
    it('allows 142.250.80.46', () => expect(isSpecialUseIPv4('142.250.80.46')).to.be.false);
    it('allows 104.16.132.229', () => expect(isSpecialUseIPv4('104.16.132.229')).to.be.false);
  });
});

describe('isSpecialUseIPv6', () => {
  // --- Explicit special cases ---

  describe('::1 — Loopback', () => {
    it('blocks ::1', () => expect(isSpecialUseIPv6('::1')).to.be.true);
  });

  describe(':: — Unspecified', () => {
    it('blocks ::', () => expect(isSpecialUseIPv6('::')).to.be.true);
  });

  // --- IPv4-mapped addresses ---

  describe('::ffff:0:0/96 — IPv4-mapped', () => {
    it('blocks ::ffff:127.0.0.1 (loopback)', () => expect(isSpecialUseIPv6('::ffff:127.0.0.1')).to.be.true);
    it('blocks ::ffff:10.0.0.1 (private)', () => expect(isSpecialUseIPv6('::ffff:10.0.0.1')).to.be.true);
    it('blocks ::ffff:192.168.1.1 (private)', () => expect(isSpecialUseIPv6('::ffff:192.168.1.1')).to.be.true);
    it('blocks ::ffff:172.16.0.1 (private)', () => expect(isSpecialUseIPv6('::ffff:172.16.0.1')).to.be.true);
    it('allows ::ffff:8.8.8.8 (public)', () => expect(isSpecialUseIPv6('::ffff:8.8.8.8')).to.be.false);
    it('allows ::ffff:1.1.1.1 (public)', () => expect(isSpecialUseIPv6('::ffff:1.1.1.1')).to.be.false);
    it('is case-insensitive', () => expect(isSpecialUseIPv6('::FFFF:10.0.0.1')).to.be.true);
  });

  // --- Prefix-matched ranges ---

  describe('64:ff9b::/96 — IPv4-IPv6 Translation', () => {
    it('blocks 64:ff9b::1', () => expect(isSpecialUseIPv6('64:ff9b::1')).to.be.true);
    it('blocks 64:ff9b::ffff:ffff', () => expect(isSpecialUseIPv6('64:ff9b::ffff:ffff')).to.be.true);
    it('allows 64:ff9a::1', () => expect(isSpecialUseIPv6('64:ff9a::1')).to.be.false);
  });

  describe('64:ff9b:1::/48 — IPv4-IPv6 Translation', () => {
    it('blocks 64:ff9b:1::1', () => expect(isSpecialUseIPv6('64:ff9b:1::1')).to.be.true);
    it('allows 64:ff9b:2::1', () => expect(isSpecialUseIPv6('64:ff9b:2::1')).to.be.false);
  });

  describe('100::/64 — Discard-Only', () => {
    it('blocks 100::1', () => expect(isSpecialUseIPv6('100::1')).to.be.true);
    it('blocks 100::ffff:ffff:ffff:ffff', () => expect(isSpecialUseIPv6('100::ffff:ffff:ffff:ffff')).to.be.true);
    it('allows 100:0:0:1::1', () => {
      // 100:0:0:1::/64 is Dummy IPv6 Prefix, but 100:0:0:2::1 should be allowed
      expect(isSpecialUseIPv6('100:0:0:2::1')).to.be.false;
    });
  });

  describe('100:0:0:1::/64 — Dummy IPv6 Prefix', () => {
    it('blocks 100:0:0:1::1', () => expect(isSpecialUseIPv6('100:0:0:1::1')).to.be.true);
    it('blocks 100:0:0:1:ffff:ffff:ffff:ffff', () => {
      expect(isSpecialUseIPv6('100:0:0:1:ffff:ffff:ffff:ffff')).to.be.true;
    });
  });

  describe('2001::/23 — IETF Protocol Assignments', () => {
    it('blocks 2001:0:0:0:0:0:0:1', () => expect(isSpecialUseIPv6('2001:0:0:0:0:0:0:1')).to.be.true);
    it('blocks 2001:01ff:ffff:ffff:ffff:ffff:ffff:ffff', () => {
      expect(isSpecialUseIPv6('2001:01ff:ffff:ffff:ffff:ffff:ffff:ffff')).to.be.true;
    });
    it('allows 2001:0200::1', () => expect(isSpecialUseIPv6('2001:0200::1')).to.be.false);
  });

  describe('2001:db8::/32 — Documentation', () => {
    it('blocks 2001:db8::1', () => expect(isSpecialUseIPv6('2001:db8::1')).to.be.true);
    it('blocks 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', () => {
      expect(isSpecialUseIPv6('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff')).to.be.true;
    });
    it('allows 2001:db9::1', () => expect(isSpecialUseIPv6('2001:db9::1')).to.be.false);
  });

  describe('2002::/16 — 6to4', () => {
    it('blocks 2002::1', () => expect(isSpecialUseIPv6('2002::1')).to.be.true);
    it('blocks 2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff', () => {
      expect(isSpecialUseIPv6('2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff')).to.be.true;
    });
    it('allows 2003::1', () => expect(isSpecialUseIPv6('2003::1')).to.be.false);
  });

  describe('2620:4f:8000::/48 — Direct Delegation AS112 Service', () => {
    it('blocks 2620:4f:8000::1', () => expect(isSpecialUseIPv6('2620:4f:8000::1')).to.be.true);
    it('allows 2620:4f:8001::1', () => expect(isSpecialUseIPv6('2620:4f:8001::1')).to.be.false);
  });

  describe('3fff::/20 — Documentation', () => {
    it('blocks 3fff:0::1', () => expect(isSpecialUseIPv6('3fff:0::1')).to.be.true);
    it('blocks 3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff', () => {
      expect(isSpecialUseIPv6('3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff')).to.be.true;
    });
    it('allows 3fff:1000::1', () => expect(isSpecialUseIPv6('3fff:1000::1')).to.be.false);
  });

  describe('5f00::/16 — Segment Routing (SRv6) SIDs', () => {
    it('blocks 5f00::1', () => expect(isSpecialUseIPv6('5f00::1')).to.be.true);
    it('allows 5f01::1', () => expect(isSpecialUseIPv6('5f01::1')).to.be.false);
  });

  describe('fc00::/7 — Unique-Local', () => {
    it('blocks fc00::1', () => expect(isSpecialUseIPv6('fc00::1')).to.be.true);
    it('blocks fd00::1', () => expect(isSpecialUseIPv6('fd00::1')).to.be.true);
    it('blocks fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', () => {
      expect(isSpecialUseIPv6('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')).to.be.true;
    });
    it('allows fe00::1', () => expect(isSpecialUseIPv6('fe00::1')).to.be.false);
    it('allows fb00::1', () => expect(isSpecialUseIPv6('fb00::1')).to.be.false);
  });

  describe('fe80::/10 — Link-Local Unicast', () => {
    it('blocks fe80::1', () => expect(isSpecialUseIPv6('fe80::1')).to.be.true);
    it('blocks fe80::1%eth0 style (without zone id)', () => {
      // Node's socket.remoteAddress won't include zone ids,
      // but test the fe80-febf range boundaries
      expect(isSpecialUseIPv6('fe9f::1')).to.be.true;
      expect(isSpecialUseIPv6('feaf::1')).to.be.true;
      expect(isSpecialUseIPv6('febf::1')).to.be.true;
    });
    it('allows fec0::1 (outside /10)', () => expect(isSpecialUseIPv6('fec0::1')).to.be.false);
  });

  // --- Case insensitivity ---

  describe('case insensitivity', () => {
    it('blocks FC00::1 (uppercase)', () => expect(isSpecialUseIPv6('FC00::1')).to.be.true);
    it('blocks FE80::1 (uppercase)', () => expect(isSpecialUseIPv6('FE80::1')).to.be.true);
    it('blocks 2001:DB8::1 (mixed case)', () => expect(isSpecialUseIPv6('2001:DB8::1')).to.be.true);
  });

  // --- Public/global addresses should be allowed ---

  describe('public/global addresses', () => {
    it('allows 2607:f8b0:4004:800::200e (Google)', () => {
      expect(isSpecialUseIPv6('2607:f8b0:4004:800::200e')).to.be.false;
    });
    it('allows 2606:4700::6810:84e5 (Cloudflare)', () => {
      expect(isSpecialUseIPv6('2606:4700::6810:84e5')).to.be.false;
    });
    it('allows 2620:1ec:c11::200 (random global)', () => {
      expect(isSpecialUseIPv6('2620:1ec:c11::200')).to.be.false;
    });
  });
});

describe('isSpecialUseIP', () => {
  describe('dispatches IPv4', () => {
    it('blocks 127.0.0.1', () => expect(isSpecialUseIP('127.0.0.1')).to.be.true);
    it('blocks 10.0.0.1', () => expect(isSpecialUseIP('10.0.0.1')).to.be.true);
    it('blocks 192.168.1.1', () => expect(isSpecialUseIP('192.168.1.1')).to.be.true);
    it('allows 8.8.8.8', () => expect(isSpecialUseIP('8.8.8.8')).to.be.false);
  });

  describe('dispatches IPv6', () => {
    it('blocks ::1', () => expect(isSpecialUseIP('::1')).to.be.true);
    it('blocks fe80::1', () => expect(isSpecialUseIP('fe80::1')).to.be.true);
    it('blocks ::ffff:192.168.1.1', () => expect(isSpecialUseIP('::ffff:192.168.1.1')).to.be.true);
    it('allows 2607:f8b0:4004:800::200e', () => {
      expect(isSpecialUseIP('2607:f8b0:4004:800::200e')).to.be.false;
    });
  });
});
