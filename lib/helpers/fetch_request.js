/* eslint-disable no-bitwise, no-plusplus */
import * as undici from 'undici';

import instance from './weak_cache.js';

// IANA IPv4 Special-Purpose Address Space
// https://www.iana.org/assignments/iana-ipv4-special-registry/
const SPECIAL_USE_IPV4 = [
  { prefix: 0x00000000, mask: 0xff000000 }, // 0.0.0.0/8 "This network" [RFC791]
  { prefix: 0x0a000000, mask: 0xff000000 }, // 10.0.0.0/8 Private-Use [RFC1918]
  { prefix: 0x64400000, mask: 0xffc00000 }, // 100.64.0.0/10 Shared Address Space [RFC6598]
  { prefix: 0x7f000000, mask: 0xff000000 }, // 127.0.0.0/8 Loopback [RFC1122]
  { prefix: 0xa9fe0000, mask: 0xffff0000 }, // 169.254.0.0/16 Link Local [RFC3927]
  { prefix: 0xac100000, mask: 0xfff00000 }, // 172.16.0.0/12 Private-Use [RFC1918]
  { prefix: 0xc0000000, mask: 0xffffff00 }, // 192.0.0.0/24 IETF Protocol Assignments [RFC6890]
  { prefix: 0xc0000200, mask: 0xffffff00 }, // 192.0.2.0/24 Documentation (TEST-NET-1) [RFC5737]
  { prefix: 0xc01fc400, mask: 0xffffff00 }, // 192.31.196.0/24 AS112-v4 [RFC7535]
  { prefix: 0xc034c100, mask: 0xffffff00 }, // 192.52.193.0/24 AMT [RFC7450]
  { prefix: 0xc0586300, mask: 0xffffff00 }, // 192.88.99.0/24 Deprecated (6to4 Relay Anycast) [RFC7526]
  { prefix: 0xc0a80000, mask: 0xffff0000 }, // 192.168.0.0/16 Private-Use [RFC1918]
  { prefix: 0xc0af3000, mask: 0xffffff00 }, // 192.175.48.0/24 Direct Delegation AS112 Service [RFC7534]
  { prefix: 0xc6120000, mask: 0xfffe0000 }, // 198.18.0.0/15 Benchmarking [RFC2544]
  { prefix: 0xc6336400, mask: 0xffffff00 }, // 198.51.100.0/24 Documentation (TEST-NET-2) [RFC5737]
  { prefix: 0xcb007100, mask: 0xffffff00 }, // 203.0.113.0/24 Documentation (TEST-NET-3) [RFC5737]
  { prefix: 0xf0000000, mask: 0xf0000000 }, // 240.0.0.0/4 Reserved [RFC1112]

  // TCP cannot connect to multicast
  // { prefix: 0xe0000000, mask: 0xf0000000 }, // 224.0.0.0/4 Multicast [RFC1112]
  // TCP cannot connect to broadcast
  // { prefix: 0xffffffff, mask: 0xffffffff }, // 255.255.255.255/32 Limited Broadcast [RFC919][RFC8190]
];

function ipv4ToInt(ip) {
  // Parses an IPv4 dotted-decimal string into an unsigned 32-bit integer
  // without allocating a split('.') array. Walks the string character by
  // character, accumulating each decimal octet then shifting it into the
  // result. The final >>> 0 ensures an unsigned value.
  let result = 0;
  let octet = 0;
  for (let i = 0; i <= ip.length; i++) {
    if (i === ip.length || ip.charCodeAt(i) === 46 /* '.' */) {
      result = result * 256 + octet; // * 256 is equivalent to << 8
      octet = 0;
    } else {
      octet = octet * 10 + ip.charCodeAt(i) - 48; // 48 is '0'.charCodeAt(0)
    }
  }
  return result >>> 0;
}

function expandIPv6(address) {
  // Expands a potentially shortened IPv6 address into a 32-char lowercase
  // hex string (8 groups x 4 hex digits) for prefix matching via startsWith.
  let parts;
  const dcIndex = address.indexOf('::');
  if (dcIndex !== -1) {
    const left = address.substring(0, dcIndex);
    const right = address.substring(dcIndex + 2);
    const leftParts = left ? left.split(':') : [];
    const rightParts = right ? right.split(':') : [];
    const missing = 8 - leftParts.length - rightParts.length;
    parts = leftParts;
    for (let i = 0; i < missing; i++) parts.push('0000');
    for (let i = 0; i < rightParts.length; i++) parts.push(rightParts[i]);
  } else {
    parts = address.split(':');
  }
  let result = '';
  for (let i = 0; i < 8; i++) result += parts[i].padStart(4, '0');
  return result;
}

// Group CIDR entries by first octet for fast rejection.
// For each of the 256 possible first-octet values, only the entries whose
// range can include that octet are stored, so non-special IPs skip most checks.
const V4_OCTET_BUCKETS = new Array(256);
for (let i = 0; i < 256; i++) V4_OCTET_BUCKETS[i] = [];
for (const entry of SPECIAL_USE_IPV4) {
  const entryStart = (entry.prefix >>> 24) & 0xff;
  const hostBits = (~entry.mask >>> 24) & 0xff;
  for (let o = entryStart; o <= entryStart + hostBits && o < 256; o++) {
    V4_OCTET_BUCKETS[o].push(entry);
  }
}

function isSpecialUseIPv4(address) {
  const addr = ipv4ToInt(address);
  const bucket = V4_OCTET_BUCKETS[(addr >>> 24) & 0xff];
  for (let i = 0; i < bucket.length; i++) {
    if (((addr & bucket[i].mask) >>> 0) === bucket[i].prefix) return true;
  }
  return false;
}

// IANA IPv6 Special-Purpose Address Space
// https://www.iana.org/assignments/iana-ipv6-special-registry/
// Entries are expanded hex string prefixes matched via startsWith.
// Non-nibble-aligned CIDR ranges are split into nibble-aligned entries.
const SPECIAL_USE_IPV6 = [
  '0064ff9b0000000000000000', // 64:ff9b::/96 IPv4-IPv6 Translat. [RFC6052]
  '0064ff9b0001', // 64:ff9b:1::/48 IPv4-IPv6 Translat. [RFC8215]
  '0100000000000000', // 100::/64 Discard-Only [RFC6666]
  '0100000000000001', // 100:0:0:1::/64 Dummy IPv6 Prefix [RFC9780]
  '200100', // 2001::/23 IETF Protocol Assignments [RFC2928] (1/2)
  '200101', // 2001::/23 IETF Protocol Assignments [RFC2928] (2/2)
  '20010db8', // 2001:db8::/32 Documentation [RFC3849]
  '2002', // 2002::/16 6to4 [RFC3056]
  '2620004f8000', // 2620:4f:8000::/48 Direct Delegation AS112 Service [RFC7534]
  '3fff0', // 3fff::/20 Documentation [RFC9637]
  '5f00', // 5f00::/16 Segment Routing (SRv6) SIDs [RFC9602]
  'fc', // fc00::/7 Unique-Local [RFC4193] (1/2)
  'fd', // fc00::/7 Unique-Local [RFC4193] (2/2)
  'fe8', // fe80::/10 Link-Local Unicast [RFC4291] (1/4)
  'fe9', // fe80::/10 Link-Local Unicast [RFC4291] (2/4)
  'fea', // fe80::/10 Link-Local Unicast [RFC4291] (3/4)
  'feb', // fe80::/10 Link-Local Unicast [RFC4291] (4/4)

  // TCP cannot connect to multicast, also not in the IANA special-use registry
  // 'ff', // ff00::/8 Multicast [RFC4291]

  // Handled explicitly in isSpecialUseIPv6 — cannot use startsWith matching
  // ::1/128 Loopback [RFC4291]
  // ::/128 Unspecified [RFC4291]
  // ::ffff:0:0/96 IPv4-mapped [RFC4291] — delegates to isSpecialUseIPv4
];

// Character-level trie built from prefix strings. Walking the trie is
// 2-3x faster than Map-bucketed startsWith checks because it exits as
// soon as a terminal (matching) or dead-end (non-matching) node is reached.
function hexCharToTrieIndex(code) {
  // '0'-'9' => 0-9, 'a'-'f' => 10-15
  return code <= 57 /* '9' */ ? code - 48 /* '0' */ : code - 87;
}

const TRIE_CHILDREN = [];
const TRIE_TERMINAL = [];
function allocTrieNode() {
  const id = TRIE_CHILDREN.length;
  TRIE_CHILDREN.push(new Int8Array(16).fill(-1));
  TRIE_TERMINAL.push(0);
  return id;
}

const IPV6_TRIE_ROOT = allocTrieNode();
for (const prefix of SPECIAL_USE_IPV6) {
  let node = IPV6_TRIE_ROOT;
  for (let i = 0; i < prefix.length; i++) {
    const ci = hexCharToTrieIndex(prefix.charCodeAt(i));
    if (TRIE_CHILDREN[node][ci] === -1) {
      TRIE_CHILDREN[node][ci] = allocTrieNode();
    }
    node = TRIE_CHILDREN[node][ci];
  }
  TRIE_TERMINAL[node] = 1;
}

function isSpecialUseIPv6(address) {
  const lower = address.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  if (lower.startsWith('::ffff:')) {
    const v4part = lower.substring(7);
    if (v4part.includes('.')) return isSpecialUseIPv4(v4part);
  }
  const full = expandIPv6(lower);
  let node = IPV6_TRIE_ROOT;
  for (let i = 0; i < full.length; i++) {
    if (TRIE_TERMINAL[node]) return true;
    const next = TRIE_CHILDREN[node][hexCharToTrieIndex(full.charCodeAt(i))];
    if (next === -1) return false;
    node = next;
  }
  return !!TRIE_TERMINAL[node];
}

function isSpecialUseIP(address) {
  // socket.remoteAddress is always a valid IP; colons only appear in IPv6
  if (!address.includes(':')) return isSpecialUseIPv4(address);
  return isSpecialUseIPv6(address);
}

let dispatcher;

export default async function fetchRequest(provider, url, options) {
  /* eslint-disable no-param-reassign */
  options.signal = AbortSignal.timeout(2500);
  options.headers = new Headers(options.headers);
  options.headers.set('user-agent', ''); // removes the default user-agent header

  // SSRF protection: validate the connected socket's remote address rather than
  // resolving DNS upfront via dns/promises. An upfront lookup is vulnerable to
  // TOCTOU — the HTTP client resolves the hostname again independently, and the
  // result can differ (DNS rebinding, round-robin, short TTL). Checking
  // socket.remoteAddress in the connector inspects the actual IP the socket is
  // bound to, which is the only reliable enforcement point.
  dispatcher ??= new undici.Agent({
    connect(opts, cb) {
      undici.buildConnector({})(opts, (err, socket) => {
        if (err) {
          cb(err);
        } else if (isSpecialUseIP(socket.remoteAddress)) {
          socket.destroy();
          cb(new Error('hostname resolves to a special-use IP address'));
        } else {
          cb(null, socket);
        }
      });
    },
  });
  options.dispatcher = dispatcher;
  /* eslint-enable no-param-reassign */

  return instance(provider).configuration.fetch(url, options);
}

export {
  ipv4ToInt,
  expandIPv6,
  isSpecialUseIPv4,
  isSpecialUseIPv6,
  isSpecialUseIP,
};
