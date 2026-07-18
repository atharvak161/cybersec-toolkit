/**
 * CIDR / subnet calculator. Pure logic, IPv4-focused with basic IPv6
 * range support.
 */

export function ipv4ToInt(ip) {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) throw new Error('Invalid IPv4 address: ' + ip);
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) throw new Error('Invalid IPv4 octet: ' + p);
    n = (n << 8) | v;
  }
  return n >>> 0;
}

export function intToIpv4(n) {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

/**
 * Calculate subnet details for an IPv4 CIDR string, e.g. "192.168.1.10/24".
 */
export function calculateIpv4Subnet(cidr) {
  const [ipStr, prefixStr] = cidr.trim().split('/');
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error('Invalid IPv4 prefix length: ' + prefixStr);
  }
  const ipInt = ipv4ToInt(ipStr);
  const maskInt = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const networkInt = (ipInt & maskInt) >>> 0;
  const broadcastInt = (networkInt | (~maskInt >>> 0)) >>> 0;
  const wildcardInt = (~maskInt) >>> 0;

  const totalAddresses = Math.pow(2, 32 - prefix);
  const usableHosts = prefix >= 31 ? 0 : totalAddresses - 2;

  let firstUsable, lastUsable;
  if (prefix >= 31) {
    firstUsable = intToIpv4(networkInt);
    lastUsable = intToIpv4(broadcastInt);
  } else {
    firstUsable = intToIpv4(networkInt + 1);
    lastUsable = intToIpv4(broadcastInt - 1);
  }

  return {
    input: cidr,
    ipAddress: intToIpv4(ipInt),
    prefix,
    netmask: intToIpv4(maskInt),
    wildcardMask: intToIpv4(wildcardInt),
    networkAddress: intToIpv4(networkInt),
    broadcastAddress: intToIpv4(broadcastInt),
    firstUsable,
    lastUsable,
    totalAddresses,
    usableHosts
  };
}

/** Basic IPv6 CIDR range info (network/broadcast-equivalent boundaries via BigInt). */
export function calculateIpv6Subnet(cidr) {
  const [ipStr, prefixStr] = cidr.trim().split('/');
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
    throw new Error('Invalid IPv6 prefix length: ' + prefixStr);
  }
  const full = expandIpv6(ipStr);
  const ipBig = ipv6ToBigInt(full);
  const maskBig = prefix === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - prefix)) - 1n);
  const networkBig = ipBig & maskBig;
  const lastBig = networkBig | (~maskBig & ((1n << 128n) - 1n));

  return {
    input: cidr,
    ipAddress: full,
    prefix,
    networkAddress: bigIntToIpv6(networkBig),
    lastAddress: bigIntToIpv6(lastBig),
    totalAddresses: (2n ** BigInt(128 - prefix)).toString()
  };
}

export function expandIpv6(ip) {
  let [head, tail] = ip.split('::');
  const headParts = head ? head.split(':').filter(Boolean) : [];
  const tailParts = tail ? tail.split(':').filter(Boolean) : [];
  if (ip.includes('::')) {
    const missing = 8 - headParts.length - tailParts.length;
    const middle = new Array(missing).fill('0');
    return [...headParts, ...middle, ...tailParts].map((p) => p.padStart(4, '0')).join(':');
  }
  return headParts.map((p) => p.padStart(4, '0')).join(':');
}

function ipv6ToBigInt(fullIp) {
  return fullIp.split(':').reduce((acc, group) => (acc << 16n) | BigInt(parseInt(group, 16)), 0n);
}

function bigIntToIpv6(big) {
  const groups = [];
  let n = big;
  for (let i = 0; i < 8; i++) {
    groups.unshift((n & 0xffffn).toString(16).padStart(4, '0'));
    n >>= 16n;
  }
  return groups.join(':');
}
