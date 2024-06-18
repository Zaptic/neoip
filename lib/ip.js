const ip = exports;
const { Buffer } = require('buffer');
const os = require('os');
const net = require('net');

const isOctal = (unknown) => {
  const str = String(unknown);
  return str.startsWith('0') && /^[0-7]+$/.test(str);
};

const parseOctets = (addr) => {
  return String(addr)
    .toLowerCase()
    .split('.')
    .map((octet) => {
      // Handle hexadecimal format
      if (octet.startsWith('0x')) {
        return parseInt(octet, 16);
      }

      // Handle octal format
      if (isOctal(octet)) {
        return parseInt(octet, 8);
      }

      // Handle decimal format, reject invalid leading zeros
      if (/^[1-9]\d*$/.test(octet)) {
        return parseInt(octet, 10);
      }

      // Error case
      return NaN;
    });
};

const parseWords = (addr) => {
  return String(addr || '')
    .split(':')
    .flatMap((word) => {
      if (word === '') {
        return [];
      }

      if (word.includes('.')) {
        return parseOctets(word);
      }

      const int16 = parseInt(word, 16);
      return [(int16 >> 8) & 0xff, int16 & 0xff];
    });
};

const compressv6 = (words) => {
  // Find the longest sequence of zero words
  const currentZeroSequence = { start: null, length: 0 };
  const longestZeroSequence = { start: null, length: 0 };

  words.forEach((word, index) => {
    if (word === '0') {
      currentZeroSequence.start ??= index;
      currentZeroSequence.length += 1;
      return;
    }

    if (currentZeroSequence.length > longestZeroSequence.length) {
      Object.assign(longestZeroSequence, currentZeroSequence);
    }

    Object.assign(currentZeroSequence, { start: null, length: 0 });
  });

  if (currentZeroSequence.length > longestZeroSequence.length) {
    Object.assign(longestZeroSequence, currentZeroSequence);
  }

  // If the longest sequence is the full address, return '::'
  if (longestZeroSequence.length === 8) {
    return '::';
  }

  // If the longest sequence is more than one zeros, then replace it with ''
  // Once joined with ':', the longest sequence will be '::'
  if (longestZeroSequence.length > 1) {
    words.splice(longestZeroSequence.start, longestZeroSequence.length, '');
  }

  // If we start or end with a : then we need to add an extra :
  const compressed = words.join(':');
  if (compressed.startsWith(':')) {
    return ':' + compressed;
  }

  if (compressed.endsWith(':')) {
    return compressed + ':';
  }

  return compressed;
};

const v4toUInt8Array = (addr) => {
  // Empty string is invalid
  if (addr === '') {
    throw new Error('invalid ip address');
  }

  // Anything not a string or a number is invalid
  if (typeof addr !== 'string' && typeof addr !== 'number') {
    throw new Error('invalid ip address');
  }

  // If there are no dots, or the type is a number, then assume it's a long
  if (typeof addr === 'number' || String(addr).includes('.') === false) {
    const int32 = isOctal(addr) ? parseInt(addr, 8) : Number(addr) >>> 0;

    return new Uint8Array([
      (int32 >> 24) & 0xff,
      (int32 >> 16) & 0xff,
      (int32 >> 8) & 0xff,
      int32 & 0xff,
    ]);
  }

  const FOUR_BYTES = 4;
  let parts = parseOctets(addr);

  // If there are more than 4 parts, this is not valid
  if (parts.length > FOUR_BYTES) {
    throw new Error('invalid ip address');
  }

  // If any part has a NaN, this is not valid
  if (parts.some(Number.isNaN)) {
    throw new Error('invalid ip address');
  }

  // If any part is < 0 or > 255, this is not valid
  if (parts.some((part) => part < 0 || part > 255)) {
    throw new Error('invalid ip address');
  }

  // If any part is a float, this is not valid
  if (parts.some((part) => part !== parseInt(part, 10))) {
    throw new Error('invalid ip address');
  }

  // If there are fewer than 4 parts, fill in the missing parts with 0
  if (parts.length < FOUR_BYTES) {
    parts = parts
      .slice(0, -1)
      .concat(Array(4 - parts.length).fill(0), parts.slice(-1));
  }

  return Uint8Array.from(parts);
};

const v6toUInt8Array = (addr) => {
  // Empty string is invalid
  if (addr === '') {
    throw new Error('invalid ip address');
  }

  // Anything not a string  is invalid
  if (typeof addr !== 'string') {
    throw new Error('invalid ip address');
  }

  // Anything not in a valid v6 format is invalid
  if (net.isIPv6(addr) === false) {
    throw new Error('invalid ip address');
  }

  const SIXTEEN_BYTES = 16;

  // If there is no double colon, handle the parts directly
  let words;
  if (addr.includes('::') === false) {
    words = parseWords(addr);
    if (words.length > SIXTEEN_BYTES) {
      throw new Error('invalid ip address');
    }
  } else {
    const [left, right] = addr.toLowerCase().split('::');
    const leftWords = parseWords(left);
    const rightWords = parseWords(right);

    if (leftWords.length + rightWords.length > SIXTEEN_BYTES) {
      throw new Error('invalid ip address 3');
    }

    words = leftWords.concat(
      Array.from({
        length: SIXTEEN_BYTES - leftWords.length - rightWords.length,
      }).fill(0),
      rightWords,
    );
  }

  if (words.some(Number.isNaN)) {
    throw new Error('invalid ip address');
  }

  return Uint8Array.from(words);
};

const getWordAtIndex = (bytes, index) => {
  return (bytes[index * 2] << 8) + bytes[index * 2 + 1];
};

const isV4MappedV6 = (bytes) => {
  if (bytes.length !== 16) {
    return false;
  }

  const sixthWord = getWordAtIndex(bytes, 5);
  return sixthWord === 0xffff && bytes.slice(0, 10).every((byte) => byte === 0);
};

ip.isV4Format = (addr) => net.isIPv4(addr);

ip.isV6Format = (addr) => net.isIPv6(addr);

ip.toUInt8Array = (addr) => {
  if (String(addr).includes(':')) {
    return v6toUInt8Array(addr);
  }
  return v4toUInt8Array(addr);
};

ip.toBuffer = (addr, buff, offset) => {
  offset = ~~offset;

  const bytes = ip.toUInt8Array(addr);
  const result = buff || Buffer.alloc(offset + bytes.length);
  bytes.forEach((byte, index) => (result[offset + index] = byte));

  return result;
};

const bufferToString = (buff, offset, length) => {
  offset = ~~offset;
  length = length || buff.length - offset;

  if (length === 4) {
    return buff.slice(offset, offset + length).join('.');
  }

  if (length === 16) {
    const words = [];
    for (let i = 0; i < length; i += 2) {
      const int16 = buff.readUInt16BE(offset + i);
      words.push(int16.toString(16));
    }

    return compressv6(words);
  }

  throw new Error('invalid ip address');
};

ip.toString = (bytes, ...rest) => {
  if (Buffer.isBuffer(bytes)) {
    return bufferToString(bytes, ...rest);
  }

  if (bytes instanceof Uint8Array === false) {
    throw new Error('argument must be Buffer or a Uint8Array');
  }

  if (bytes.length === 4) {
    return bytes.join('.');
  }

  if (bytes.length === 16) {
    const words = [];
    for (let i = 0; i < bytes.length; i += 2) {
      const int16 = (bytes[i] << 8) + bytes[i + 1];
      words.push(int16.toString(16));
    }

    return compressv6(words);
  }

  throw new Error('invalid ip address');
};

const normalizeFamily = (family) => {
  if (String(family) === '6' || String(family).toLowerCase() === 'ipv6') {
    return 'ipv6';
  }
  return 'ipv4';
};

ip.fromPrefixLen = (prefixlen, family) => {
  if (prefixlen > 32) {
    family = 'ipv6';
  } else {
    family = normalizeFamily(family);
  }

  const len = family === 'ipv6' ? 16 : 4;
  const bytes = new Uint8Array(len);

  for (let i = 0; i < len; i += 1) {
    let bits = 8;
    if (prefixlen < 8) {
      bits = prefixlen;
    }

    prefixlen -= bits;
    bytes[i] = ~(0xff >> bits) & 0xff;
  }

  return ip.toString(bytes);
};

ip.mask = (addr, mask) => {
  addr = ip.toUInt8Array(addr);
  mask = ip.toUInt8Array(mask);

  const result = new Uint8Array(Math.max(addr.length, mask.length));

  // Same protocol, simple mask
  if (addr.length === mask.length) {
    for (let i = 0; i < addr.length; i += 1) {
      result[i] = addr[i] & mask[i];
    }
    return ip.toString(result);
  }

  // IPv6 address and IPv4 mask (mask low bits)
  if (mask.length === 4) {
    for (let i = 0; i < mask.length; i += 1) {
      result[12 + i] = addr[12 + i] & mask[i];
    }
    return ip.toString(result);
  }

  // IPv4 address and IPv6 mask (v4 embedded in v6)
  if (addr.length === 4) {
    // ::ffff:ipv4
    result[10] = 0xff;
    result[11] = 0xff;

    for (let i = 0; i < addr.length; i += 1) {
      result[12 + i] = addr[i] & mask[12 + i];
    }
    return ip.toString(result);
  }
};

ip.cidr = (cidrString) => {
  const [addr, mask, ...rest] = cidrString.split('/');

  if (rest.length !== 0) {
    throw new Error(`invalid CIDR subnet: ${addr}`);
  }

  const maskBytes = ip.fromPrefixLen(parseInt(mask, 10));
  return ip.mask(addr, maskBytes);
};

ip.subnet = (addr, mask) => {
  const maskLong = ip.toLong(mask);

  let maskLength = 0;
  for (let i = 0; i < 32; i += 1) {
    maskLength += (maskLong >> i) & 1;
  }

  const addressLong = ip.toLong(ip.mask(addr, mask));
  const numberOfAddresses = Math.pow(2, 32 - maskLength);

  return {
    networkAddress: ip.fromLong(addressLong),
    firstAddress:
      numberOfAddresses > 2
        ? ip.fromLong(addressLong + 1)
        : ip.fromLong(addressLong),
    lastAddress:
      numberOfAddresses > 2
        ? ip.fromLong(addressLong + numberOfAddresses - 2)
        : ip.fromLong(addressLong + numberOfAddresses - 1),
    broadcastAddress: ip.fromLong(addressLong + numberOfAddresses - 1),
    subnetMask: ip.fromLong(maskLong),
    subnetMaskLength: maskLength,
    numHosts: numberOfAddresses > 2 ? numberOfAddresses - 2 : numberOfAddresses,
    length: numberOfAddresses,
    contains: (other) => addressLong === ip.toLong(ip.mask(other, mask)),
  };
};

ip.cidrSubnet = (cidrString) => {
  const [addr, mask, ...rest] = cidrString.split('/');

  if (rest.length !== 0) {
    throw new Error(`invalid CIDR subnet: ${addr}`);
  }

  const maskBytes = ip.fromPrefixLen(parseInt(mask, 10));
  return ip.subnet(addr, maskBytes);
};

ip.not = (addr) => {
  const bytes = ip.toUInt8Array(addr);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = 0xff ^ bytes[i];
  }
  return ip.toString(bytes);
};

ip.or = (a, b) => {
  a = ip.toUInt8Array(a);
  b = ip.toUInt8Array(b);

  // same protocol
  if (a.length === b.length) {
    for (let i = 0; i < a.length; i += 1) {
      a[i] |= b[i];
    }
    return ip.toString(a);
  }

  // mixed protocols
  let buff = a;
  let other = b;
  if (b.length > a.length) {
    buff = b;
    other = a;
  }

  const offset = buff.length - other.length;
  for (let i = offset; i < buff.length; i += 1) {
    buff[i] |= other[i - offset];
  }

  return ip.toString(buff);
};

ip.isEqual = (a, b) => {
  a = ip.toUInt8Array(a);
  b = ip.toUInt8Array(b);

  // Same protocol
  if (a.length === b.length) {
    return a.every((byte, index) => byte === b[index]);
  }

  // Mixed protocols
  if (b.length === 4) {
    const t = b;
    b = a;
    a = t;
  }

  // a - IPv4, b - IPv6
  for (let i = 0; i < 10; i += 1) {
    if (b[i] !== 0) {
      return false;
    }
  }

  // The sixth word should be 0xffff or 0
  const sixthWord = getWordAtIndex(b, 5);
  if (sixthWord !== 0xffff && sixthWord !== 0) {
    return false;
  }

  // Ensure the final bytes match
  for (let i = 0; i < 4; i += 1) {
    if (a[i] !== b[i + 12]) {
      return false;
    }
  }

  return true;
};

ip.isLoopback = (addr) => {
  let bytes;

  try {
    bytes = ip.toUInt8Array(addr);
  } catch (ignore) {
    return false;
  }

  if (isV4MappedV6(bytes)) {
    bytes = bytes.slice(12);
  }

  if (bytes.length === 4) {
    return bytes[0] === 127;
  }

  return bytes[15] === 1 && bytes.slice(0, -1).every((byte) => byte === 0);
};

ip.isLinkLocal = (addr) => {
  let bytes;

  try {
    bytes = ip.toUInt8Array(addr);
  } catch (ignore) {
    return false;
  }

  if (isV4MappedV6(bytes)) {
    bytes = bytes.slice(12);
  }

  if (bytes.length === 4) {
    return bytes[0] === 169 && bytes[1] === 254;
  }

  const firstWord = getWordAtIndex(bytes, 0);
  return firstWord >= 0xfe80 && firstWord <= 0xfebf;
};

ip.isReserved = (addr) => {
  let bytes;

  try {
    bytes = ip.toUInt8Array(addr);
  } catch (ignore) {
    return false;
  }

  if (isV4MappedV6(bytes)) {
    bytes = bytes.slice(12);
  }

  // IPv4 reserved
  if (bytes.length === 4) {
    // 0.0.0.0/8
    if (bytes[0] === 0) {
      return true;
    }

    // 255.255.255.255
    if (bytes.every((byte) => byte === 255)) {
      return true;
    }

    // 192.0.2.0/24 - TEST-NET-1
    if (bytes[0] === 192 && bytes[1] === 0 && bytes[2] === 2) {
      return true;
    }

    // 198.51.100.0/24 - TEST-NET-2
    if (bytes[0] === 198 && bytes[1] === 51 && bytes[2] === 100) {
      return true;
    }

    // 203.0.113.0/24 - TEST-NET-3
    if (bytes[0] === 203 && bytes[1] === 0 && bytes[2] === 113) {
      return true;
    }

    // 224.0.0.0/4 - MULTICAST
    if (bytes[0] >= 224 && bytes[0] <= 239) {
      return true;
    }

    // 192.0.0.0/24 - IETF Protocol Assignments
    if (bytes[0] === 192 && bytes[1] === 0 && bytes[2] === 0) {
      return true;
    }

    // 192.88.99.0/24 - 6to4 Relay Anycast
    if (bytes[0] === 192 && bytes[1] === 88 && bytes[2] === 99) {
      return true;
    }

    // 198.18.0.0/15 - Network Interconnect Device Benchmark Testing
    if (bytes[0] === 198 && bytes[1] >= 18 && bytes[1] <= 19) {
      return true;
    }

    return false;
  }

  // IPv6 reserved
  const firstWord = getWordAtIndex(bytes, 0);

  // ff00::/8 - Multicast
  if (firstWord === 0xff00) {
    return true;
  }

  // 100::/64 - Discard-Only Address Block
  if (firstWord === 0x0100) {
    return true;
  }

  // 2001::/32 - TEREDO
  if (firstWord === 0x2001) {
    return true;
  }

  // 2002::/16 - 6to4
  if (firstWord === 0x2002) {
    return true;
  }

  // ::
  if (bytes.every((byte) => byte === 0)) {
    return true;
  }

  // ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
  return bytes.every((byte) => byte === 0xff);
};

ip.isPrivate = (addr) => {
  if (ip.isLoopback(addr)) {
    return true;
  }

  if (ip.isLinkLocal(addr)) {
    return true;
  }

  if (ip.isReserved(addr)) {
    return true;
  }

  let bytes;

  try {
    bytes = ip.toUInt8Array(addr);
  } catch (ignore) {
    return false;
  }

  if (isV4MappedV6(bytes)) {
    bytes = bytes.slice(12);
  }

  if (bytes.length === 4) {
    // 10.0.0.0/8 - Class A private network
    if (bytes[0] === 10) {
      return true;
    }

    // 172.16.0.0/12 - Class B private network
    if (bytes[0] === 172 && bytes[1] >= 16 && bytes[1] <= 31) {
      return true;
    }

    // 192.168.0.0/16 - Class C private network
    if (bytes[0] === 192 && bytes[1] === 168) {
      return true;
    }
  }

  // fc00::/7 - Unique local address
  const firstWord = getWordAtIndex(bytes, 0);
  if (firstWord >= 0xfc00 && firstWord <= 0xfdff) {
    return true;
  }

  // fe80::/10 - Link-local unicast
  if (firstWord >= 0xfe80 && firstWord <= 0xfebf) {
    return true;
  }

  return false;
};

ip.isPublic = (addr) => {
  if (net.isIP(addr) === 0) {
    return false;
  }

  try {
    return ip.isPrivate(addr) === false;
  } catch (ignore) {
    return false;
  }
};

ip.loopback = (family) => {
  family = normalizeFamily(family);
  if (family !== 'ipv4' && family !== 'ipv6') {
    throw new Error('family must be ipv4 or ipv6');
  }

  return family === 'ipv4' ? '127.0.0.1' : 'fe80::1';
};

/**
 * address()
 *
 * @param {string|'public'|'private'} name **Optional** Name or security of the network interface.
 * @param {'ipv4'|'ipv6'} family **Optional** IP family of the address (defaults to ipv4).
 * @returns {string} Address for the network interface on the current system with the specified `name`
 */
ip.address = (name, family) => {
  const interfaces = os.networkInterfaces();

  // Defaults to ipv4
  family = normalizeFamily(family);

  // If a specific interface has been named, return an address from there
  if (name && name !== 'public' && name !== 'private') {
    const res = interfaces[name].filter((details) => {
      const itemFamily = normalizeFamily(details.family);
      return itemFamily === family;
    });

    if (res.length === 0) {
      return undefined;
    }

    return res[0].address;
  }

  const inter = Object.values(interfaces).flatMap((nic) => {
    return nic.filter((details) => {
      // If this is the loopback or local link, discard it
      if (ip.isLoopback(details.address) || ip.isLinkLocal(details.address)) {
        return false;
      }

      // If this is the wrong family, discard it
      if (normalizeFamily(details.family) !== family) {
        return false;
      }

      // If no name is specified, return all addresses
      if (!name) {
        return true;
      }

      // If the name is `public`, return only public addresses
      if (name === 'public' && ip.isPublic(details.address)) {
        return true;
      }

      if (name === 'private' && ip.isPrivate(details.address)) {
        return true;
      }

      return false;
    });
  });

  if (inter.length === 0) {
    return ip.loopback(family);
  }

  return inter[0].address;
};

ip.toLong = (addr) => {
  if (ip.isV6Format(addr)) {
    throw new Error('invalid ipv4 address');
  }

  const bytes = ip.toUInt8Array(addr);
  return bytes.reduce((acc, byte) => acc * 256 + byte, 0);
};

ip.fromLong = (int32) => {
  if (int32 >>> 0 !== int32) {
    throw new Error('invalid long value');
  }

  return `${int32 >>> 24}.${(int32 >> 16) & 255}.${(int32 >> 8) & 255}.${int32 & 255}`;
};

ip.normalizeToLong = (addr) => {
  try {
    return ip.toLong(addr);
  } catch (ignore) {
    return -1;
  }
};

ip.normalize = (addr) => ip.toString(ip.toUInt8Array(addr));
