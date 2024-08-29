import { Buffer } from 'node:buffer';
import os from 'node:os';
import net from 'node:net';

/**
 * Returns true if the string looks like a number in octal format.
 * @param byte The byte to test.
 */
const isOctal = (byte: unknown) => {
  const str = String(byte);
  return str.startsWith('0') && /^[0-7]+$/.test(str);
};

/**
 * Parse an IPv4 address into an array of bytes.
 * @param addr The IPv4 address to parse.
 */
const parseOctets = (addr: string) => {
  return addr
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

/**
 * Parse an IPv6 address into a byte array
 * @param addr The IPv6 address to parse.
 */
const parseWords = (addr: string) => {
  return addr.split(':').flatMap((word) => {
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

/**
 * Compress an IPv6 address by removing the longest sequence of zero words.
 * @param words The words of the IPv6 address in hex notation
 */
const compressv6 = (words: string[]) => {
  // Find the longest sequence of zero words
  type ZeroSequence = { start: number | null; length: number };
  const currentZeroSequence: ZeroSequence = { start: null, length: 0 };
  const longestZeroSequence: ZeroSequence = { start: null, length: 0 };

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

  // If the longest sequence is more than one zero, then replace it with ''
  // Once joined with ':', the longest sequence will be '::'
  if (longestZeroSequence.length > 1 && longestZeroSequence.start !== null) {
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

/**
 * Convert an IPv4 address into a Uint8Array
 * @param addr The IPv4 address to convert
 * @throws {Error} If the address is invalid
 */
const v4toUInt8Array = (addr: string | number) => {
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
    const int32 = isOctal(addr) ? parseInt(String(addr), 8) : Number(addr);
    return new Uint8Array([
      (int32 >> 24) & 0xff,
      (int32 >> 16) & 0xff,
      (int32 >> 8) & 0xff,
      int32 & 0xff,
    ]);
  }

  const FOUR_BYTES = 4 as const;
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
  if (parts.some((part) => part !== (part | 0))) {
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

/**
 * Convert an IPv6 address into a Uint8Array.
 * @param addr The IPv6 address to convert.
 * @throws {Error} If the address is invalid
 */
const v6toUInt8Array = (addr: string) => {
  // Empty string is invalid
  if (addr === '') {
    throw new Error('invalid ip address');
  }

  // Anything not a string is invalid
  if (typeof addr !== 'string') {
    throw new Error('invalid ip address');
  }

  // Anything not in a valid v6 format is invalid
  if (net.isIPv6(addr) === false) {
    throw new Error('invalid ip address');
  }

  const SIXTEEN_BYTES = 16 as const;

  let words;

  // If there is no double colon, handle the parts directly
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
      throw new Error('invalid ip address');
    }

    const padding = Array(SIXTEEN_BYTES).fill(0);
    words = leftWords.concat(
      padding.slice(leftWords.length + rightWords.length),
      rightWords,
    );
  }

  if (words.some(Number.isNaN)) {
    throw new Error('invalid ip address');
  }

  return Uint8Array.from(words);
};

/**
 * Gets a 16-bit word from a Uint8Array at a given index. Indicies are specified in words, not bytes.
 * ```js
 * getWordAtIndex(new Uint8Array([0x12, 0x34, 0x56, 0x78]), 1) // 0x5678
 * ```
 * @param bytes The byte array to extract the word from.
 * @param index The index of the word to extract.
 */
const getWordAtIndex = (bytes: Uint8Array, index: number) => {
  return (bytes[index * 2] << 8) + bytes[index * 2 + 1];
};

/**
 * Detect if an IPv6 address has an IPv4 address embedded in it.
 * @param bytes The byte array to check.
 */
const isV4MappedV6 = (bytes: Uint8Array) => {
  if (bytes.length !== 16) {
    return false;
  }

  // Sixth word should be 0xffff and everything before should be 0
  const sixthWord = getWordAtIndex(bytes, 5);
  return sixthWord === 0xffff && bytes.slice(0, 10).every((byte) => byte === 0);
};

type Family =
  | 4
  | 6
  | '4'
  | '6'
  | 'ipv4'
  | 'ipv6'
  | 'IPv4'
  | 'IPv6'
  | 'IPV4'
  | 'IPV6';

/**
 * Normalize the ip family to either ipv4 or ipv6
 * @param family A representation of the IP family
 */
const normalizeFamily = (family?: Family) => {
  if (String(family) === '6' || String(family).toLowerCase() === 'ipv6') {
    return 'ipv6';
  }
  return 'ipv4';
};

/**
 * Test if a string is in IPv4 format.
 * ```js
 * isV4Format('127.0.0.1') // true
 * isV4Format('::1') // false
 * isV4Format('foo') // false
 * isV4Format(0) // false
 * ```
 * @param addr The address to test.
 */
export const isV4Format = (addr: string) => net.isIPv4(addr);

/**
 * Test if a string is in IPv6 format.
 * ```js
 * isV6Format('::1') // true
 * isV6Format('127.0.0.1') // false
 * isV6Format('foo') // false
 * ```
 * @param addr The address to test.
 */
export const isV6Format = (addr: string) => net.isIPv6(addr);

/**
 * Convert an IP address into a Uint8Array.
 * ```js
 * toUInt8Array('127.0.0.1') // [ 127, 0, 0, 1 ]
 * toUInt8Array('::1') // [ 0, 0, 0, 0, 0, 0, 0, 1 ]
 * toUInt8Array('foo') // throws
 * ```
 * @throws {Error} If the address is invalid
 */
export const toUInt8Array = (addr: string | number) => {
  if (typeof addr === 'string' && addr.includes(':')) {
    return v6toUInt8Array(addr);
  }
  return v4toUInt8Array(addr);
};

/**
 * Convert an IP address to a node Buffer.
 * ```js
 * toBuffer('127.0.0.1') // <Buffer 7f 00 00 01>
 * toBuffer('::1') // <Buffer 00 00 00 00 00 00 00 01>
 * toBuffer('foo') // throws
 * toBuffer('127.0.0.1', Buffer.alloc(6), 1) // <Buffer 00 7f 00 00 01 00>
 * ```
 * @param addr The address to convert
 * @param buf An optional buffer to write the address to
 * @param offset The offset within the buffer to write to
 * @throws {Error} If the address is invalid
 */
export const toBuffer = (
  addr: string | number,
  buf?: Buffer,
  offset?: number,
) => {
  offset = ~~Number(offset);

  const bytes = toUInt8Array(addr);
  const result = buf || Buffer.alloc(offset + bytes.length);
  bytes.forEach((byte, index) => (result[offset + index] = byte));

  return result;
};

/**
 * Convert a Buffer into an IP string representation
 * ```js
 * bufferToString(Buffer.from([127, 0, 0, 1])) // 127.0.0.1
 * bufferToString(Buffer.from([0, 0, 0, 0, 0, 0, 0, 1])) // ::1
 * ```
 * @param buf The buffer to convert
 * @param offset The offset within the buffer to start reading
 * @param length The number of bytes to read
 * @throws {Error} If the buffer is not a valid IP byte array
 */
const bufferToString = (buf: Buffer, offset?: number, length?: number) => {
  offset = ~~Number(offset);
  length = length || buf.length - offset;

  if (length === 4) {
    return buf.subarray(offset, offset + length).join('.');
  }

  if (length === 16) {
    const words: string[] = [];
    for (let i = 0; i < length; i += 2) {
      const int16 = buf.readUInt16BE(offset + i);
      words.push(int16.toString(16));
    }

    return compressv6(words);
  }

  throw new Error('invalid ip address');
};

/**
 * Converts a byte array into an IP string representation
 * ```js
 * toString(new Uint8Array([127, 0, 0, 1])) // 127.0.0.1
 * toString(new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1])) // ::1
 * ```
 * @param bytes The byte array to convert
 * @param offset The offset within the buffer to start reading (buffer only)
 * @param length The number of bytes to read (buffer only)
 */
export const toString = (
  bytes: Uint8Array | Buffer,
  offset?: number,
  length?: number,
) => {
  if (Buffer.isBuffer(bytes)) {
    return bufferToString(bytes, offset, length);
  }

  if (bytes instanceof Uint8Array === false) {
    throw new Error('argument must be Buffer or a Uint8Array');
  }

  if (bytes.length === 4) {
    return bytes.join('.');
  }

  if (bytes.length === 16) {
    const words: string[] = [];
    for (let i = 0; i < bytes.length; i += 2) {
      const int16 = (bytes[i] << 8) + bytes[i + 1];
      words.push(int16.toString(16));
    }

    return compressv6(words);
  }

  throw new Error('invalid ip address');
};

/**
 * Create a subnet mask from a prefix length.
 * ```js
 * fromPrefixLen(24) // 255.255.255.0
 * fromPrefixLen(64) // ffff:ffff:ffff:ffff::
 * ```
 * @param prefixLength The length of the prefix in bits
 * @param family The IP family to use. Infers v6 if the prefix length is greater than 32 bits
 */
export const fromPrefixLen = (prefixLength: number, family?: Family) => {
  if (prefixLength > 32) {
    family = 'ipv6';
  } else {
    family = normalizeFamily(family);
  }

  const len = family === 'ipv6' ? 16 : 4;
  const bytes = new Uint8Array(len);

  for (let i = 0; i < len; i += 1) {
    let bits = 8;
    if (prefixLength < 8) {
      bits = prefixLength;
    }

    prefixLength -= bits;
    bytes[i] = ~(0xff >> bits) & 0xff;
  }

  return toString(bytes);
};

/**
 * Apply a subnet mask to an IP address.
 * ```js
 * mask('192.168.1.134', '255.255.255.0'); // 192.168.1.0
 * mask('192.168.1.134', '255.0.0.0'); // 192.0.0.0
 * ```
 * @param addr The IP address to mask
 * @param subnetMask The subnet mask to apply
 * @throws {Error} If the address or mask is invalid
 */
export const mask = (addr: string, subnetMask: string) => {
  const addrBytes = toUInt8Array(addr);
  const maskBytes = toUInt8Array(subnetMask);

  const result = new Uint8Array(Math.max(addrBytes.length, maskBytes.length));

  // Same protocol, simple mask
  if (addrBytes.length === maskBytes.length) {
    for (let i = 0; i < addrBytes.length; i += 1) {
      result[i] = addrBytes[i] & maskBytes[i];
    }
    return toString(result);
  }

  // IPv6 address and IPv4 mask (mask low bits)
  if (maskBytes.length === 4) {
    for (let i = 0; i < maskBytes.length; i += 1) {
      result[12 + i] = addrBytes[12 + i] & maskBytes[i];
    }
    return toString(result);
  }

  // IPv4 address and IPv6 mask (v4 embedded in v6)
  if (addrBytes.length === 4) {
    // ::ffff:ipv4
    result[10] = 0xff;
    result[11] = 0xff;

    for (let i = 0; i < addrBytes.length; i += 1) {
      result[12 + i] = addrBytes[i] & maskBytes[12 + i];
    }
    return toString(result);
  }

  throw new Error('invalid ip address');
};

/**
 * Apply a CIDR mask to an IP address.
 * ```js
 * cidr('192.168.1.134/26'); // 192.168.1.128
 * ```
 * @param cidrString An IP address with a CIDR mask
 */
export const cidr = (cidrString: string) => {
  const [addr, prefixLength, ...rest] = cidrString.split('/');

  if (rest.length !== 0) {
    throw new Error(`invalid CIDR subnet: ${addr}`);
  }

  const maskLength = fromPrefixLen(parseInt(prefixLength, 10));
  return mask(addr, maskLength);
};

type SubnetData = {
  networkAddress: string;
  firstAddress: string;
  lastAddress: string;
  broadcastAddress: string;
  subnetMask: string;
  subnetMaskLength: number;
  numHosts: number;
  length: number;
  contains: (addr: string) => boolean;
};

/**
 * Compute the subnet details for an IP address and subnet mask.
 * ```js
 * subnet('192.168.1.134', '255.255.255.192');
 * // {
 * //   networkAddress: '192.168.1.128',
 * //   firstAddress: '192.168.1.129',
 * //   lastAddress: '192.168.1.190',
 * //   broadcastAddress: '192.168.1.191',
 * //   subnetMask: '255.255.255.192',
 * //   subnetMaskLength: 26,
 * //   numHosts: 62,
 * //   length: 64,
 * //   contains: (addr: string) => boolean;
 * // }
 * ```
 * @param addr The IP address
 * @param subnetMask The subnet mask
 */
export const subnet = (addr: string, subnetMask: string): SubnetData => {
  const maskLong = toLong(subnetMask);

  let maskLength = 0;
  for (let i = 0; i < 32; i += 1) {
    maskLength += (maskLong >> i) & 1;
  }

  const addressLong = toLong(mask(addr, subnetMask));
  const numberOfAddresses = Math.pow(2, 32 - maskLength);

  return {
    networkAddress: fromLong(addressLong),
    firstAddress:
      numberOfAddresses > 2 ? fromLong(addressLong + 1) : fromLong(addressLong),
    lastAddress:
      numberOfAddresses > 2
        ? fromLong(addressLong + numberOfAddresses - 2)
        : fromLong(addressLong + numberOfAddresses - 1),
    broadcastAddress: fromLong(addressLong + numberOfAddresses - 1),
    subnetMask: fromLong(maskLong),
    subnetMaskLength: maskLength,
    numHosts: numberOfAddresses > 2 ? numberOfAddresses - 2 : numberOfAddresses,
    length: numberOfAddresses,
    contains: (other) => addressLong === toLong(mask(other, subnetMask)),
  };
};

/**
 * Compute the subnet detailsfrom CIDR notation.
 * ```js
 * cidrSubnet('192.168.1.134/26');
 * // {
 * //   networkAddress: '192.168.1.128',
 * //   firstAddress: '192.168.1.129',
 * //   lastAddress: '192.168.1.190',
 * //   broadcastAddress: '192.168.1.191',
 * //   subnetMask: '255.255.255.192',
 * //   subnetMaskLength: 26,
 * //   numHosts: 62,
 * //   length: 64,
 * //   contains: (addr: string) => boolean;
 * // }
 * ```
 * @param cidrString An IP address with a CIDR mask
 */
export const cidrSubnet = (cidrString: string) => {
  const [addr, prefixLength, ...rest] = cidrString.split('/');

  if (rest.length !== 0) {
    throw new Error(`invalid CIDR subnet: ${addr}`);
  }

  const maskBytes = fromPrefixLen(parseInt(prefixLength, 10));
  return subnet(addr, maskBytes);
};

/**
 * Invert the bits of an IP address.
 * ```js
 * not('255.255.255.0'); // 0.0.0.255
 * ```
 * @param addr The IP address to invert
 * @throws {Error} If the address is invalid
 */
export const not = (addr: string | number) => {
  const bytes = toUInt8Array(addr);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = 0xff ^ bytes[i];
  }
  return toString(bytes);
};

/**
 * Perform a logical OR operation on two IP addresses
 * ```js
 * or('192.168.1.134', '0.0.0.255'); // 192.168.1.255
 * ```
 * @param a The first IP address
 * @param b The second IP address
 * @throws {Error} If the addresses are invalid
 */
export const or = (addr1: string | number, addr2: string | number) => {
  const a = toUInt8Array(addr1);
  const b = toUInt8Array(addr2);

  // same protocol
  if (a.length === b.length) {
    for (let i = 0; i < a.length; i += 1) {
      a[i] |= b[i];
    }
    return toString(a);
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

  return toString(buff);
};

/**
 * Test if two IP addresses are equal.
 * ```js
 * isEqual('::1', '::0:1'); // true
 * isEqual('127.0.0.1', 2130706433); // true
 * ```
 * @param addr1 The first IP address
 * @param addr2 The second IP address
 * @throws {Error} If the addresses are invalid
 */
export const isEqual = (addr1: string | number, addr2: string | number) => {
  let a = toUInt8Array(addr1);
  let b = toUInt8Array(addr2);

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

/**
 * Test if an IP address is a loopback address
 * ```js
 * isLoopback('127.0.0.1'); // true
 * isLoopback('::1'); // true
 * isLoopback('192.168.0.1'); // false
 * isLoopback('foo'); // false
 * ```
 * @param addr The IP address to test
 */
export const isLoopback = (addr: string | number) => {
  let bytes;

  try {
    bytes = toUInt8Array(addr);
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

/**
 * Test if an IP address is a link-local address
 * ```js
 * isLinkLocal('169.254.0.0'); // true
 * isLinkLocal('fe80::'); // true
 * isLinkLocal('127.0.0.1'); // false
 * ```
 * @param addr The IP address to test
 */
export const isLinkLocal = (addr: string | number) => {
  let bytes;

  try {
    bytes = toUInt8Array(addr);
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

/**
 * Test if an IP address is marked as reserved
 * ```js
 * isReserved('255.255.255.255'); // true
 * isReserved('224.0.0.0'); // true
 * isReserved('ff00::'); // true
 * isReserved('127.0.0.1'); // false
 * isReserved('::1'); // false
 * ```
 * @param addr The IP address to test
 */
export const isReserved = (addr: string | number) => {
  let bytes;

  try {
    bytes = toUInt8Array(addr);
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

/**
 * Test if an IP address is a private address
 * ```js
 * isPrivate('127.0.0.1'); // true, loopback is private
 * isPrivate('192.168.0.1'); // true, private network
 * isPrivate('169.254.2.3'); // true, link-local is private
 * isPrivate('8.8.8.8'); // false, google is public
 * isPrivate('foo'); // false, invalid address
 * ```
 * @param addr The IP address to test
 */
export const isPrivate = (addr: string | number) => {
  if (isLoopback(addr)) {
    return true;
  }

  if (isLinkLocal(addr)) {
    return true;
  }

  if (isReserved(addr)) {
    return true;
  }

  let bytes;

  try {
    bytes = toUInt8Array(addr);
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

/**
 * Test if an IP address is a public address
 * ```js
 * isPrivate('127.0.0.1'); // false, loopback is private
 * isPrivate('192.168.0.1'); // false, private network
 * isPrivate('169.254.2.3'); // false, link-local is private
 * isPrivate('8.8.8.8'); // true, google is public
 * isPrivate('foo'); // false, invalid address
 * ```
 * @param addr The IP address to test
 */
export const isPublic = (addr: string | number) => {
  if (typeof addr === 'string' && net.isIP(addr) === 0) {
    return false;
  }

  try {
    return isPrivate(addr) === false;
  } catch (ignore) {
    return false;
  }
};

/**
 * Get the loopback address for the current IP family
 * ```js
 * loopback('ipv4'); // 127.0.0.1
 * loopback('ipv6'); // fe80::1
 * ```
 * @param family The IP family to use, defaults to ipv4
 */
export const loopback = (family?: Family) => {
  family = normalizeFamily(family);
  if (family !== 'ipv4' && family !== 'ipv6') {
    throw new Error('family must be ipv4 or ipv6');
  }

  return family === 'ipv4' ? '127.0.0.1' : 'fe80::1';
};

/**
 * Get the IP address of a specifiec network interface and family
 * Returns loopback address if no address is found.
 * ```js
 * address('public'); // Some public address
 * address('private'); // Some private address
 * address('eth0'); // Some address on eth0
 * address('eth0', 'ipv6'); // Some ipv6 address on eth0
 * address(); // Some address from the first NIC
 * ```
 */
export const address = (
  name?: string | 'public' | 'private',
  family?: Family,
) => {
  const interfaces = os.networkInterfaces();

  // Defaults to ipv4
  family = normalizeFamily(family);

  // If a specific interface has been named, return an address from there
  if (name && name !== 'public' && name !== 'private') {
    const res = interfaces[name]?.filter((details) => {
      const itemFamily = normalizeFamily(details.family);
      return itemFamily === family;
    });

    if (!res || res.length === 0) {
      return undefined;
    }

    return res[0].address;
  }

  const inter = Object.values(interfaces).flatMap((nic) => {
    if (!nic) {
      return [];
    }

    return nic.filter((details) => {
      // If this is the loopback or local link, discard it
      if (isLoopback(details.address) || isLinkLocal(details.address)) {
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
      if (name === 'public' && isPublic(details.address)) {
        return true;
      }

      if (name === 'private' && isPrivate(details.address)) {
        return true;
      }

      return false;
    });
  });

  if (inter.length === 0) {
    return loopback(family);
  }

  return inter[0].address;
};

/**
 * Convert an IPv4 address to a 32-bit integer
 * ```js
 * toLong('127.0.0.1'); // 2130706433
 * ```
 * @param addr The IPv4 address to convert
 * @throws {Error} If the address is invalid
 */
export const toLong = (addr: string) => {
  const bytes = toUInt8Array(addr);
  if (bytes.length !== 4) {
    throw new Error('invalid ip address');
  }
  return bytes.reduce((acc, byte) => acc * 256 + byte, 0);
};

/**
 * Convert a 32-bit integer to an IPv4 address
 * ```js
 * fromLong(2130706433); // 127.0.0.1
 * ```
 * @param int32 The 32-bit integer to convert
 * @throws {Error} If the value is invalid
 */
export const fromLong = (int32: number) => {
  if (int32 >>> 0 !== int32) {
    throw new Error('invalid long value');
  }
  return `${int32 >>> 24}.${(int32 >> 16) & 255}.${(int32 >> 8) & 255}.${int32 & 255}`;
};

/**
 * Convert an IP address to a 32-bit integer, returning -1 for invalid addresses
 * ```js
 * normalizeToLong('127.0.0.1'); // 2130706433
 * normalizeToLong('foo'); // -1
 * ```
 * @param addr The IP address to convert
 */
export const normalizeToLong = (addr: string) => {
  try {
    return toLong(addr);
  } catch (ignore) {
    return -1;
  }
};

/**
 * Normalize an IP address
 * ```js
 * normalize('127.1'); // 127.0.0.1
 * normalize('0x7f.0.1'); // 127.0.0.1
 * normalize('::0:1'); // ::1
 * normalize('foo'); // throws
 * ```
 * @param addr The IP address to normalize
 * @throws {Error} If the address is invalid
 */
export const normalize = (addr: string | number) => {
  return toString(toUInt8Array(addr));
};
