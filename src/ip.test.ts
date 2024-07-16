/* global describe, it */
import assert from 'node:assert';
import os from 'node:os';
import net from 'node:net';
import * as ip from './ip';

describe('toUIntArray() method', () => {
  describe('IPv4', () => {
    it('should convert from int32', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array(2130706433),
        Uint8Array.from([127, 0, 0, 1]),
      );
    });

    it('should convert "127.0.0.1"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('127.0.0.1'),
        Uint8Array.from([127, 0, 0, 1]),
      );
    });

    it('should convert "127.0.1"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('127.0.1'),
        Uint8Array.from([127, 0, 0, 1]),
      );
    });

    it('should convert "127.1"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('127.1'),
        Uint8Array.from([127, 0, 0, 1]),
      );
    });

    it('should convert "1" as int32', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('1'),
        Uint8Array.from([0, 0, 0, 1]),
      );
    });

    it('should handle hexadecimal notation "0x7f.0x0.0x0.0x1"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('0x7f.0x0.0x0.0x1'),
        Uint8Array.from([127, 0, 0, 1]),
      );
    });

    it('should handle octal notation "0177.0.0.01"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('0177.0.0.01'),
        Uint8Array.from([127, 0, 0, 1]),
      );
    });

    it('should handle hex long "0x7f000001"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('0x7f000001'),
        Uint8Array.from([127, 0, 0, 1]),
      );
    });

    it('should throw for octets out of range', () => {
      assert.throws(() => ip.toUInt8Array('256.100.50.25'));
    });

    it('should throw for invalid octal', () => {
      assert.throws(() => ip.toUInt8Array('019.0.0.1'));
    });

    it('should throw for invalid hex', () => {
      assert.throws(() => ip.toUInt8Array('0xgg.0.0.1'));
    });

    it('should throw for empty string', () => {
      assert.throws(() => ip.toUInt8Array(''));
    });

    it('should throw for too many octets', () => {
      assert.throws(() => ip.toUInt8Array('127.0.0.0.1'));
    });
  });

  describe('IPv4 mapped IPv6', () => {
    it('should convert "::fFFf:127.0.0.1"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('::fFFf:127.0.0.1'),
        Uint8Array.from([
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1,
        ]),
      );
    });

    it('should convert "::127.0.0.1"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('::127.0.0.1'),
        Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1]),
      );
    });
  });

  describe('IPv6', () => {
    it('should convert "fe80::1"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('fe80::1'),
        Uint8Array.from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
      );
    });

    it('should convert "fe80::0001"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('fe80::0001'),
        Uint8Array.from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
      );
    });

    it('should convert "::"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('::'),
        Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
      );
    });

    it('should convert "::0"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('::0'),
        Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
      );
    });

    it('should convert "::000"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('::000'),
        Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
      );
    });

    it('should convert "::1"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('::1'),
        Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
      );
    });

    it('should convert "::01"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('::01'),
        Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
      );
    });

    it('should convert "::001"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('::001'),
        Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
      );
    });

    it('should convert "0::1"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('0::1'),
        Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
      );
    });

    it('should convert "000:0:0000::01"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('000:0:0000::01'),
        Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
      );
    });

    it('should convert "000:0:0000:0:000:0:00:001"', () => {
      assert.deepStrictEqual(
        ip.toUInt8Array('000:0:0000:0:000:0:00:001'),
        Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
      );
    });

    it('should throw for words out of range', () => {
      assert.throws(() => ip.toUInt8Array('::FFFG'));
    });

    it('should throw for too many :: tokens', () => {
      assert.throws(() => ip.toUInt8Array('::FFFF::1'));
    });

    it('should throw for too many words', () => {
      assert.throws(() => ip.toUInt8Array('0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0'));
    });
  });
});

describe('toBuffer() method', () => {
  describe('IPv4', () => {
    it('should convert to buffer IPv4 address', () => {
      const buf = ip.toBuffer('127.0.0.1');
      assert.equal(buf.toString('hex'), '7f000001');
    });

    it('should convert to buffer IPv4 address in-place', () => {
      const buf = Buffer.alloc(16);
      const offset = 8;

      ip.toBuffer('127.0.0.1', buf, offset);

      assert.equal(buf.toString('hex'), '00000000000000007f00000100000000');
    });
  });

  describe('IPv4 mapped IPv6', () => {
    it('should convert "::ffff:192.0.2.128"', () => {
      const buf = ip.toBuffer('::ffff:192.0.2.128');
      assert.equal(buf.toString('hex'), '00000000000000000000ffffc0000280');
    });

    it('should convert "ffff::127.0.0.1"', () => {
      const buf = ip.toBuffer('ffff::127.0.0.1');
      assert.equal(buf.toString('hex'), 'ffff000000000000000000007f000001');
    });

    it('should convert "0:0:0:0:0:ffff:127.0.0.1"', () => {
      const buf = ip.toBuffer('0:0:0:0:0:ffff:127.0.0.1');
      assert.equal(buf.toString('hex'), '00000000000000000000ffff7f000001');
    });
  });

  describe('IPv6', () => {
    it('should convert to buffer IPv6 address', () => {
      const buf = ip.toBuffer('::1');
      assert.equal(buf.toString('hex'), '00000000000000000000000000000001');
    });

    it('should convert to buffer IPv6 address in-place', () => {
      const buf = Buffer.alloc(24);
      const offset = 4;

      ip.toBuffer('::1', buf, offset);

      assert.equal(
        buf.toString('hex'),
        '000000000000000000000000000000000000000100000000',
      );
    });

    it('should convert "1::"', () => {
      const buf = ip.toBuffer('1::');
      assert.equal(buf.toString('hex'), '00010000000000000000000000000000');
    });

    it('should convert "abcd::dcba"', () => {
      const buf = ip.toBuffer('abcd::dcba');
      assert.equal(buf.toString('hex'), 'abcd000000000000000000000000dcba');
    });

    it('should convert "2001:0db8:85a3:0000:0000:8a2e:0370:7334"', () => {
      const buf = ip.toBuffer('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
      assert.equal(buf.toString('hex'), '20010db885a3000000008a2e03707334');
    });

    it('should convert "2001:db8:85a3::8a2e:370:7334"', () => {
      const buf = ip.toBuffer('2001:db8:85a3::8a2e:370:7334');
      assert.equal(buf.toString('hex'), '20010db885a3000000008a2e03707334');
    });

    it('should convert "::"', () => {
      const buf = ip.toBuffer('::');
      assert.equal(buf.toString('hex'), '00000000000000000000000000000000');
    });

    it('should convert "ff00::1"', () => {
      const buf = ip.toBuffer('ff00::1');
      assert.equal(buf.toString('hex'), 'ff000000000000000000000000000001');
    });

    it('should convert "fe80::1ff:fe23:4567:890a"', () => {
      const buf = ip.toBuffer('fe80::1ff:fe23:4567:890a');
      assert.equal(buf.toString('hex'), 'fe8000000000000001fffe234567890a');
    });

    it('should convert "2002:c000:0204::"', () => {
      const buf = ip.toBuffer('2002:c000:0204::');
      assert.equal(buf.toString('hex'), '2002c000020400000000000000000000');
    });

    it('should convert "fc00::"', () => {
      const buf = ip.toBuffer('fc00::');
      assert.equal(buf.toString('hex'), 'fc000000000000000000000000000000');
    });

    it('should convert "2001:0db8:1234:5678:9abc:def0:1234:5678"', () => {
      const buf = ip.toBuffer('2001:0db8:1234:5678:9abc:def0:1234:5678');
      assert.equal(buf.toString('hex'), '20010db8123456789abcdef012345678');
    });

    it('should convert "::ffff:c000:280"', () => {
      const buf = ip.toBuffer('::ffff:c000:280');
      assert.equal(buf.toString('hex'), '00000000000000000000ffffc0000280');
    });

    it('should convert "fec0::"', () => {
      const buf = ip.toBuffer('fec0::');
      assert.equal(buf.toString('hex'), 'fec00000000000000000000000000000');
    });

    it('should convert "ff02::1"', () => {
      const buf = ip.toBuffer('ff02::1');
      assert.equal(buf.toString('hex'), 'ff020000000000000000000000000001');
    });

    it('should convert "ff02::2"', () => {
      const buf = ip.toBuffer('ff02::2');
      assert.equal(buf.toString('hex'), 'ff020000000000000000000000000002');
    });

    it('should convert "ff02::1:ff00:0"', () => {
      const buf = ip.toBuffer('ff02::1:ff00:0');
      assert.equal(buf.toString('hex'), 'ff0200000000000000000001ff000000');
    });
  });
});

describe('toString() from Uint8Array', () => {
  describe('IPv4', () => {
    it('should convert "127.0.0.1"', () => {
      const bytes = ip.toUInt8Array('127.0.0.1');
      assert.equal(ip.toString(bytes), '127.0.0.1');
    });
  });

  describe('IPv4 mapped IPv6', () => {
    it('should convert "::ffff:c000:280"', () => {
      const bytes = ip.toUInt8Array('::ffff:c000:280');
      assert.equal(ip.toString(bytes), '::ffff:c000:280');
    });

    it('should convert "::ffff:192.0.2.128"', () => {
      const bytes = ip.toUInt8Array('::ffff:192.0.2.128');
      assert.equal(ip.toString(bytes), '::ffff:c000:280');
    });

    it('should convert "0:0:0:0:0:ffff:192.0.2.128"', () => {
      const bytes = ip.toUInt8Array('0:0:0:0:0:ffff:192.0.2.128');
      assert.equal(ip.toString(bytes), '::ffff:c000:280');
    });
  });

  describe('IPv6', () => {
    it('should convert "::"', () => {
      const bytes = ip.toUInt8Array('::');
      assert.equal(ip.toString(bytes), '::');
    });

    it('should convert "::1"', () => {
      const bytes = ip.toUInt8Array('::1');
      assert.equal(ip.toString(bytes), '::1');
    });

    it('should convert "ff00::1"', () => {
      const bytes = ip.toUInt8Array('ff00::1');
      assert.equal(ip.toString(bytes), 'ff00::1');
    });

    it('should convert "2001:0db8:85a3:0000:0000:8a2e:0370:7334"', () => {
      const bytes = ip.toUInt8Array('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
      assert.equal(ip.toString(bytes), '2001:db8:85a3::8a2e:370:7334');
    });

    it('should convert "2001:db8:85a3::8a2e:370:7334"', () => {
      const bytes = ip.toUInt8Array('2001:db8:85a3::8a2e:370:7334');
      assert.equal(ip.toString(bytes), '2001:db8:85a3::8a2e:370:7334');
    });

    it('should convert "fe80::1ff:fe23:4567:890a"', () => {
      const bytes = ip.toUInt8Array('fe80::1ff:fe23:4567:890a');
      assert.equal(ip.toString(bytes), 'fe80::1ff:fe23:4567:890a');
    });

    it('should convert "2002:c000:0204::"', () => {
      const bytes = ip.toUInt8Array('2002:c000:0204::');
      assert.equal(ip.toString(bytes), '2002:c000:204::');
    });

    it('should convert "fc00::"', () => {
      const bytes = ip.toUInt8Array('fc00::');
      assert.equal(ip.toString(bytes), 'fc00::');
    });

    it('should convert "2001:0db8:1234:5678:9abc:def0:1234:5678"', () => {
      const bytes = ip.toUInt8Array('2001:0db8:1234:5678:9abc:def0:1234:5678');
      assert.equal(
        ip.toString(bytes),
        '2001:db8:1234:5678:9abc:def0:1234:5678',
      );
    });

    it('should convert "fec0::"', () => {
      const bytes = ip.toUInt8Array('fec0::');
      assert.equal(ip.toString(bytes), 'fec0::');
    });

    it('should convert "ff02::1"', () => {
      const bytes = ip.toUInt8Array('ff02::1');
      assert.equal(ip.toString(bytes), 'ff02::1');
    });

    it('should convert "ff02::2"', () => {
      const bytes = ip.toUInt8Array('ff02::2');
      assert.equal(ip.toString(bytes), 'ff02::2');
    });

    it('should convert "ff02::1:ff00:0"', () => {
      const bytes = ip.toUInt8Array('ff02::1:ff00:0');
      assert.equal(ip.toString(bytes), 'ff02::1:ff00:0');
    });
  });
});

describe('toString() from Buffer', () => {
  describe('IPv4', () => {
    it('should convert to buffer IPv4 address', () => {
      const buf = ip.toBuffer('127.0.0.1');
      assert.equal(ip.toString(buf), '127.0.0.1');
    });

    it('should convert to buffer IPv4 address in-place', () => {
      const buf = Buffer.alloc(32);
      const offset = 16;

      ip.toBuffer('127.0.0.1', buf, offset);

      assert.equal(ip.toString(buf, offset, 4), '127.0.0.1');
    });
  });

  describe('IPv4 mapped IPv6', () => {
    it('should convert "::ffff:192.0.2.128"', () => {
      const buf = ip.toBuffer('::ffff:192.0.2.128');
      assert.equal(ip.toString(buf), '::ffff:c000:280');
    });

    it('should convert "ffff::127.0.0.1"', () => {
      const buf = ip.toBuffer('ffff::127.0.0.1');
      assert.equal(ip.toString(buf), 'ffff::7f00:1');
    });
  });

  describe('IPv6', () => {
    it('should convert to buffer IPv6 address', () => {
      const buf = ip.toBuffer('::1');
      assert.equal(ip.toString(buf), '::1');
    });

    it('should convert to buffer IPv6 address in-place', () => {
      const buf = Buffer.alloc(32);
      const offset = 16;

      ip.toBuffer('::1', buf, offset);

      assert.equal(ip.toString(buf, offset, 16), '::1');
    });

    it('should convert "1::"', () => {
      assert.equal(ip.toString(ip.toBuffer('1::')), '1::');
    });

    it('should convert "abcd::dcba"', () => {
      assert.equal(ip.toString(ip.toBuffer('abcd::dcba')), 'abcd::dcba');
    });

    it('should convert "2001:0db8:85a3:0000:0000:8a2e:0370:7334"', () => {
      const buf = ip.toBuffer('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
      assert.equal(ip.toString(buf), '2001:db8:85a3::8a2e:370:7334');
    });

    it('should convert "2001:db8:85a3::8a2e:370:7334"', () => {
      const buf = ip.toBuffer('2001:db8:85a3::8a2e:370:7334');
      assert.equal(ip.toString(buf), '2001:db8:85a3::8a2e:370:7334');
    });

    it('should convert "::"', () => {
      const buf = ip.toBuffer('::');
      assert.equal(ip.toString(buf), '::');
    });

    it('should convert "0:0:0:0:0:ffff:127.0.0.1"', () => {
      const buf = ip.toBuffer('0:0:0:0:0:ffff:127.0.0.1');
      assert.equal(ip.toString(buf), '::ffff:7f00:1');
    });

    it('should convert "ff00::1"', () => {
      const buf = ip.toBuffer('ff00::1');
      assert.equal(ip.toString(buf), 'ff00::1');
    });

    it('should convert "fe80::1ff:fe23:4567:890a"', () => {
      const buf = ip.toBuffer('fe80::1ff:fe23:4567:890a');
      assert.equal(ip.toString(buf), 'fe80::1ff:fe23:4567:890a');
    });

    it('should convert "2002:c000:0204::"', () => {
      const buf = ip.toBuffer('2002:c000:0204::');
      assert.equal(ip.toString(buf), '2002:c000:204::');
    });

    it('should convert "fc00::"', () => {
      const buf = ip.toBuffer('fc00::');
      assert.equal(ip.toString(buf), 'fc00::');
    });

    it('should convert "2001:0db8:1234:5678:9abc:def0:1234:5678"', () => {
      const buf = ip.toBuffer('2001:0db8:1234:5678:9abc:def0:1234:5678');
      assert.equal(ip.toString(buf), '2001:db8:1234:5678:9abc:def0:1234:5678');
    });

    it('should convert "::ffff:c000:280"', () => {
      const buf = ip.toBuffer('::ffff:c000:280');
      assert.equal(ip.toString(buf), '::ffff:c000:280');
    });

    it('should convert "fec0::"', () => {
      const buf = ip.toBuffer('fec0::');
      assert.equal(ip.toString(buf), 'fec0::');
    });

    it('should convert "ff02::1"', () => {
      const buf = ip.toBuffer('ff02::1');
      assert.equal(ip.toString(buf), 'ff02::1');
    });

    it('should convert "ff02::2"', () => {
      const buf = ip.toBuffer('ff02::2');
      assert.equal(ip.toString(buf), 'ff02::2');
    });

    it('should convert "ff02::1:ff00:0"', () => {
      const buf = ip.toBuffer('ff02::1:ff00:0');
      assert.equal(ip.toString(buf), 'ff02::1:ff00:0');
    });
  });
});

describe('fromPrefixLen() method', () => {
  it('should create IPv4 mask', () => {
    assert.equal(ip.fromPrefixLen(24), '255.255.255.0');
  });

  it('should create IPv6 mask', () => {
    assert.equal(ip.fromPrefixLen(64), 'ffff:ffff:ffff:ffff::');
  });

  it('should create IPv6 mask explicitly', () => {
    assert.equal(ip.fromPrefixLen(24, 'IPv6'), 'ffff:ff00::');
  });
});

describe('not() method', () => {
  it('should reverse bits in IPv4 address', () => {
    assert.equal(ip.not('255.255.255.0'), '0.0.0.255');
  });

  it('should reverse bits in IPv6 address', () => {
    assert.equal(ip.not('::FFFF'), 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:0');
  });
});

describe('or() method', () => {
  it('should or bits in IPv4 addresses', () => {
    assert.equal(ip.or('0.0.0.255', '192.168.1.10'), '192.168.1.255');
  });

  it('should or bits in IPv6 addresses', () => {
    assert.equal(
      ip.or('::ff', '::abcd:dcba:abcd:dcba'),
      '::abcd:dcba:abcd:dcff',
    );
  });

  it('should or bits in mixed addresses', () => {
    assert.equal(
      ip.or('0.0.0.255', '::abcd:dcba:abcd:dcba'),
      '::abcd:dcba:abcd:dcff',
    );
  });
});

describe('mask() method', () => {
  it('should mask bits in ipv4 address', () => {
    assert.equal(ip.mask('192.168.1.134', '255.255.255.0'), '192.168.1.0');
  });

  it('should mask bits in ipv6 address', () => {
    assert.equal(ip.mask('ffff::', 'ff00::'), 'ff00::');
  });

  it('should mask bits in ipv4 embedded address', () => {
    assert.equal(ip.mask('192.168.1.134', '::ffff:ff00'), '::ffff:c0a8:100');
  });

  it('should apply low order bits from v4 mask to v6', () => {
    assert.equal(ip.mask('::f7f7', '0.0.0.255'), '::f7');
  });
});

describe('subnet() method', () => {
  // Test cases calculated with http://www.subnet-calculator.com/
  describe('255.255.255.192 subnet mask', () => {
    const IPv4Subnet = ip.subnet('192.168.1.134', '255.255.255.192');

    it('should compute IPv4 network address', () => {
      assert.equal(IPv4Subnet.networkAddress, '192.168.1.128');
    });

    it("should compute IPv4 network's first address", () => {
      assert.equal(IPv4Subnet.firstAddress, '192.168.1.129');
    });

    it("should compute IPv4 network's last address", () => {
      assert.equal(IPv4Subnet.lastAddress, '192.168.1.190');
    });

    it('should compute IPv4 broadcast address', () => {
      assert.equal(IPv4Subnet.broadcastAddress, '192.168.1.191');
    });

    it('should compute IPv4 subnet number of addresses', () => {
      assert.equal(IPv4Subnet.length, 64);
    });

    it('should compute IPv4 subnet number of addressable hosts', () => {
      assert.equal(IPv4Subnet.numHosts, 62);
    });

    it('should compute IPv4 subnet mask', () => {
      assert.equal(IPv4Subnet.subnetMask, '255.255.255.192');
    });

    it("should compute IPv4 subnet mask's length", () => {
      assert.equal(IPv4Subnet.subnetMaskLength, 26);
    });

    it('should know whether a subnet contains an address', () => {
      assert.equal(IPv4Subnet.contains('192.168.1.180'), true);
    });

    it('should know whether a subnet does not contain an address', () => {
      assert.equal(IPv4Subnet.contains('192.168.1.195'), false);
    });
  });

  describe('255.255.255.255 subnet mask', () => {
    const IPv4Subnet = ip.subnet('192.168.1.134', '255.255.255.255');

    it("should compute IPv4 network's first address", () => {
      assert.equal(IPv4Subnet.firstAddress, '192.168.1.134');
    });

    it("should compute IPv4 network's last address", () => {
      assert.equal(IPv4Subnet.lastAddress, '192.168.1.134');
    });

    it('should compute IPv4 subnet number of addressable hosts', () => {
      assert.equal(IPv4Subnet.numHosts, 1);
    });
  });

  describe('255.255.255.254 subnet mask', () => {
    const IPv4Subnet = ip.subnet('192.168.1.134', '255.255.255.254');

    it("should compute IPv4 network's first address", () => {
      assert.equal(IPv4Subnet.firstAddress, '192.168.1.134');
    });

    it("should compute IPv4 network's last address", () => {
      assert.equal(IPv4Subnet.lastAddress, '192.168.1.135');
    });

    it('should compute IPv4 subnet number of addressable hosts', () => {
      assert.equal(IPv4Subnet.numHosts, 2);
    });
  });
});

describe('cidrSubnet() method', () => {
  // Test cases calculated with http://www.subnet-calculator.com/
  describe('/26 subnet mask', () => {
    const IPv4Subnet = ip.cidrSubnet('192.168.1.134/26');

    it('should compute an IPv4 network address', () => {
      assert.equal(IPv4Subnet.networkAddress, '192.168.1.128');
    });

    it("should compute an IPv4 network's first address", () => {
      assert.equal(IPv4Subnet.firstAddress, '192.168.1.129');
    });

    it("should compute an IPv4 network's last address", () => {
      assert.equal(IPv4Subnet.lastAddress, '192.168.1.190');
    });

    it('should compute an IPv4 broadcast address', () => {
      assert.equal(IPv4Subnet.broadcastAddress, '192.168.1.191');
    });

    it('should compute an IPv4 subnet number of addresses', () => {
      assert.equal(IPv4Subnet.length, Math.pow(2, 6));
    });

    it('should compute an IPv4 subnet number of addressable hosts', () => {
      assert.equal(IPv4Subnet.numHosts, Math.pow(2, 6) - 2);
    });

    it('should compute an IPv4 subnet mask', () => {
      assert.equal(IPv4Subnet.subnetMask, '255.255.255.192');
    });

    it("should compute an IPv4 subnet mask's length", () => {
      assert.equal(IPv4Subnet.subnetMaskLength, 26);
    });

    it('should know whether a subnet contains an address', () => {
      assert.equal(IPv4Subnet.contains('192.168.1.180'), true);
    });

    it('should know whether a subnet does not contain an address', () => {
      assert.equal(IPv4Subnet.contains('192.168.1.195'), false);
    });
  });

  describe('/8 subnet mask', () => {
    const IPv4Subnet = ip.cidrSubnet('192.168.1.134/8');

    it('should compute an IPv4 network address', () => {
      assert.equal(IPv4Subnet.networkAddress, '192.0.0.0');
    });

    it("should compute an IPv4 network's first address", () => {
      assert.equal(IPv4Subnet.firstAddress, '192.0.0.1');
    });

    it("should compute an IPv4 network's last address", () => {
      assert.equal(IPv4Subnet.lastAddress, '192.255.255.254');
    });

    it('should compute an IPv4 broadcast address', () => {
      assert.equal(IPv4Subnet.broadcastAddress, '192.255.255.255');
    });

    it('should compute an IPv4 subnet number of addresses', () => {
      assert.equal(IPv4Subnet.length, Math.pow(2, 24));
    });

    it('should compute an IPv4 subnet number of addressable hosts', () => {
      assert.equal(IPv4Subnet.numHosts, Math.pow(2, 24) - 2);
    });

    it('should compute an IPv4 subnet mask', () => {
      assert.equal(IPv4Subnet.subnetMask, '255.0.0.0');
    });

    it("should compute an IPv4 subnet mask's length", () => {
      assert.equal(IPv4Subnet.subnetMaskLength, 8);
    });

    it('should know whether a subnet contains an address', () => {
      assert.equal(IPv4Subnet.contains('192.168.1.180'), true);
    });

    it('should know whether a subnet does not contain an address', () => {
      assert.equal(IPv4Subnet.contains('193.0.0.0'), false);
    });
  });

  describe('/32 subnet mask', () => {
    const IPv4Subnet = ip.cidrSubnet('192.168.1.134/32');

    it('should compute an IPv4 network address', () => {
      assert.equal(IPv4Subnet.networkAddress, '192.168.1.134');
    });

    it("should compute an IPv4 network's first address", () => {
      assert.equal(IPv4Subnet.firstAddress, '192.168.1.134');
    });

    it("should compute an IPv4 network's last address", () => {
      assert.equal(IPv4Subnet.lastAddress, '192.168.1.134');
    });

    it('should compute an IPv4 broadcast address', () => {
      assert.equal(IPv4Subnet.broadcastAddress, '192.168.1.134');
    });

    it('should compute an IPv4 subnet number of addresses', () => {
      assert.equal(IPv4Subnet.length, 1);
    });

    it('should compute an IPv4 subnet number of addressable hosts', () => {
      assert.equal(IPv4Subnet.numHosts, 1);
    });

    it('should compute an IPv4 subnet mask', () => {
      assert.equal(IPv4Subnet.subnetMask, '255.255.255.255');
    });

    it("should compute an IPv4 subnet mask's length", () => {
      assert.equal(IPv4Subnet.subnetMaskLength, 32);
    });

    it('should know whether a subnet contains an address', () => {
      assert.equal(IPv4Subnet.contains('192.168.1.134'), true);
    });

    it('should know whether a subnet contains an address', () => {
      assert.equal(IPv4Subnet.contains('192.168.1.135'), false);
    });
  });
});

describe('cidr() method', () => {
  it('should mask address in CIDR notation', () => {
    assert.equal(ip.cidr('192.168.1.134/26'), '192.168.1.128');
    assert.equal(ip.cidr('2607:f0d0:1002:51::4/56'), '2607:f0d0:1002::');
  });
});

describe('isEqual() method', () => {
  it('should check if addresses are equal', () => {
    assert.equal(ip.isEqual('127.0.0.1', '::7f00:1'), true);
  });

  it('should check if addresses are not equal', () => {
    assert.equal(ip.isEqual('127.0.0.1', '::7f00:2'), false);
  });

  it('should check if addresses are equal with IPv4-mapped IPv6 address', () => {
    assert.equal(ip.isEqual('127.0.0.1', '::ffff:7f00:1'), true);
  });

  it('should check if addresses are not equal with invalid IPv6 address', () => {
    assert.equal(ip.isEqual('127.0.0.1', '::ffaf:7f00:1'), false);
  });

  it('should check if addresses are equal with IPv4-mapped IPv6 address', () => {
    assert.equal(ip.isEqual('::ffff:127.0.0.1', '::ffff:127.0.0.1'), true);
  });

  it('should check if addresses are equal with IPv4-mapped IPv6 address and IPv4 address', () => {
    assert.equal(ip.isEqual('::ffff:127.0.0.1', '127.0.0.1'), true);
  });
});

describe('normalizeToLong() method', () => {
  it('should correctly normalize "127.0.0.1"', () => {
    assert.equal(ip.normalizeToLong('127.0.0.1'), 2130706433);
  });

  it('should correctly handle "127.1" as two parts', () => {
    assert.equal(ip.normalizeToLong('127.1'), 2130706433);
  });

  it('should correctly handle "127.0.1" as three parts', () => {
    assert.equal(ip.normalizeToLong('127.0.1'), 2130706433);
  });

  it('should correctly handle hexadecimal notation "0x7f.0x0.0x0.0x1"', () => {
    assert.equal(ip.normalizeToLong('0x7f.0x0.0x0.0x1'), 2130706433);
  });

  // Testing with fewer than 4 parts
  it('should correctly handle "0x7f000001" as a single part', () => {
    assert.equal(ip.normalizeToLong('0x7f000001'), 2130706433);
  });

  it('should correctly handle octal notation "010.0.0.01"', () => {
    assert.equal(ip.normalizeToLong('010.0.0.01'), 134217729);
  });

  // Testing invalid inputs
  it('should return -1 for an invalid address "256.100.50.25"', () => {
    assert.equal(ip.normalizeToLong('256.100.50.25'), -1);
  });

  it('should return -1 for an address with invalid octal "019.0.0.1"', () => {
    assert.equal(ip.normalizeToLong('019.0.0.1'), -1);
  });

  it('should return -1 for an address with invalid hex "0xGG.0.0.1"', () => {
    assert.equal(ip.normalizeToLong('0xGG.0.0.1'), -1);
  });

  // Testing edge cases
  it('should return -1 for an empty string', () => {
    assert.equal(ip.normalizeToLong(''), -1);
  });

  it('should return -1 for a string with too many parts "192.168.0.1.100"', () => {
    assert.equal(ip.normalizeToLong('192.168.0.1.100'), -1);
  });
});

describe('isPrivate() method', () => {
  describe('IPv4', () => {
    it('should mark localhost as private', () => {
      assert.equal(ip.isPrivate('127.0.0.1'), true);
    });

    it('should mark 192.168.0.0/16 as private', () => {
      assert.equal(ip.isPrivate('192.168.0.123'), true);
      assert.equal(ip.isPrivate('192.168.122.123'), true);
      assert.equal(ip.isPrivate('192.169.0.0'), false);
    });

    it('should mark 172.16.0.0/12 as private', () => {
      assert.equal(ip.isPrivate('172.16.0.5'), true);
      assert.equal(ip.isPrivate('172.16.123.254'), true);
      assert.equal(ip.isPrivate('171.16.0.5'), false);
      assert.equal(ip.isPrivate('172.25.232.15'), true);
      assert.equal(ip.isPrivate('172.15.0.5'), false);
      assert.equal(ip.isPrivate('172.32.0.5'), false);
    });

    it('should mark 10.0.0.0/8 as private', () => {
      assert.equal(ip.isPrivate('10.0.2.3'), true);
      assert.equal(ip.isPrivate('10.1.23.45'), true);
      assert.equal(ip.isPrivate('12.1.2.3'), false);
    });

    it('should mark link local as private', () => {
      assert.equal(ip.isPrivate('169.254.2.3'), true);
      assert.equal(ip.isPrivate('169.254.221.9'), true);
      assert.equal(ip.isPrivate('168.254.2.3'), false);
    });

    it('should handle irregular address "0x7f.1"', () => {
      // 127.0.0.1
      assert.equal(ip.isPrivate('0x7f.1'), true);
    });

    it('should handle irregular address "0300.0XA8.3"', () => {
      // 192.168.0.3
      assert.equal(ip.isPrivate('0300.0XA8.3'), true);
    });

    it('should handle irregular address "01200034567"', () => {
      // 10.0.57.119
      assert.equal(ip.isPrivate('01200034567'), true);
    });

    it('should handle irregular address "012.1.2.3"', () => {
      // 10.1.2.3
      assert.equal(ip.isPrivate('012.1.2.3'), true);
    });

    it('should check if an address is from the internet', () => {
      assert.equal(ip.isPrivate('8.8.8.8'), false);
    });
  });

  describe('IPv4 mapped IPv6', () => {
    it('should mark 10.0.0.0/8 in IPv4-mapped IPv6 as private', () => {
      assert.equal(ip.isPrivate('::ffff:10.100.1.42'), true);
    });

    it('should mark 172.16.0.0/12 in IPv4-mapped IPv6 as private', () => {
      assert.equal(ip.isPrivate('::FFFF:172.16.200.1'), true);
    });

    it('should mark 192.168.0.0/16 in IPv4-mapped IPv6 as private', () => {
      assert.equal(ip.isPrivate('::ffff:192.168.0.1'), true);
    });
  });

  describe('IPv6', () => {
    it('should check if an address is a loopback IPv6 address', () => {
      assert.equal(ip.isPrivate('::'), true);
      assert.equal(ip.isPrivate('::1'), true);
      assert.equal(ip.isPrivate('fe80::1'), true);
    });

    it('should check if an address is from a private IPv6 network', () => {
      assert.equal(ip.isPrivate('fd12:3456:789a:1::1'), true);
      assert.equal(ip.isPrivate('fe80::f2de:f1ff:fe3f:307e'), true);
    });
  });
});

describe('isPublic() method', () => {
  describe('IPv4', () => {
    it('should say localhost is not public', () => {
      assert.equal(ip.isPublic('127.0.0.1'), false);
    });

    it('should say "10.0.0.1" is not public', () => {
      assert.equal(ip.isPublic('10.0.0.1'), false);
    });

    it('should say "192.168.1.1" is not public', () => {
      assert.equal(ip.isPublic('192.168.1.1'), false);
    });

    it('should say "172.16.0.1" is not public', () => {
      assert.equal(ip.isPublic('172.16.0.1'), false);
    });

    it('should say "8.8.8.8" is public', () => {
      assert.equal(ip.isPublic('8.8.8.8'), true);
    });

    it('should say bogus ipv4 is not public', () => {
      assert.equal(ip.isPublic('999.999.999.999'), false);
    });
  });

  describe('IPv4 mapped IPv6', () => {
    it('should say localhost is not public', () => {
      assert.equal(ip.isPublic('::FFFF:127.0.0.1'), false);
    });

    it('should say "::FFFF:8.8.8.8" is public', () => {
      assert.equal(ip.isPublic('::FFFF:8.8.8.8'), true);
    });
  });

  describe('IPv6', () => {
    it('should say "::1" is not public', () => {
      assert.equal(ip.isPublic('::1'), false);
    });

    it('should say "fd00::1" is not public', () => {
      assert.equal(ip.isPublic('fd00::1'), false);
    });

    it('should say "2607:f8b0:4007:80f::200e" is public', () => {
      assert.equal(ip.isPublic('2607:f8b0:4007:80f::200e'), true);
    });

    it('should say bogus ipv6 is not public', () => {
      assert.equal(ip.isPublic('FFFG::'), false);
    });
  });
});

describe('isLoopback() method', () => {
  describe('IPv4', () => {
    it('should respond true for "127.0.0.1"', () => {
      assert.equal(ip.isLoopback('127.0.0.1'), true);
    });

    it('should respond true for "127.8.8.8"', () => {
      assert.equal(ip.isLoopback('127.8.8.8'), true);
    });

    it('should respond true for "0177.0.0.1"', () => {
      assert.equal(ip.isLoopback('0177.0.0.1'), true);
    });

    it('should respond true for "0177.0.1"', () => {
      assert.equal(ip.isLoopback('0177.0.1'), true);
    });

    it('should respond true for "0177.1"', () => {
      assert.equal(ip.isLoopback('0177.1'), true);
    });

    it('should respond true for "017700000001"', () => {
      assert.equal(ip.isLoopback('017700000001'), true);
    });

    it('should respond true for "0x7f.0.0.1"', () => {
      assert.equal(ip.isLoopback('0x7f.0.0.1'), true);
    });

    it('should respond true for "0x7F.0.1"', () => {
      assert.equal(ip.isLoopback('0x7F.0.1'), true);
    });

    it('should respond true for "0X7f.1"', () => {
      assert.equal(ip.isLoopback('0X7f.1'), true);
    });

    it('should respond true for "0X7F000001"', () => {
      assert.equal(ip.isLoopback('0X7F000001'), true);
    });

    it('should respond true for "127.0.1"', () => {
      assert.equal(ip.isLoopback('127.0.1'), true);
    });

    it('should respond true for "127.1"', () => {
      assert.equal(ip.isLoopback('127.1'), true);
    });

    it('should respond true for "2130706433"', () => {
      assert.equal(ip.isLoopback('2130706433'), true);
    });

    it('should respond true for "127.00.0x1"', () => {
      assert.equal(ip.isLoopback('127.00.0x1'), true);
    });

    it('should respond true for "127.0.0x0.1"', () => {
      assert.equal(ip.isLoopback('127.0.0x0.1'), true);
    });

    it('should respond true for "0x7f.01"', () => {
      assert.equal(ip.isLoopback('0x7f.01'), true);
    });

    it('should respond false for "8.8.8.8"', () => {
      assert.equal(ip.isLoopback('8.8.8.8'), false);
    });

    it('should respond false for "192.168.1.1"', () => {
      assert.equal(ip.isLoopback('192.168.1.1'), false);
    });
  });

  describe('IPv4 mapped IPv6', () => {
    it('should respond true for "::ffff:127.0.0.1"', () => {
      assert.equal(ip.isLoopback('::ffff:127.0.0.1'), true);
    });

    it('should respond true for "::ffff:127.8.8.8"', () => {
      assert.equal(ip.isLoopback('::ffff:127.8.8.8'), true);
    });

    it('should respond false for "::127.8.8.8"', () => {
      assert.equal(ip.isLoopback('::127.8.8.8'), false);
    });

    it('should respond false for "::ffff:8.8.8.8"', () => {
      assert.equal(ip.isLoopback('::ffff:8.8.8.8'), false);
    });

    it('should respond false for "::ffff:192.168.1.1"', () => {
      assert.equal(ip.isLoopback('::ffff:192.168.1.1'), false);
    });
  });

  describe('IPv6', () => {
    it('should respond true for "::1"', () => {
      assert.equal(ip.isLoopback('::1'), true);
    });

    it('should respond true for "::01"', () => {
      assert.equal(ip.isLoopback('::01'), true);
    });

    it('should respond true for "::001"', () => {
      assert.equal(ip.isLoopback('::001'), true);
    });

    it('should respond true for "0::1"', () => {
      assert.equal(ip.isLoopback('0::1'), true);
    });

    it('should respond true for "000:0:0000::01"', () => {
      assert.equal(ip.isLoopback('000:0:0000::01'), true);
    });

    it('should respond true for "000:0:0000:0:000:0:00:001"', () => {
      assert.equal(ip.isLoopback('000:0:0000:0:000:0:00:001'), true);
    });
  });
});

describe('isLinkLocal() method', () => {
  describe('IPv4', () => {
    it('should respond true for "169.254.0.0"', () => {
      assert.equal(ip.isLinkLocal('169.254.0.0'), true);
    });

    it('should respond true for "169.254.255.255"', () => {
      assert.equal(ip.isLinkLocal('169.254.255.255'), true);
    });

    it('should respond true for "0251.254.0.1"', () => {
      assert.equal(ip.isLinkLocal('0251.254.0.1'), true);
    });

    it('should respond true for "0251.254.1"', () => {
      assert.equal(ip.isLinkLocal('0251.254.1'), true);
    });

    it('should respond true for "025177400000"', () => {
      assert.equal(ip.isLinkLocal('025177400000'), true);
    });

    it('should respond true for "0xa9.0xfe.0.1"', () => {
      assert.equal(ip.isLinkLocal('0xa9.0xfe.0.1'), true);
    });

    it('should respond true for "0xa9.0xfe.1"', () => {
      assert.equal(ip.isLinkLocal('0xa9.0xfe.1'), true);
    });

    it('should respond true for "0XA9FE0001"', () => {
      assert.equal(ip.isLinkLocal('0XA9FE0001'), true);
    });

    it('should respond true for "2851995648"', () => {
      assert.equal(ip.isLinkLocal('2851995648'), true);
    });

    it('should respond true for "169.254.00.0x1"', () => {
      assert.equal(ip.isLinkLocal('169.254.00.0x1'), true);
    });

    it('should respond true for "169.254.0x0.1"', () => {
      assert.equal(ip.isLinkLocal('169.254.0x0.1'), true);
    });

    it('should respond false for "127.0.0.1"', () => {
      assert.equal(ip.isLinkLocal('127.0.0.1'), false);
    });

    it('should respond false for "8.8.8.8"', () => {
      assert.equal(ip.isLinkLocal('8.8.8.8'), false);
    });

    it('should respond false for "192.168.1.1"', () => {
      assert.equal(ip.isLinkLocal('192.168.1.1'), false);
    });
  });

  describe('IPv4 mapped IPv6', () => {
    it('should respond true for "::ffff:169.254.0.1"', () => {
      assert.equal(ip.isLinkLocal('::ffff:169.254.0.1'), true);
    });

    it('should respond true for "::ffff:169.254.255.255"', () => {
      assert.equal(ip.isLinkLocal('::ffff:169.254.255.255'), true);
    });

    it('should respond false for "::169.254.255.255"', () => {
      assert.equal(ip.isLinkLocal('::169.254.255.255'), false);
    });

    it('should respond false for "::ffff:8.8.8.8"', () => {
      assert.equal(ip.isLinkLocal('::ffff:8.8.8.8'), false);
    });

    it('should respond false for "::ffff:192.168.1.1"', () => {
      assert.equal(ip.isLinkLocal('::ffff:192.168.1.1'), false);
    });
  });

  describe('IPv6', () => {
    it('should respond true for "fe80::1"', () => {
      assert.equal(ip.isLinkLocal('fe80::1'), true);
    });

    it('should respond true for "fe80::01"', () => {
      assert.equal(ip.isLinkLocal('fe80::01'), true);
    });

    it('should respond true for "fe80::001"', () => {
      assert.equal(ip.isLinkLocal('fe80::001'), true);
    });

    it('should respond true for "fe80:0::1"', () => {
      assert.equal(ip.isLinkLocal('fe80:0::1'), true);
    });

    it('should respond true for "fe80:000:0:0000::01"', () => {
      assert.equal(ip.isLinkLocal('fe80:000:0:0000::01'), true);
    });

    it('should respond true for "fe80:0:0000:0:000:0:00:001"', () => {
      assert.equal(ip.isLinkLocal('fe80:0:0000:0:000:0:00:001'), true);
    });

    it('should respond false for "ffff::1"', () => {
      assert.equal(ip.isLinkLocal('ffff::1'), false);
    });
  });
});

describe('isReserved() method', () => {
  describe('IPv4', () => {
    it('should respond true for "0.0.0.0"', () => {
      assert.equal(ip.isReserved('0.0.0.0'), true);
    });

    it('should respond true for "0"', () => {
      assert.equal(ip.isReserved('0'), true);
    });

    it('should respond true for "0.0"', () => {
      assert.equal(ip.isReserved('0.0'), true);
    });

    it('should respond true for "0.0.0"', () => {
      assert.equal(ip.isReserved('0.0.0'), true);
    });

    it('should respond true for "255.255.255.255"', () => {
      assert.equal(ip.isReserved('255.255.255.255'), true);
    });

    it('should respond true for "0xff.0xff.0xff.0xff"', () => {
      assert.equal(ip.isReserved('0xff.0xff.0xff.0xff'), true);
    });

    it('should respond true for "0377.0377.0377.0377"', () => {
      assert.equal(ip.isReserved('0377.0377.0377.0377'), true);
    });

    it('should respond false for "8.8.8.8"', () => {
      assert.equal(ip.isReserved('8.8.8.8'), false);
    });
  });

  describe('IPv4 mapped IPv6', () => {
    it('should respond true for "::ffff:0.0.0.0"', () => {
      assert.equal(ip.isReserved('::ffff:0.0.0.0'), true);
    });

    it('should respond true for "::ffff:255.255.255.255"', () => {
      assert.equal(ip.isReserved('::ffff:255.255.255.255'), true);
    });

    it('should respond false for "::ffff:8.8.8.8"', () => {
      assert.equal(ip.isReserved('::ffff:8.8.8.8'), false);
    });
  });

  describe('IPv6', () => {
    it('should respond true for "::"', () => {
      assert.equal(ip.isReserved('::'), true);
    });

    it('should respond true for "ff00::"', () => {
      assert.equal(ip.isReserved('ff00::'), true);
    });

    it('should respond true for "2001:db8::"', () => {
      assert.equal(ip.isReserved('2001:db8::'), true);
    });

    it('should respond false for "fe80::1"', () => {
      assert.equal(ip.isReserved('fe80::1'), false);
    });

    it('should respond false for "::1"', () => {
      assert.equal(ip.isReserved('::1'), false);
    });
  });
});

describe('loopback() method', () => {
  it('should respond with 127.0.0.1 by default', () => {
    assert.equal(ip.loopback(), '127.0.0.1');
  });

  it('should respond with 127.0.0.1 for IPv4', () => {
    assert.equal(ip.loopback('IPv4'), '127.0.0.1');
    assert.equal(ip.loopback(4), '127.0.0.1');
  });

  it('should respond with fe80::1 for IPv6', () => {
    assert.equal(ip.loopback('IPv6'), 'fe80::1');
    assert.equal(ip.loopback(6), 'fe80::1');
  });
});

describe('address() method', () => {
  describe('default', () => {
    it('should respond with an IPv4 by default', () => {
      const addr = ip.address();
      assert.ok(addr === undefined || net.isIPv4(addr));
    });
  });

  describe('private', () => {
    it('should respond with a private IPv4 address by default', () => {
      const addr = ip.address('private');
      assert.ok(addr === undefined || net.isIPv4(addr));
      assert.ok(addr === undefined || ip.isPrivate(addr));
    });

    it('should respond with a private IPv4 address', () => {
      const addr = ip.address('private', 'IPv4');
      assert.ok(addr === undefined || net.isIPv4(addr));
      assert.ok(addr === undefined || ip.isPrivate(addr));
    });

    it('should respond with a private IPv6 address', () => {
      const addr = ip.address('private', 'IPv6');
      assert.ok(addr === undefined || net.isIPv6(addr));
      assert.ok(addr === undefined || ip.isPrivate(addr));
    });
  });

  // Also test out the network interfaces
  const interfaces = os.networkInterfaces();

  Object.keys(interfaces).forEach((nic) => {
    describe(nic, () => {
      it('should respond with an IPv4 address by default', () => {
        const addr = ip.address(nic);
        assert.ok(addr === undefined || net.isIPv4(addr));
      });

      it('should respond with an IPv4 address', () => {
        const addr = ip.address(nic, 'IPv4');
        assert.ok(addr === undefined || net.isIPv4(addr));
      });

      it('should respond with an IPv6 address', () => {
        const addr = ip.address(nic, 'IPv6');
        assert.ok(addr === undefined || net.isIPv6(addr));
      });
    });
  });
});

describe('toLong() method', () => {
  it('should respond with an int32', () => {
    assert.equal(ip.toLong('127.0.0.1'), 2130706433);
    assert.equal(ip.toLong('255.255.255.255'), 0xffffffff);
  });

  it('should reject ipv6 addresses', () => {
    assert.throws(() => ip.toLong('::1'));
  });
});

describe('fromLong() method', () => {
  it('should repond with IPv4 address', () => {
    assert.equal(ip.fromLong(0x7f000001), '127.0.0.1');
    assert.equal(ip.fromLong(0xffffffff), '255.255.255.255');
  });

  it('should reject non-IP values', () => {
    assert.throws(() => ip.fromLong(false as unknown as number));
    assert.throws(() => ip.fromLong('foo' as unknown as number));
    assert.throws(() => ip.fromLong([] as unknown as number));
    assert.throws(() => ip.fromLong({} as unknown as number));
    assert.throws(() => ip.fromLong(0xffffffff + 1));
  });
});

describe('normalize() method', () => {
  describe('IPv4', () => {
    it('should normalize int32 to dot notation', () => {
      assert.deepStrictEqual(ip.normalize(2130706433), '127.0.0.1');
    });

    it('should normalize "127.0.0.1"', () => {
      assert.deepStrictEqual(ip.normalize('127.0.0.1'), '127.0.0.1');
    });

    it('should normalize "127.0.1"', () => {
      assert.deepStrictEqual(ip.normalize('127.0.1'), '127.0.0.1');
    });

    it('should normalize "127.1"', () => {
      assert.deepStrictEqual(ip.normalize('127.1'), '127.0.0.1');
    });

    it('should normalize "1" as int32', () => {
      assert.deepStrictEqual(ip.normalize('1'), '0.0.0.1');
    });

    it('should normalize hexadecimal notation "0x7f.0x0.0x0.0x1"', () => {
      assert.deepStrictEqual(ip.normalize('0x7f.0x0.0x0.0x1'), '127.0.0.1');
    });

    it('should normalize octal notation "0177.0.0.01"', () => {
      assert.deepStrictEqual(ip.normalize('0177.0.0.01'), '127.0.0.1');
    });

    it('should normalize hex int32 "0x7f000001"', () => {
      assert.deepStrictEqual(ip.normalize('0x7f000001'), '127.0.0.1');
    });

    it('should throw for octets out of range', () => {
      assert.throws(() => ip.normalize('256.100.50.25'));
    });

    it('should throw for invalid octal', () => {
      assert.throws(() => ip.normalize('019.0.0.1'));
    });

    it('should throw for invalid hex', () => {
      assert.throws(() => ip.normalize('0xgg.0.0.1'));
    });

    it('should throw for empty string', () => {
      assert.throws(() => ip.normalize(''));
    });

    it('should throw for too many octets', () => {
      assert.throws(() => ip.normalize('127.0.0.0.1'));
    });
  });

  describe('IPv4 mapped IPv6', () => {
    it('should normalize "::fFFf:127.0.0.1"', () => {
      assert.equal(ip.normalize('::fFFf:127.0.0.1'), '::ffff:7f00:1');
    });

    it('should normalize "::127.0.0.1"', () => {
      assert.equal(ip.normalize('::127.0.0.1'), '::7f00:1');
    });
  });

  describe('IPv6', () => {
    it('should normalize "fe80::1"', () => {
      assert.equal(ip.normalize('fe80::1'), 'fe80::1');
    });

    it('should normalize "fe80::0001"', () => {
      assert.equal(ip.normalize('fe80::0001'), 'fe80::1');
    });

    it('should normalize "::"', () => {
      assert.equal(ip.normalize('::'), '::');
    });

    it('should normalize "::0"', () => {
      assert.equal(ip.normalize('::0'), '::');
    });

    it('should normalize "::000"', () => {
      assert.equal(ip.normalize('::000'), '::');
    });

    it('should normalize "::1"', () => {
      assert.equal(ip.normalize('::1'), '::1');
    });

    it('should normalize "::01"', () => {
      assert.equal(ip.normalize('::01'), '::1');
    });

    it('should normalize "::001"', () => {
      assert.equal(ip.normalize('::001'), '::1');
    });

    it('should normalize "0::1"', () => {
      assert.equal(ip.normalize('0::1'), '::1');
    });

    it('should normalize "000:0:0000::01"', () => {
      assert.equal(ip.normalize('000:0:0000::01'), '::1');
    });

    it('should normalize "000:0:0000:0:000:0:00:001"', () => {
      assert.equal(ip.normalize('000:0:0000:0:000:0:00:001'), '::1');
    });

    it('should throw for words out of range', () => {
      assert.throws(() => ip.normalize('::FFFG'));
    });

    it('should throw for too many :: tokens', () => {
      assert.throws(() => ip.normalize('::FFFF::1'));
    });

    it('should throw for too many words', () => {
      assert.throws(() => ip.normalize('0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0'));
    });
  });
});
