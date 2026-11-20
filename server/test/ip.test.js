import { describe, expect, it } from "vitest";
import { isBlockedAddress } from "../src/security/ip.js";

// [range, allowed example just outside, blocked example inside]
const IPV4_RANGES = [
  ["0.0.0.0/8", "1.0.0.0", "0.0.0.0"],
  ["0.0.0.0/8 top", "1.0.0.1", "0.255.255.255"],
  ["10.0.0.0/8", "11.0.0.0", "10.0.0.1"],
  ["10.0.0.0/8 top", "9.255.255.255", "10.255.255.255"],
  ["100.64.0.0/10", "100.63.255.255", "100.64.0.0"],
  ["100.64.0.0/10 top", "100.128.0.0", "100.127.255.255"],
  ["127.0.0.0/8", "128.0.0.1", "127.0.0.1"],
  ["127.0.0.0/8 top", "126.255.255.255", "127.255.255.254"],
  ["169.254.0.0/16", "169.253.255.255", "169.254.0.1"],
  ["169.254.169.254 metadata", "169.255.0.0", "169.254.169.254"],
  ["172.16.0.0/12 low", "172.15.255.255", "172.16.0.0"],
  ["172.16.0.0/12 high", "172.32.0.0", "172.31.255.255"],
  ["192.168.0.0/16", "192.167.255.255", "192.168.1.1"],
  ["192.168.0.0/16 top", "192.169.0.0", "192.168.255.255"],
  ["224.0.0.0/4 multicast", "223.255.255.255", "224.0.0.1"],
  ["224.0.0.0/4 top", "93.184.216.34", "239.255.255.255"],
  ["240.0.0.0/4 reserved", "203.0.113.10", "240.0.0.1"],
  ["255.255.255.255 broadcast", "8.8.8.8", "255.255.255.255"],
];

describe("isBlockedAddress: IPv4 ranges", () => {
  it.each(IPV4_RANGES)("%s: allows %s and blocks %s", (_range, allowed, blocked) => {
    expect(isBlockedAddress(allowed)).toBe(false);
    expect(isBlockedAddress(blocked)).toBe(true);
  });

  it("handles the 172.16/12 boundaries exactly", () => {
    expect(isBlockedAddress("172.15.255.255")).toBe(false);
    expect(isBlockedAddress("172.16.0.0")).toBe(true);
    expect(isBlockedAddress("172.31.255.255")).toBe(true);
    expect(isBlockedAddress("172.32.0.0")).toBe(false);
  });
});

const IPV6_RANGES = [
  ["::1 loopback", "2001:db8::1", "::1"],
  [":: unspecified", "2606:4700::1111", "::"],
  ["fc00::/7 unique-local (fc)", "fbff:ffff::1", "fc00::1"],
  ["fc00::/7 unique-local (fd)", "fe00::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
  ["fe80::/10 link-local", "fe7f:ffff::1", "fe80::1"],
  ["fe80::/10 top", "fec0::1", "febf:ffff::1"],
  ["ff00::/8 multicast", "feff:ffff::1", "ff02::1"],
  ["ff00::/8 top", "2a00:1450::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
];

describe("isBlockedAddress: IPv6 ranges", () => {
  it.each(IPV6_RANGES)("%s: allows %s and blocks %s", (_range, allowed, blocked) => {
    expect(isBlockedAddress(allowed)).toBe(false);
    expect(isBlockedAddress(blocked)).toBe(true);
  });

  it("accepts brackets, upper case and zone ids", () => {
    expect(isBlockedAddress("[::1]")).toBe(true);
    expect(isBlockedAddress("FE80::1")).toBe(true);
    expect(isBlockedAddress("fe80::1%eth0")).toBe(true);
    expect(isBlockedAddress("[2001:DB8::1]")).toBe(false);
  });

  it("blocks the whole deprecated IPv4-compatible range ::/96", () => {
    expect(isBlockedAddress("::127.0.0.1")).toBe(true);
    expect(isBlockedAddress("::8.8.8.8")).toBe(true);
  });
});

describe("isBlockedAddress: IPv4-mapped IPv6", () => {
  it("judges by the embedded IPv4 address (dotted form)", () => {
    expect(isBlockedAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isBlockedAddress("[::ffff:127.0.0.1]")).toBe(true);
    expect(isBlockedAddress("::ffff:169.254.169.254")).toBe(true);
    expect(isBlockedAddress("::ffff:10.1.2.3")).toBe(true);
    expect(isBlockedAddress("::ffff:192.168.0.1")).toBe(true);
    expect(isBlockedAddress("::ffff:8.8.8.8")).toBe(false);
    expect(isBlockedAddress("::ffff:203.0.113.5")).toBe(false);
  });

  it("judges by the embedded IPv4 address (hex form)", () => {
    expect(isBlockedAddress("::ffff:7f00:1")).toBe(true); // 127.0.0.1
    expect(isBlockedAddress("::ffff:a9fe:a9fe")).toBe(true); // 169.254.169.254
    expect(isBlockedAddress("::ffff:808:808")).toBe(false); // 8.8.8.8
    expect(isBlockedAddress("0:0:0:0:0:ffff:7f00:1")).toBe(true);
  });

  it("judges NAT64 (64:ff9b::/96) by the embedded IPv4 address", () => {
    expect(isBlockedAddress("64:ff9b::127.0.0.1")).toBe(true);
    expect(isBlockedAddress("64:ff9b::a9fe:a9fe")).toBe(true);
    expect(isBlockedAddress("64:ff9b::8.8.8.8")).toBe(false);
  });
});

describe("isBlockedAddress: fails closed", () => {
  it.each([
    "",
    "localhost",
    "2130706433",
    "0177.0.0.1",
    "0x7f.1",
    "127.1",
    "01.02.03.04",
    "256.0.0.1",
    "1.2.3",
    ":::1",
    "example.test",
  ])("blocks non-canonical or non-IP text %j", (text) => {
    expect(isBlockedAddress(text)).toBe(true);
  });

  it("blocks non-strings", () => {
    expect(isBlockedAddress(undefined)).toBe(true);
    expect(isBlockedAddress(2130706433)).toBe(true);
    expect(isBlockedAddress(null)).toBe(true);
  });
});
