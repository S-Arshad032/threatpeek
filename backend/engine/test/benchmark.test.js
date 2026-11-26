import { describe, it, expect } from "vitest";
import { SETS, loadSet, setNote, evaluate } from "../benchmark/lib.js";
import { BENCHMARK_MIN_DETECTION_RATE, BENCHMARK_MAX_FALSE_ALARM_RATE } from "../src/config.js";

// Regression guard on the dev set only. The held-out set is never asserted on, so it stays an
// honest measure (run it by hand with `npm run benchmark -- --set=heldout`).
const FICTIONAL_BRANDS = ["Galactibank", "Orbitins", "Nexamail", "VaultPay", "TrustLedger"];
const URL_HOST = /https?:\/\/([^/\s"]+)/g;
const RESERVED_OR_DOC_IP = /(?:\.(?:example|test|invalid)$)|^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/;
const REAL_TLD = /\.(?:com|net|org|io|co|me|info|biz|app|xyz|top|click)\b/i;
const BENGALI_BLOCK_START = 0x0980;
const BENGALI_BLOCK_END = 0x09ff;
const BENGALI_SCRIPT = new RegExp(
  `[${String.fromCodePoint(BENGALI_BLOCK_START)}-${String.fromCodePoint(BENGALI_BLOCK_END)}]`,
);

describe("benchmark dev set", () => {
  const set = loadSet("dev");

  it("is well formed: 35 scam and 35 benign, English only, reserved domains", () => {
    expect(set).toHaveLength(70);
    expect(set.filter((m) => m.label === "scam")).toHaveLength(35);
    expect(set.filter((m) => m.label === "benign")).toHaveLength(35);
    expect(new Set(set.map((m) => m.id)).size).toBe(70);
    for (const m of set) {
      expect(BENGALI_SCRIPT.test(m.text)).toBe(false);
      expect(REAL_TLD.test(m.text), m.id).toBe(false);
      for (const [, host] of m.text.matchAll(URL_HOST)) {
        expect(RESERVED_OR_DOC_IP.test(host), `${m.id}: ${host}`).toBe(true);
      }
    }
    expect(set.some((m) => FICTIONAL_BRANDS.some((b) => m.text.includes(b)))).toBe(true);
  });

  it(`detects >= ${BENCHMARK_MIN_DETECTION_RATE * 100}% of scams with <= ${BENCHMARK_MAX_FALSE_ALARM_RATE * 100}% false alarms`, () => {
    const ev = evaluate(set);
    expect(ev.detectionRate).toBeGreaterThanOrEqual(BENCHMARK_MIN_DETECTION_RATE);
    expect(ev.falseAlarmRate).toBeLessThanOrEqual(BENCHMARK_MAX_FALSE_ALARM_RATE);
  });
});

// Format only. Scores on the held-out sets are never asserted, so they stay an honest measure.
describe("benchmark held-out sets are well formed", () => {
  for (const [name, size] of [["heldout", 40], ["heldout2", 30]]) {
    it(`${name}: ${size / 2} scam and ${size / 2} benign, English only, reserved domains`, () => {
      const set = loadSet(name);
      expect(set).toHaveLength(size);
      expect(set.filter((m) => m.label === "scam")).toHaveLength(size / 2);
      expect(set.filter((m) => m.label === "benign")).toHaveLength(size / 2);
      expect(new Set(set.map((m) => m.id)).size).toBe(size);
      for (const m of set) {
        expect(BENGALI_SCRIPT.test(m.text)).toBe(false);
        expect(REAL_TLD.test(m.text), m.id).toBe(false);
        for (const [, host] of m.text.matchAll(URL_HOST)) {
          expect(RESERVED_OR_DOC_IP.test(host), `${m.id}: ${host}`).toBe(true);
        }
      }
    });
  }
  it("no message text or id is repeated across dev, heldout and heldout2", () => {
    const all = ["dev", "heldout", "heldout2"].flatMap((n) => loadSet(n));
    expect(new Set(all.map((m) => m.text)).size).toBe(all.length);
    expect(new Set(all.map((m) => m.id)).size).toBe(all.length);
  });
});

describe("benchmark heldout3 and heldout4", () => {
  it("heldout3 is a known set whose note says it was used for round 2 tuning", () => {
    expect(SETS).toContain("heldout3");
    expect(loadSet("heldout3")).toHaveLength(30);
    expect(setNote("heldout3")).toMatch(/used for rule tuning in round 2/);
  });
  it("heldout4 is reserved: a note and an empty messages array", () => {
    expect(SETS).toContain("heldout4");
    expect(loadSet("heldout4")).toEqual([]);
    expect(setNote("heldout4")).toMatch(/nobody .* has seen/);
  });
  it("the older sets are still bare arrays", () => {
    for (const name of ["dev", "heldout", "heldout2"]) expect(setNote(name)).toBeNull();
  });
});
