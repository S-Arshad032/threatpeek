import { describe, it, expect } from "vitest";
import { loadSet, evaluate } from "../benchmark/lib.js";
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

  it("is well formed: 30 scam and 30 benign, English only, reserved domains", () => {
    expect(set).toHaveLength(60);
    expect(set.filter((m) => m.label === "scam")).toHaveLength(30);
    expect(set.filter((m) => m.label === "benign")).toHaveLength(30);
    expect(new Set(set.map((m) => m.id)).size).toBe(60);
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
