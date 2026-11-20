import { describe, it, expect } from "vitest";
import { DEFAULT_BRANDS } from "../src/brands.js";

const RESERVED_TLD = /\.(example|test|invalid)$/;

describe("DEFAULT_BRANDS", () => {
  it("uses lowercase a-z0-9 names and reserved TLDs only", () => {
    expect(DEFAULT_BRANDS.length).toBe(5);
    for (const brand of DEFAULT_BRANDS) {
      expect(brand.name).toMatch(/^[a-z0-9]+$/);
      expect(brand.domains.length).toBeGreaterThan(0);
      for (const d of brand.domains) expect(d).toMatch(RESERVED_TLD);
    }
  });
});
