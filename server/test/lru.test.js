import { describe, expect, it } from "vitest";
import { LRUCache } from "../src/lib/lru.js";

describe("LRUCache", () => {
  it("stores and returns values", () => {
    const c = new LRUCache({ max: 2, ttlMs: 1000 });
    c.set("a", 1);
    expect(c.get("a")).toBe(1);
    expect(c.get("b")).toBeUndefined();
  });

  it("evicts the least recently used entry", () => {
    const c = new LRUCache({ max: 2, ttlMs: 1000 });
    c.set("a", 1);
    c.set("b", 2);
    c.get("a"); // a is now the most recent
    c.set("c", 3);
    expect(c.get("b")).toBeUndefined();
    expect(c.get("a")).toBe(1);
    expect(c.get("c")).toBe(3);
    expect(c.size).toBe(2);
  });

  it("expires entries after the TTL", () => {
    let t = 0;
    const c = new LRUCache({ max: 5, ttlMs: 100, now: () => t });
    c.set("a", 1);
    t = 99;
    expect(c.get("a")).toBe(1);
    t = 100;
    expect(c.get("a")).toBeUndefined();
    expect(c.size).toBe(0);
  });

  it("keeps falsy values", () => {
    const c = new LRUCache({ max: 5, ttlMs: 100 });
    c.set("f", false);
    expect(c.get("f")).toBe(false);
    expect(c.has("f")).toBe(true);
  });

  it("re-setting a key refreshes its TTL", () => {
    let t = 0;
    const c = new LRUCache({ max: 5, ttlMs: 100, now: () => t });
    c.set("a", 1);
    t = 50;
    c.set("a", 2);
    t = 120;
    expect(c.get("a")).toBe(2);
  });

  it("rejects bad options", () => {
    expect(() => new LRUCache({ max: 0, ttlMs: 1 })).toThrow(RangeError);
    expect(() => new LRUCache({ max: 1, ttlMs: 0 })).toThrow(RangeError);
  });
});
