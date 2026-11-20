// Tiny LRU cache with a per-entry TTL. `now` is injectable for tests.
export class LRUCache {
  /**
   * @param {{ max: number, ttlMs: number, now?: () => number }} opts
   */
  constructor({ max, ttlMs, now = Date.now }) {
    if (!Number.isInteger(max) || max < 1) throw new RangeError("max must be a positive integer");
    if (!(ttlMs > 0)) throw new RangeError("ttlMs must be positive");
    this.max = max;
    this.ttlMs = ttlMs;
    this.now = now;
    this.map = new Map();
  }

  get size() {
    return this.map.size;
  }

  has(key) {
    return this.get(key) !== undefined;
  }

  get(key) {
    const entry = this.map.get(key);
    if (entry === undefined) return undefined;
    if (this.now() >= entry.expiresAt) {
      this.map.delete(key);
      return undefined;
    }
    // Move to the most-recently-used position.
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.value;
  }

  /** @param {number} [ttlMs] optional shorter TTL for this entry (capped at the cache TTL) */
  set(key, value, ttlMs = this.ttlMs) {
    const ttl = Math.min(this.ttlMs, ttlMs > 0 ? ttlMs : this.ttlMs);
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, { value, expiresAt: this.now() + ttl });
    while (this.map.size > this.max) {
      this.map.delete(this.map.keys().next().value);
    }
  }

  clear() {
    this.map.clear();
  }
}
