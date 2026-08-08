/*
 * Transcribed from quick-lru, limited to the surface oidc-provider uses:
 * get, set (with a per entry maxAge), delete, has, clear and size.
 *
 * Eviction is quick-lru's generational scheme rather than a linked list: writes
 * land in `recent`, and once it fills up it becomes `stale` and a fresh Map
 * takes over. Reading a key out of `stale` promotes it back into `recent`.
 * Nothing is evicted key by key, so the live entry count sits somewhere between
 * maxSize and 2x maxSize - which is quick-lru's behaviour, and what the memory
 * adapter has always been sized against.
 *
 * Per entry expiry is lazy, again as quick-lru does it: an expired entry is
 * dropped when it is next looked up, not on a timer.
 *
 * test/helpers/lru_parity.test.js holds this to quick-lru itself.
 */
export default class LRU {
  #maxSize;

  #recent = new Map();

  #stale = new Map();

  #size = 0;

  constructor({ maxSize }) {
    if (!(maxSize && maxSize > 0)) {
      throw new TypeError('`maxSize` must be a number greater than 0');
    }
    this.#maxSize = maxSize;
  }

  #expired(key, entry) {
    if (typeof entry.expiry === 'number' && entry.expiry <= Date.now()) {
      this.delete(key);
      return true;
    }
    return false;
  }

  #insert(key, entry) {
    this.#recent.set(key, entry);
    this.#size += 1;

    if (this.#size >= this.#maxSize) {
      this.#size = 0;
      this.#stale = this.#recent;
      this.#recent = new Map();
    }
  }

  get(key) {
    if (this.#recent.has(key)) {
      const entry = this.#recent.get(key);
      return this.#expired(key, entry) ? undefined : entry.value;
    }

    if (this.#stale.has(key)) {
      const entry = this.#stale.get(key);
      if (this.#expired(key, entry)) return undefined;
      this.#stale.delete(key);
      this.#insert(key, entry);
      return entry.value;
    }

    return undefined;
  }

  set(key, value, { maxAge } = {}) {
    const expiry = typeof maxAge === 'number' && maxAge !== Number.POSITIVE_INFINITY
      ? Date.now() + maxAge
      : undefined;

    if (this.#recent.has(key)) {
      this.#recent.set(key, { value, expiry });
    } else {
      this.#insert(key, { value, expiry });
    }

    return this;
  }

  has(key) {
    if (this.#recent.has(key)) return !this.#expired(key, this.#recent.get(key));
    if (this.#stale.has(key)) return !this.#expired(key, this.#stale.get(key));
    return false;
  }

  delete(key) {
    const deleted = this.#recent.delete(key);
    if (deleted) this.#size -= 1;
    return this.#stale.delete(key) || deleted;
  }

  clear() {
    this.#recent.clear();
    this.#stale.clear();
    this.#size = 0;
  }

  get size() {
    if (!this.#size) return this.#stale.size;

    let stale = 0;
    for (const key of this.#stale.keys()) {
      if (!this.#recent.has(key)) stale += 1;
    }

    return Math.min(this.#size + stale, this.#maxSize);
  }
}
