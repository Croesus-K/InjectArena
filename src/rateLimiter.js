/**
 * 攻心 InjectArena —— 每 IP 令牌桶限流器（纯逻辑，UMD 双端）。
 *
 * 时钟通过 now() 注入，单测可以精确推进时间；桶按 key（通常是 IP）隔离。
 * 成本与滥用防线的第一层：LLM 调用是真实花钱的，限流必须在进入 LLM 之前生效。
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.InjectArenaRateLimiter = factory();
  }
})(typeof globalThis === 'object' ? globalThis : this, function () {
  'use strict';

  const MAX_KEYS = 10000; // 防内存膨胀：桶数量超限即清理长期未触发的 key

  class TokenBucketLimiter {
    /**
     * @param {object} options
     * @param {number} options.capacity         桶容量（瞬时突发上限）
     * @param {number} options.refillPerMinute  每分钟回填的令牌数
     * @param {Function} [options.now]          时钟注入，默认 Date.now
     */
    constructor(options) {
      const opts = options || {};
      this.capacity = opts.capacity > 0 ? opts.capacity : 10;
      this.refillPerMinute = opts.refillPerMinute > 0 ? opts.refillPerMinute : this.capacity;
      this.now = opts.now || function () { return Date.now(); };
      this.buckets = new Map(); // key -> {tokens, lastRefill, lastSeen}
    }

    check(key) {
      const t = this.now();
      let bucket = this.buckets.get(key);
      if (!bucket) {
        bucket = { tokens: this.capacity, lastRefill: t, lastSeen: t };
        this.buckets.set(key, bucket);
        if (this.buckets.size > MAX_KEYS) this._prune(t);
      } else {
        const elapsedMinutes = Math.max(0, t - bucket.lastRefill) / 60000;
        bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsedMinutes * this.refillPerMinute);
        bucket.lastRefill = t;
        bucket.lastSeen = t;
      }

      if (bucket.tokens >= 1) {
        bucket.tokens -= 1;
        return { allowed: true, remaining: Math.floor(bucket.tokens), retryAfterSeconds: 0 };
      }
      const deficit = 1 - bucket.tokens;
      const retryAfterSeconds = Math.max(1, Math.ceil((deficit / this.refillPerMinute) * 60));
      return { allowed: false, remaining: 0, retryAfterSeconds };
    }

    _prune(t) {
      for (const [key, bucket] of this.buckets) {
        if (t - bucket.lastSeen > 600000) this.buckets.delete(key); // 10 分钟未触发的桶
      }
    }
  }

  return { TokenBucketLimiter };
});
