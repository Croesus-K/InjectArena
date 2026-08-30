'use strict';
const test = require('node:test');
const assert = require('node:assert');

const { TokenBucketLimiter } = require('../src/rateLimiter.js');

function makeFakeClock() {
  let now = 0;
  return { fn: () => now, advance: (ms) => { now += ms; } };
}

test('突发上限：容量耗尽后拒绝并给出 retryAfter', () => {
  const clock = makeFakeClock();
  const rl = new TokenBucketLimiter({ capacity: 2, refillPerMinute: 60, now: clock.fn });
  assert.equal(rl.check('1.2.3.4').allowed, true);
  assert.equal(rl.check('1.2.3.4').allowed, true);
  const denied = rl.check('1.2.3.4');
  assert.equal(denied.allowed, false);
  assert.equal(denied.retryAfterSeconds, 1); // 缺 1 个令牌，60/分钟 → 1 秒
});

test('时间推进回填令牌，回填封顶于容量', () => {
  const clock = makeFakeClock();
  const rl = new TokenBucketLimiter({ capacity: 2, refillPerMinute: 60, now: clock.fn });
  rl.check('ip'); rl.check('ip');
  assert.equal(rl.check('ip').allowed, false);
  clock.advance(1000); // 1 秒 → 回填 1 个
  assert.equal(rl.check('ip').allowed, true);
  clock.advance(60000); // 1 分钟 → 回填满 2 个
  assert.equal(rl.check('ip').allowed, true);
  assert.equal(rl.check('ip').allowed, true);
  assert.equal(rl.check('ip').allowed, false);
});

test('按 key 隔离：不同 IP 互不影响', () => {
  const clock = makeFakeClock();
  const rl = new TokenBucketLimiter({ capacity: 1, refillPerMinute: 1, now: clock.fn });
  assert.equal(rl.check('a').allowed, true);
  assert.equal(rl.check('a').allowed, false);
  assert.equal(rl.check('b').allowed, true);
});

test('retryAfter 随速率换算：12/分钟缺 1 令牌 → 5 秒', () => {
  const clock = makeFakeClock();
  const rl = new TokenBucketLimiter({ capacity: 1, refillPerMinute: 12, now: clock.fn });
  rl.check('ip');
  assert.equal(rl.check('ip').retryAfterSeconds, 5);
});
