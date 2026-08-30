'use strict';
const test = require('node:test');
const assert = require('node:assert');

const { createOpenAICompatible, ProviderError, joinUrl } = require('../src/provider/openaiCompatible.js');
const { createProvider, createProviderRegistry } = require('../src/provider/index.js');

function okFetch(payload) {
  return async (url, options) => {
    options.capturedUrl = url;
    okFetch.lastOptions = options;
    return {
      ok: true,
      status: 200,
      json: async () => payload
    };
  };
}

test('joinUrl：容忍 baseUrl 尾部斜杠', () => {
  assert.equal(joinUrl('https://api.x.com/v1', '/chat/completions'), 'https://api.x.com/v1/chat/completions');
  assert.equal(joinUrl('https://api.x.com/v1///', '/chat/completions'), 'https://api.x.com/v1/chat/completions');
});

test('请求形状：URL / 鉴权头 / 请求体；响应解析 text 与 tokens', async () => {
  const fetchImpl = okFetch({ choices: [{ message: { content: '你好，攻心。' } }], usage: { total_tokens: 123 } });
  const provider = createOpenAICompatible({
    baseUrl: 'https://api.example.com/v1/',
    apiKey: 'sk-test',
    model: 'test-model',
    fetchImpl
  });
  const res = await provider.chat([{ role: 'user', content: 'hi' }], { temperature: 0.2, maxTokens: 50 });

  assert.equal(okFetch.lastOptions.capturedUrl, 'https://api.example.com/v1/chat/completions');
  assert.equal(okFetch.lastOptions.method, 'POST');
  assert.equal(okFetch.lastOptions.headers.authorization, 'Bearer sk-test');
  const body = JSON.parse(okFetch.lastOptions.body);
  assert.equal(body.model, 'test-model');
  assert.equal(body.temperature, 0.2);
  assert.equal(body.max_tokens, 50);
  assert.deepEqual(body.messages, [{ role: 'user', content: 'hi' }]);

  assert.equal(res.text, '你好，攻心。');
  assert.equal(res.tokens, 123);
});

test('默认参数：temperature / max_tokens', async () => {
  const fetchImpl = okFetch({ choices: [{ message: { content: 'ok' } }] });
  const provider = createOpenAICompatible({
    baseUrl: 'https://api.example.com', apiKey: 'k', model: 'm', fetchImpl
  });
  await provider.chat([], {});
  const body = JSON.parse(okFetch.lastOptions.body);
  assert.equal(body.temperature, 0.7);
  assert.equal(body.max_tokens, 1024);
});

test('非 200 状态：抛 ProviderError 且带状态码', async () => {
  const fetchImpl = async () => ({ ok: false, status: 401, text: async () => 'invalid api key' });
  const provider = createOpenAICompatible({ baseUrl: 'https://api.example.com', apiKey: 'bad', model: 'm', fetchImpl });
  await assert.rejects(
    () => provider.chat([], {}),
    (err) => err instanceof ProviderError && err.status === 401 && /invalid api key/.test(err.message)
  );
});

test('畸形响应：缺 choices 抛错', async () => {
  const fetchImpl = okFetch({ object: 'error' });
  const provider = createOpenAICompatible({ baseUrl: 'https://api.example.com', apiKey: 'k', model: 'm', fetchImpl });
  await assert.rejects(() => provider.chat([], {}), /choices\[0\]\.message\.content/);
});

test('配置缺失：快速失败并给出明确中文错误', () => {
  assert.throws(() => createOpenAICompatible({ apiKey: 'k', model: 'm' }), /baseUrl/);
  assert.throws(() => createOpenAICompatible({ baseUrl: 'https://x', model: 'm' }), /apiKey/);
  assert.throws(() => createOpenAICompatible({ baseUrl: 'https://x', apiKey: 'k' }), /model/);
});

test('工厂：openai-compatible 直通、未知 provider 抛错', () => {
  const p = createProvider({ baseUrl: 'https://api.example.com', apiKey: 'k', model: 'm', fetchImpl: okFetch({}) });
  assert.equal(p.provider, 'openai-compatible');
  assert.throws(() => createProvider({ provider: 'nope' }), /未知 provider/);
});

test('注册表：按模型缓存实例，关卡覆盖与默认模型各取所得', () => {
  const reg = createProviderRegistry({ baseUrl: 'https://api.example.com', apiKey: 'k', model: 'default-model' });
  const a = reg.get();
  const b = reg.get('other-model');
  assert.equal(a.model, 'default-model');
  assert.equal(b.model, 'other-model');
  assert.equal(reg.get(), a, '同一模型必须命中缓存');
  assert.equal(reg.get('other-model'), b);
  const empty = createProviderRegistry({ baseUrl: 'https://x', apiKey: 'k' });
  assert.throws(() => empty.get(), /缺少 model/);
});

test('429 自动重试：两次拥堵后第三次成功', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    if (calls <= 2) return { ok: false, status: 429, headers: { get: () => null }, text: async () => 'busy' };
    return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: 'ok' } }] }) };
  };
  const p = createOpenAICompatible({ baseUrl: 'https://api.example.com', apiKey: 'k', model: 'm', fetchImpl, retryBaseMs: 1 });
  const res = await p.chat([], {});
  assert.equal(res.text, 'ok');
  assert.equal(calls, 3);
});

test('超过 maxRetries 仍 429 → 抛错且不再重试', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return { ok: false, status: 429, headers: { get: () => null }, text: async () => 'busy' };
  };
  const p = createOpenAICompatible({ baseUrl: 'https://api.example.com', apiKey: 'k', model: 'm', fetchImpl, maxRetries: 1, retryBaseMs: 1 });
  await assert.rejects(() => p.chat([], {}), (err) => err instanceof ProviderError && err.status === 429);
  assert.equal(calls, 2); // 首发 + 1 次重试
});

test('401 鉴权失败不重试（fast-fail）', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return { ok: false, status: 401, text: async () => 'bad key' };
  };
  const p = createOpenAICompatible({ baseUrl: 'https://api.example.com', apiKey: 'k', model: 'm', fetchImpl, retryBaseMs: 1 });
  await assert.rejects(() => p.chat([], {}), (err) => err.status === 401);
  assert.equal(calls, 1);
});

test('Retry-After 头存在时不抛错（优先于退避基数）', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    if (calls === 1) return { ok: false, status: 429, headers: { get: () => '0.001' }, text: async () => 'busy' };
    return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: 'ok' } }] }) };
  };
  const p = createOpenAICompatible({ baseUrl: 'https://api.example.com', apiKey: 'k', model: 'm', fetchImpl, retryBaseMs: 1 });
  const res = await p.chat([], {});
  assert.equal(res.text, 'ok');
  assert.equal(calls, 2);
});
