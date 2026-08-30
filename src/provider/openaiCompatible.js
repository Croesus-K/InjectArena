'use strict';
/**
 * 攻心 InjectArena —— OpenAI 兼容协议适配器（BYOK 主适配器）。
 *
 * 覆盖 OpenAI / DeepSeek / 智谱 GLM / Kimi / Qwen 等一切兼容
 * POST {baseUrl}/chat/completions 的服务：自部署者填 baseUrl + key + model 即可换厂商。
 * key 只存在于服务端进程内存，绝不发往前端（BYOK 的安全底线）。
 *
 * 仅依赖注入的 fetchImpl（默认全局 fetch），单测用 mock 注入，不发真实网络请求。
 */

class ProviderError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ProviderError';
    this.status = status === undefined ? null : status;
  }
}

function joinUrl(base, pathSuffix) {
  return base.replace(/\/+$/, '') + pathSuffix;
}

/**
 * @param {object} config
 * @param {string} config.baseUrl   OpenAI 兼容服务根地址，如 https://api.deepseek.com/v1
 * @param {string} config.apiKey    BYOK：自部署者自己的 key
 * @param {string} config.model     模型名，如 deepseek-chat / glm-4-flash / gpt-4o-mini
 * @param {Function} [config.fetchImpl] 可注入的 fetch（默认 globalThis.fetch）
 * @param {number}  [config.timeoutMs]  请求超时毫秒数，默认 60000
 * @param {number}  [config.maxRetries] 429/5xx 自动重试次数，默认 2（免费共享池拥堵是常态）
 * @param {number}  [config.retryBaseMs] 重试退避基数毫秒，第 n 次重试等待 base*n（有 Retry-After 头则优先）
 */
function createOpenAICompatible(config) {
  const baseUrl = config.baseUrl;
  const apiKey = config.apiKey;
  const model = config.model;
  if (!baseUrl) throw new Error('缺少 baseUrl（OpenAI 兼容服务地址）');
  if (!apiKey) throw new Error('缺少 apiKey（BYOK：由自部署者提供）');
  if (!model) throw new Error('缺少 model（如 deepseek-chat / glm-4-flash / gpt-4o-mini）');

  const fetchImpl = config.fetchImpl || globalThis.fetch;
  const timeoutMs = config.timeoutMs || 60000;
  const maxRetries = config.maxRetries === undefined ? 2 : config.maxRetries;
  const retryBaseMs = config.retryBaseMs === undefined ? 800 : config.retryBaseMs;
  const defaultTemperature = typeof config.temperature === 'number' ? config.temperature : 0.7;
  const defaultMaxTokens = config.maxTokens || 1024;

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  function retryAfterMs(res, attempt) {
    let header = null;
    try {
      header = res.headers && typeof res.headers.get === 'function' ? res.headers.get('retry-after') : null;
    } catch (_) { /* mock 响应可能没有 headers */ }
    const seconds = header === null || header === undefined ? NaN : parseFloat(header);
    if (Number.isFinite(seconds) && seconds > 0) return seconds * 1000;
    return retryBaseMs * attempt;
  }

  /**
   * @param {Array<{role,content}>} messages
   * @param {{temperature?: number, maxTokens?: number}} [options]
   * @returns {Promise<{text: string, tokens?: number}>}
   */
  async function chat(messages, options) {
    const opts = options || {};
    const body = {
      model,
      messages,
      temperature: typeof opts.temperature === 'number' ? opts.temperature : defaultTemperature,
      max_tokens: opts.maxTokens || defaultMaxTokens
    };

    for (let attempt = 1; ; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let res;
      try {
        res = await fetchImpl(joinUrl(baseUrl, '/chat/completions'), {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: 'Bearer ' + apiKey
          },
          body: JSON.stringify(body),
          signal: controller.signal
        });
      } catch (err) {
        clearTimeout(timer);
        throw new ProviderError('LLM 服务请求失败: ' + ((err && err.message) || err), null);
      }
      clearTimeout(timer);

      // 免费共享池的 429 与上游 5xx 值得退避重试；鉴权类 4xx 不重试（fast-fail）
      const retryable = res.status === 429 || res.status >= 500;
      if (retryable && attempt <= maxRetries) {
        await sleep(retryAfterMs(res, attempt));
        continue;
      }

      if (!res.ok) {
        let detail = '';
        try {
          detail = (await res.text()).slice(0, 300);
        } catch (_) {
          /* 读取错误体失败不影响主错误 */
        }
        throw new ProviderError('LLM 服务返回错误状态 ' + res.status + (detail ? ': ' + detail : ''), res.status);
      }

      let data;
      try {
        data = await res.json();
      } catch (_) {
        throw new ProviderError('LLM 服务返回非 JSON 响应', res.status);
      }
      const choice = data && data.choices && data.choices[0];
      const text = choice && choice.message && typeof choice.message.content === 'string'
        ? choice.message.content
        : null;
      if (text === null) throw new ProviderError('LLM 服务响应缺少 choices[0].message.content', res.status);

      const tokens = data.usage && typeof data.usage.total_tokens === 'number' ? data.usage.total_tokens : undefined;
      return { text, tokens };
    }
  }

  return { chat, model, baseUrl, provider: 'openai-compatible' };
}

module.exports = { createOpenAICompatible, ProviderError, joinUrl };
