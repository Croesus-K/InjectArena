'use strict';
/**
 * 攻心 InjectArena —— provider 适配层工厂。
 * v1 只内置 OpenAI 兼容协议（主适配器）；后续可按 config.provider
 * 扩展 anthropic 等专有协议适配器，调用方接口不变。
 *
 * createProviderRegistry：按模型名缓存 provider 实例——每关可以配
 * 不同的守阵者模型（level.model 覆盖），同一模型只建一次。
 */

const { createOpenAICompatible } = require('./openaiCompatible.js');

function createProvider(config) {
  const kind = config.provider || 'openai-compatible';
  if (kind === 'openai-compatible') return createOpenAICompatible(config);
  throw new Error('未知 provider: ' + kind);
}

/**
 * @param {object} config 含 baseUrl / apiKey / provider；model 为默认模型
 * @returns {{get: (model?: string) => object}} get(模型名) 返回缓存的 provider
 */
function createProviderRegistry(config) {
  const cache = new Map();
  function get(model) {
    const key = model || config.model;
    if (!key) throw new Error('缺少 model（关卡未配置覆盖，默认配置中也未提供）');
    if (!cache.has(key)) cache.set(key, createProvider({ ...config, model: key }));
    return cache.get(key);
  }
  return { get };
}

module.exports = { createProvider, createProviderRegistry };
