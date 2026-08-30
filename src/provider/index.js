'use strict';
/**
 * 攻心 InjectArena —— provider 适配层工厂。
 * v1 只内置 OpenAI 兼容协议（主适配器）；后续可按 config.provider
 * 扩展 anthropic 等专有协议适配器，调用方接口不变。
 */

const { createOpenAICompatible } = require('./openaiCompatible.js');

function createProvider(config) {
  const kind = config.provider || 'openai-compatible';
  if (kind === 'openai-compatible') return createOpenAICompatible(config);
  throw new Error('未知 provider: ' + kind);
}

module.exports = { createProvider };
