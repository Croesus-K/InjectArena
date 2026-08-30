'use strict';
/**
 * 攻心 InjectArena —— 运行配置。
 * 一切来自环境变量（BYOK：key 只进服务端内存）；支持可选的 .env 文件
 * （不自建存储，只读进进程环境，格式 KEY=VALUE，# 开头为注释）。
 */

const fs = require('node:fs');

/**
 * 读取 .env 到 process.env（已存在的环境变量优先，不被覆盖）。
 * 文件不存在时静默跳过——没配 .env 也能用真实环境变量启动。
 * 安全约束：只允许注入 INJECTARENA_ 前缀的键，.env 无法覆盖进程其他环境变量。
 */
function loadDotEnv(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (_) {
    return 0;
  }
  let count = 0;
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!m) continue;
    const key = m[1];
    if (!key.startsWith('INJECTARENA_')) continue;
    let value = m[2];
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
    if (!(key in process.env)) {
      process.env[key] = value;
      count += 1;
    }
  }
  return count;
}

/**
 * @param {object} [env] 环境变量源（默认 process.env，测试可注入）
 */
function loadConfig(env) {
  const e = env || process.env;
  return {
    host: e.INJECTARENA_HOST || '127.0.0.1',
    port: Number(e.INJECTARENA_PORT || 8787),
    dbPath: e.INJECTARENA_DB_PATH || 'data/audit.db',
    provider: e.INJECTARENA_PROVIDER || 'openai-compatible',
    baseUrl: e.INJECTARENA_BASE_URL || '',
    apiKey: e.INJECTARENA_API_KEY || '',
    model: e.INJECTARENA_MODEL || '',
    chatRate: {
      capacity: Number(e.INJECTARENA_CHAT_RATE_CAPACITY || 10),
      refillPerMinute: Number(e.INJECTARENA_CHAT_RATE_REFILL || 10)
    },
    // 守方评分一次评测 = 语料条数 × 真实 LLM 调用，成本高，默认限得更紧
    defenseRate: {
      capacity: Number(e.INJECTARENA_DEFENSE_RATE_CAPACITY || 2),
      refillPerMinute: Number(e.INJECTARENA_DEFENSE_RATE_REFILL || 2)
    }
  };
}

module.exports = { loadConfig, loadDotEnv };
