'use strict';
/**
 * 攻心 InjectArena —— 运行配置。
 * 一切来自环境变量（BYOK：key 只进服务端内存）；支持可选的 .env 文件
 * （不自建存储，只读进进程环境，格式 KEY=VALUE，# 开头为注释）。
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

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
 * 解析 env 文件路径：按顺序取第一个存在的文件（顺序即优先级）。
 * 1. INJECTARENA_ENV_FILE 显式指定——指定的文件不存在时打警告（显式配置静默消失最坑人）
 * 2. <projectRoot>/.env ——历史行为，向后兼容
 * 3. <home>/.injectarena/.env ——用户级：key 与项目目录解耦，项目文件夹拷走也不带 key
 * @param {object} [env] 环境变量源（默认 process.env，测试可注入）
 * @param {string} [projectRoot] 项目根（默认本模块上一级）
 * @param {string} [home] 用户主目录（默认 os.homedir()，测试可注入）
 * @returns {{file: string|null, source: 'explicit'|'project'|'user'|null}}
 */
function resolveEnvFile(env, projectRoot, home) {
  const e = env || process.env;
  const root = projectRoot || path.resolve(__dirname, '..');
  const userHome = home || os.homedir();
  const explicit = e.INJECTARENA_ENV_FILE;
  if (explicit) {
    if (fs.existsSync(explicit)) return { file: explicit, source: 'explicit' };
    process.stderr.write('[injectarena] INJECTARENA_ENV_FILE 指定的文件不存在，忽略: ' + explicit + '\n');
    return { file: null, source: null };
  }
  const candidates = [
    ['project', path.join(root, '.env')],
    ['user', path.join(userHome, '.injectarena', '.env')]
  ];
  for (const [source, file] of candidates) {
    if (fs.existsSync(file)) return { file, source };
  }
  return { file: null, source: null };
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
    },
    // 评测并发：同时打向 LLM 的 payload 数（免费池建议 1-4，过高易触发 429 风暴）
    evalConcurrency: Number(e.INJECTARENA_EVAL_CONCURRENCY || 4)
  };
}

module.exports = { loadConfig, loadDotEnv, resolveEnvFile };
