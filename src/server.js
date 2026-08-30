'use strict';
/**
 * 攻心 InjectArena —— 服务端（Fastify）。
 *
 * 攻击面隔离原则：
 *  - 静态文件白名单三件套（index.html / app.js / style.css），无动态路径拼接；
 *  - /api/levels 只输出公开视图（publicLevel），systemPrompt 与 secret 永不出服务端；
 *  - 客户端消息白名单校验：只收 user/assistant 两种角色，system 一律拒收——
 *    系统提示词只能由服务端注入，客户端无法用消息伪造系统层；
 *  - 判定只用确定性 judge（src/judge.js），绝不让 LLM 当裁判；
 *  - 每 IP 令牌桶限流，先于一切 LLM 调用生效（成本防线）；
 *  - SQLite 审计日志记录每次攻防交互的元数据。
 */

const fs = require('node:fs');
const path = require('node:path');
const fastifyFactory = require('fastify');

const { judge } = require('./judge.js');
const { TokenBucketLimiter } = require('./rateLimiter.js');
const { loadLevels, publicLevel } = require('./levels.js');
const { openAuditDb, insertAudit } = require('./db.js');
const { createProvider } = require('./provider/index.js');
const { loadConfig, loadDotEnv } = require('./config.js');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const STATIC_FILES = {
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
  '/style.css': { file: 'style.css', type: 'text/css; charset=utf-8' }
};

const MAX_MESSAGES = 24;
const MAX_MESSAGE_CHARS = 4000;

/**
 * 校验客户端消息历史：只允许 user/assistant 角色、长度受限、以 user 收尾。
 * 返回净化后的数组，不合法返回 null。system 角色永远由服务端独占。
 */
function sanitizeClientMessages(messages) {
  if (!Array.isArray(messages)) return null;
  if (messages.length === 0 || messages.length > MAX_MESSAGES) return null;
  const out = [];
  for (const m of messages) {
    if (!m || typeof m !== 'object') return null;
    if (m.role !== 'user' && m.role !== 'assistant') return null;
    if (typeof m.content !== 'string' || m.content.length === 0 || m.content.length > MAX_MESSAGE_CHARS) return null;
    out.push({ role: m.role, content: m.content });
  }
  if (out[out.length - 1].role !== 'user') return null;
  return out;
}

/**
 * @param {object} config loadConfig() 的结果
 * @param {object} [deps] 依赖注入（测试用）：levels / provider / rateLimiter / db
 */
function buildServer(config, deps) {
  const d = deps || {};
  const app = fastifyFactory({ logger: d.logger || false });

  const levels = d.levels || loadLevels(path.join(__dirname, '..', 'levels'));
  const levelById = new Map(levels.map((l) => [l.id, l]));
  const limiter = d.rateLimiter || new TokenBucketLimiter(config.chatRate);
  const db = d.db || openAuditDb(config.dbPath);

  // BYOK：baseUrl/apiKey/model 任一缺失则不创建 provider，聊天接口降级为 503
  let provider = null;
  if (d.provider !== undefined) {
    provider = d.provider;
  } else if (config.baseUrl && config.apiKey && config.model) {
    provider = createProvider(config);
  }

  for (const [route, meta] of Object.entries(STATIC_FILES)) {
    app.get(route, async (_req, reply) => {
      reply.type(meta.type).send(fs.readFileSync(path.join(PUBLIC_DIR, meta.file)));
    });
  }

  app.get('/api/health', async () => ({
    ok: true,
    provider: provider ? provider.provider : null,
    model: provider ? provider.model : null
  }));

  app.get('/api/levels', async () => ({ levels: levels.map(publicLevel) }));

  app.post('/api/levels/:id/chat', async (req, reply) => {
    const level = levelById.get(req.params.id);
    if (!level) {
      reply.code(404);
      return { error: '未知关卡' };
    }

    const ip = req.ip || 'unknown';
    const rl = limiter.check('chat:' + ip);
    if (!rl.allowed) {
      reply.code(429).header('retry-after', String(rl.retryAfterSeconds));
      insertAudit(db, { ts: new Date().toISOString(), ip, route: 'chat', levelId: level.id, outcome: 'rate-limited' });
      return { error: '出招太密，' + rl.retryAfterSeconds + ' 秒后再来。' };
    }

    const messages = sanitizeClientMessages(req.body && req.body.messages);
    if (!messages) {
      reply.code(400);
      return { error: '消息格式不合法：messages 必须为 1-' + MAX_MESSAGES + ' 条 user/assistant 消息，且以 user 收尾。' };
    }

    if (!provider) {
      reply.code(503);
      return {
        error: '服务端未配置 LLM API key（BYOK）。请设置 INJECTARENA_BASE_URL / INJECTARENA_API_KEY / INJECTARENA_MODEL 后重启。'
      };
    }

    const payloadText = messages[messages.length - 1].content;

    // 关键词防护（guard，L3 机制共用的引擎能力）：命中即拦截，不产生 LLM 调用
    if (level.guard && level.guard.kind === 'keywordBlock') {
      const lowerPayload = payloadText.toLowerCase();
      const hit = level.guard.patterns.some((p) => lowerPayload.indexOf(p.toLowerCase()) !== -1);
      if (hit) {
        const verdict = judge(level, level.guard.message);
        insertAudit(db, {
          ts: new Date().toISOString(), ip, route: 'chat', levelId: level.id,
          payloadChars: payloadText.length, tokens: 0, passed: verdict.passed, outcome: 'guard-blocked'
        });
        return {
          reply: level.guard.message,
          judged: { passed: verdict.passed, criterion: verdict.criterion, guarded: true },
          tokens: 0
        };
      }
    }

    const full = [{ role: 'system', content: level.systemPrompt }].concat(messages);
    let res;
    try {
      res = await provider.chat(full, {});
    } catch (err) {
      reply.code(502);
      insertAudit(db, {
        ts: new Date().toISOString(), ip, route: 'chat', levelId: level.id,
        payloadChars: payloadText.length, outcome: 'provider-error', detail: String(err.message || err).slice(0, 300)
      });
      return { error: 'LLM 服务调用失败：' + (err.message || err) };
    }

    const verdict = judge(level, res.text);
    insertAudit(db, {
      ts: new Date().toISOString(), ip, route: 'chat', levelId: level.id,
      payloadChars: payloadText.length, tokens: res.tokens === undefined ? null : res.tokens,
      passed: verdict.passed, outcome: verdict.passed ? 'breached' : 'defended'
    });

    return {
      reply: res.text,
      // matched 命中的值就是 secret，绝不随响应外传
      judged: { passed: verdict.passed, criterion: verdict.criterion },
      tokens: res.tokens === undefined ? null : res.tokens
    };
  });

  app.setNotFoundHandler((_req, reply) => {
    reply.code(404);
    return { error: '未找到资源' };
  });

  return app;
}

function start() {
  loadDotEnv(path.join(__dirname, '..', '.env'));
  const config = loadConfig();
  const app = buildServer(config);
  app.listen({ port: config.port, host: config.host }, (err) => {
    if (err) throw err;
    process.stdout.write('攻心 InjectArena 已开阵：http://' + config.host + ':' + config.port + '\n');
    if (!config.apiKey) {
      process.stdout.write('提示：尚未配置 INJECTARENA_API_KEY，聊天接口将返回 503（BYOK 见 README）。\n');
    }
  });
}

if (require.main === module) start();

module.exports = { buildServer, sanitizeClientMessages };
