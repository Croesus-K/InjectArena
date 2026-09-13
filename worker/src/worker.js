'use strict';
/**
 * arena-worker —— InjectArena 站内部署后端（Cloudflare Workers + D1）。
 *
 * 与 src/server.js（Fastify/SQLite/部署者 Key）的架构差异：
 *   1. BYOK 反转：LLM Key 由玩家在浏览器「配置」填写，随请求头进入 Worker 后
 *      只透传给白名单供应商，不落盘、不进日志、响应即焚——站内零 Key、零成本；
 *   2. 身份锚定：GitHub OAuth（client_secret 在 Worker secret）签发 HMAC 会话
 *      Cookie；上榜凭证由破阵响应签发，/records 兑换时才落 D1——灌水上限=真实破阵；
 *   3. 约束不变：secret/systemPrompt 永不出服务端、judge 确定性裁判、
 *      消息白名单、每 IP 令牌桶限流、审计只存元数据。
 *
 * 子请求预算（免费版每请求 50）：守方评测上限 40 条（带误杀判定 32+8）且关闭
 * 适配器重试，LLM + 1 次审计 ≈ 41；闯关 ≤3 轮（toolLoop）× 重试 3 + 2 次 D1，安全。
 */

import judgeMod from '../../src/judge.js';
import limiterMod from '../../src/rateLimiter.js';
import agentMod from '../../src/agentRunner.js';
import defenseMod from '../../src/defenseEvaluator.js';
import retrieverMod from '../../src/retriever.js';
import providerMod from '../../src/provider/openaiCompatible.js';

import { LEVELS, CORPORA, LEVEL_BY_ID, publicLevel, VERSION } from './data.js';
import * as store from './d1store.js';
import {
  MAX_MESSAGES,
  BENIGN_PROBES,
  isSimilarToAny,
  sanitizeClientMessages,
  selectCorpus,
  redactFlagTokens,
  parsePlayerProvider,
  parseCookies
} from './util.js';
import { signToken, verifyToken } from './identity.js';

const { judge } = judgeMod;
const { TokenBucketLimiter } = limiterMod;
const { runAgentTurn } = agentMod;
const { evaluateDefense } = defenseMod;
const { buildRetrievalContext } = retrieverMod;
const { createOpenAICompatible } = providerMod;

const COOKIE_NAME = 'arena_session';
const SESSION_TTL_MS = 30 * 24 * 3600 * 1000;      // GitHub 会话 30 天
const CREDENTIAL_TTL_MS = 2 * 3600 * 1000;         // 上榜凭证 2 小时
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;         // OAuth state 10 分钟
const EXPORT_LIMIT_MAX = 500;

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer'
};

// 限流器按 isolate 复用（env 常量不变）；内存态不跨 isolate 共享，尽力而为
let limitersCache = null;
function limiters(env) {
  if (!limitersCache) {
    limitersCache = {
      chat: new TokenBucketLimiter({
        capacity: Number(env.CHAT_RATE_CAPACITY) || 10,
        refillPerMinute: Number(env.CHAT_RATE_REFILL) || 10
      }),
      defense: new TokenBucketLimiter({
        capacity: Number(env.DEFENSE_RATE_CAPACITY) || 2,
        refillPerMinute: Number(env.DEFENSE_RATE_REFILL) || 2
      }),
      export: new TokenBucketLimiter({ capacity: 5, refillPerMinute: 5 }),
      records: new TokenBucketLimiter({ capacity: 6, refillPerMinute: 6 })
    };
  }
  return limitersCache;
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

function jsonResponse(obj, status, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...SECURITY_HEADERS,
      ...(extraHeaders || {})
    }
  });
}

/** 本地联调（wrangler dev）跨域开关；生产同源，此分支不生效。 */
function corsHeaders(request, env) {
  if (env.DEV_ALLOW_CORS !== '1') return {};
  const origin = request.headers.get('origin');
  if (!origin) return {};
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-headers': 'content-type, x-arena-key, x-arena-base-url, x-arena-model',
    'access-control-allow-methods': 'GET, POST, OPTIONS'
  };
}

async function safeJson(request) {
  try {
    return await request.json();
  } catch (_) {
    return null;
  }
}

/** 读会话（Cookie）。无 Cookie / 签名不符 / 过期 → null。 */
async function readSession(request, env) {
  if (!env.ARENA_SESSION_SECRET) return null;
  const cookies = parseCookies(request.headers.get('cookie'));
  const payload = await verifyToken(env.ARENA_SESSION_SECRET, cookies[COOKIE_NAME]);
  if (!payload || payload.kind !== 'session' || !payload.login) return null;
  return { login: payload.login, avatar: payload.avatar || null };
}

function sessionCookie(value, maxAge) {
  return COOKIE_NAME + '=' + value + '; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=' + maxAge;
}

/** 玩家供应商配置（请求头 → 白名单校验 → 可复用的 openaiCompatible 实例）。 */
function playerProvider(request, env) {
  const hosts = String(env.PROVIDER_HOSTS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const parsed = parsePlayerProvider(request.headers, hosts);
  if (!parsed.ok) return parsed;
  // 评测外通道保留重试（免费池 429 常见）；守方评测路径的实例由调用方关闭重试
  return {
    ok: true,
    provider: createOpenAICompatible({
      baseUrl: parsed.provider.baseUrl,
      apiKey: parsed.provider.apiKey,
      model: parsed.provider.model,
      fetchImpl: fetch,
      timeoutMs: 45000,
      maxRetries: 2
    })
  };
}

/** 评测专用：关闭重试，为免费版 50 子请求上限留足余量。 */
function evalProvider(request, env) {
  const hosts = String(env.PROVIDER_HOSTS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const parsed = parsePlayerProvider(request.headers, hosts);
  if (!parsed.ok) return parsed;
  return {
    ok: true,
    provider: createOpenAICompatible({
      baseUrl: parsed.provider.baseUrl,
      apiKey: parsed.provider.apiKey,
      model: parsed.provider.model,
      fetchImpl: fetch,
      timeoutMs: 45000,
      maxRetries: 0
    })
  };
}

// ---------------------------------------------------------------------------
// 数据端点
// ---------------------------------------------------------------------------

async function getLevels(env) {
  return jsonResponse({
    levels: LEVELS.map((l) => ({ ...publicLevel(l) }))
  });
}

async function getLeaderboard(request, env) {
  const url = new URL(request.url);
  if (url.searchParams.get('format') === 'export') {
    const ip = clientIp(request);
    const rl = limiters(env).export.check('export:' + ip);
    if (!rl.allowed) {
      await store.insertAudit(env.DB, { ts: new Date().toISOString(), ip, route: 'leaderboard-export', outcome: 'rate-limited' });
      return jsonResponse({ error: '导出太密，' + rl.retryAfterSeconds + ' 秒后再来（每周回流管道只需一次）。' }, 429, { 'retry-after': String(rl.retryAfterSeconds) });
    }
    const limitRaw = Number(url.searchParams.get('limit'));
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(Math.floor(limitRaw), EXPORT_LIMIT_MAX) : EXPORT_LIMIT_MAX;
    const unclaimed = await store.listUnclaimedBreaches(env.DB, limit);
    return jsonResponse({
      format: 'injectarena-export@2',
      exportedAt: new Date().toISOString(),
      redacted: true,
      // 旧 breach_records 通道已弃用：breaches 恒空（字段保留，飞轮 @1/@2 兼容）
      breaches: [],
      // 全部破阵语料（含未上榜）走 unclaimedBreaches：匿名、边缘统一打码
      unclaimedBreaches: unclaimed.map((r) => ({
        ...r,
        attackSurface: (LEVEL_BY_ID.get(r.levelId) || {}).attackSurface || null,
        payloadText: redactFlagTokens(r.payloadText)
      })),
      defense: []
    });
  }
  return jsonResponse({
    // 攻防榜：按总计份数排序前五十，仅 GitHub 登录者——破阵/考段完成即自动计入
    ranking: await store.listRanking(env.DB, 50)
  });
}

// ---------------------------------------------------------------------------
// 留言板（v0.6.0）：破阵/考段凭证即可留名留言；时间序；积分换位
// ---------------------------------------------------------------------------

function boardEntryRow(row, rankByLogin) {
  const rank = rankByLogin.get(row.login);
  return {
    id: row.id,
    displayName: row.displayName,
    message: row.message,
    position: row.position,
    ts: row.ts,
    // 用户若在攻防榜前五十，名号前显示榜排
    rank: rank ? rank.rank : null
  };
}

async function getBoard(request, env) {
  const rows = await store.listBoard(env.DB);
  const ranking = await store.listRanking(env.DB, 50);
  const rankByLogin = new Map();
  ranking.forEach((r, i) => { if (!rankByLogin.has(r.login)) rankByLogin.set(r.login, { rank: i + 1 }); });
  return jsonResponse({ entries: rows.map((r) => boardEntryRow(r, rankByLogin)) });
}

/** 留言：需 GitHub 登录 + 2h 内破阵/考段凭证（防未破阵灌水）。一人一条，重复提交即更新内容。 */
async function postBoard(request, env) {
  const session = await readSession(request, env);
  if (!session) return jsonResponse({ error: '留言需要先登录 GitHub 账号。' }, 401);

  const body = await safeJson(request);
  const message = typeof body?.message === 'string' ? body.message.trim().slice(0, 60) : '';
  if (!message) return jsonResponse({ error: '留言不能为空（≤60 字）。' }, 400);

  const credential = typeof body?.credential === 'string' ? body.credential : '';
  const claims = await verifyToken(env.ARENA_SESSION_SECRET, credential).catch(() => null);
  if (!claims || (claims.kind !== 'breach' && claims.kind !== 'defense')) {
    return jsonResponse({ error: '留言需要有效的破阵/考段凭证（2 小时内）。' }, 403);
  }

  const outcome = await store.upsertBoardMessage(env.DB, {
    githubLogin: session.login,
    displayName: session.login,
    message,
    ts: new Date().toISOString()
  });
  return jsonResponse({ outcome, login: session.login });
}

/** 换位：与目标留言互换序列号，扣 |Δ| 积分（等级不变）。需 GitHub 登录。 */
async function postBoardSwap(request, env) {
  const session = await readSession(request, env);
  if (!session) return jsonResponse({ error: '换位需要先登录 GitHub 账号。' }, 401);
  const body = await safeJson(request);
  const targetId = Number(body?.targetId);
  if (!Number.isInteger(targetId)) return jsonResponse({ error: '目标留言 ID 不合法。' }, 400);
  const result = await store.swapBoardPosition(env.DB, session.login, targetId);
  if (result.error) return jsonResponse({ error: result.error }, 400);
  return jsonResponse(result);
}

// ---------------------------------------------------------------------------
// 攻方：闯关（玩家 Key 中转 + 确定性判定 + 破阵凭证）
// ---------------------------------------------------------------------------

async function postChat(request, env, ctx, levelId) {
  const level = LEVEL_BY_ID.get(levelId);
  if (!level) return jsonResponse({ error: '未知关卡' }, 404);

  const ip = clientIp(request);
  const session = await readSession(request, env);
  const rl = limiters(env).chat.check('chat:' + ip);
  if (!rl.allowed) {
    await store.insertAudit(env.DB, { ts: new Date().toISOString(), ip, route: 'chat', levelId: level.id, outcome: 'rate-limited', githubLogin: session ? session.login : null });
    return jsonResponse({ error: '出招太密，' + rl.retryAfterSeconds + ' 秒后再来。' }, 429, { 'retry-after': String(rl.retryAfterSeconds) });
  }

  const body = await safeJson(request);
  const messages = sanitizeClientMessages(body && body.messages);
  if (!messages) {
    return jsonResponse({ error: '消息格式不合法：messages 必须为 1-' + MAX_MESSAGES + ' 条 user/assistant 消息，且以 user 收尾。' }, 400);
  }

  const parsedProvider = playerProvider(request, env);
  if (!parsedProvider.ok) return jsonResponse({ error: parsedProvider.error }, 400);
  const llm = parsedProvider.provider;

  const payloadText = messages[messages.length - 1].content;
  const auditBase = { ts: new Date().toISOString(), ip, levelId: level.id, githubLogin: session ? session.login : null };

  // RAG（L4 类关卡）：检索命中的文书拼进系统上下文——间接注入的攻击面所在
  const rag = buildRetrievalContext(level, payloadText);

  // 关键词防护（guard）：命中即拦截，不产生 LLM 调用
  if (level.guard && level.guard.kind === 'keywordBlock') {
    const lowerPayload = payloadText.toLowerCase();
    const hit = level.guard.patterns.some((p) => lowerPayload.indexOf(p.toLowerCase()) !== -1);
    if (hit) {
      const verdict = judge(level, level.guard.message);
      await store.insertAudit(env.DB, { ...auditBase, route: 'chat', payloadChars: payloadText.length, tokens: 0, passed: verdict.passed, outcome: 'guard-blocked' });
      return jsonResponse({
        reply: level.guard.message,
        judged: { passed: verdict.passed, criterion: verdict.criterion, guarded: true },
        tokens: 0,
        retrieved: rag.retrieved,
        toolTrace: [],
        credential: null
      });
    }
  }

  const full = [{ role: 'system', content: level.systemPrompt + rag.context }].concat(messages);

  let agentResult;
  try {
    if (Array.isArray(level.tools) && level.tools.length > 0) {
      // L5/L6 类关卡：代理持有工具，判定扩展到工具调用参数
      agentResult = await runAgentTurn({
        level,
        llm,
        judge,
        history: messages,
        executeTool: (name, args) => {
          // 模拟工具执行：只落审计账、不真外发；ctx.waitUntil 异步落账
          ctx.waitUntil(store.insertAudit(env.DB, {
            ts: new Date().toISOString(), ip, route: 'tool', levelId: level.id,
            payloadChars: JSON.stringify(args || {}).length, outcome: 'tool-call',
            detail: name, githubLogin: session ? session.login : null
          }));
          const def = (Array.isArray(level.tools) ? level.tools : []).find((t) => t.name === name);
          return { record: { sent: true }, result: (def && def.result) || '已执行。' };
        }
      });
    } else {
      const res = await llm.chat(full, {});
      agentResult = { reply: res.text, toolTrace: [], verdict: judge(level, res.text), tokens: res.tokens };
    }
  } catch (err) {
    await store.insertAudit(env.DB, { ...auditBase, route: 'chat', payloadChars: payloadText.length, outcome: 'provider-error', detail: String((err && err.message) || err).slice(0, 300) });
    return jsonResponse({ error: 'LLM 服务调用失败：' + ((err && err.message) || err) }, 502);
  }

  const verdict = agentResult.verdict;

  // 破阵即录（与上榜解耦）：payload 落 breach_unclaimed（匿名、幂等），语料回流专属。
  // 不阻塞响应；上榜与否、凭证兑换与否都不影响这条记录——收录规则：不上榜破阵也收。
  if (verdict.passed) {
    ctx.waitUntil(
      store.insertUnclaimedBreach(env.DB, {
        levelId: level.id,
        payloadText,
        chars: payloadText.length,
        tokens: agentResult.tokens === undefined ? null : agentResult.tokens,
        ts: new Date().toISOString()
      }).catch(() => { /* 落库失败不影响玩家；审计里仍有元数据 */ })
    );
  }

  // 份数榜计分（v0.6.0）：仅 GitHub 登录者；破阵即自动登记语料并 +1 份 +1 分，
  // 同关内相似度 ≥0.8 视为同一份（不重复升级）。游客只进匿名回流，不计份数。
  if (verdict.passed && session) {
    ctx.waitUntil(
      (async () => {
        const outcome = await store.insertBreachCorpus(env.DB, {
          githubLogin: session.login,
          levelId: level.id,
          payloadText,
          chars: payloadText.length,
          ts: new Date().toISOString()
        }, isSimilarToAny);
        if (outcome === 'written') {
          await store.addPlayerStats(env.DB, session.login, { breachDelta: 1, scoreDelta: 1 });
        }
      })().catch(() => { /* 计分失败不影响玩家 */ })
    );
  }

  // 破阵不直接落榜：签发凭证，玩家在 /records 兑换（自填名号/留言/是否挂身份）。
  // matched 命中值就是 secret，凭证里只放判定结果与元数据，绝不放 secret。
  let credential = null;
  if (verdict.passed && env.ARENA_SESSION_SECRET) {
    const token = await signToken(
      env.ARENA_SESSION_SECRET,
      { kind: 'breach', levelId: level.id, chars: payloadText.length, tokens: agentResult.tokens === undefined ? null : agentResult.tokens, payloadText },
      CREDENTIAL_TTL_MS
    );
    credential = { kind: 'breach', token, chars: payloadText.length, tokens: agentResult.tokens === undefined ? null : agentResult.tokens };
  }

  await store.insertAudit(env.DB, {
    ...auditBase,
    route: 'chat',
    payloadChars: payloadText.length,
    tokens: agentResult.tokens === undefined ? null : agentResult.tokens,
    passed: verdict.passed,
    outcome: verdict.passed ? 'breached' : 'defended'
  });

  return jsonResponse({
    reply: agentResult.reply,
    judged: { passed: verdict.passed, criterion: verdict.criterion },
    tokens: agentResult.tokens === undefined ? null : agentResult.tokens,
    retrieved: rag.retrieved,
    toolTrace: agentResult.toolTrace,
    credential
  });
}

// ---------------------------------------------------------------------------
// 守方：布防跑分（玩家 Key 中转 + 条数硬顶 + 破阵凭证）
// ---------------------------------------------------------------------------

function parseDefenseRequest(body) {
  const defensePrompt = typeof body.defensePrompt === 'string' ? body.defensePrompt.trim() : '';
  if (defensePrompt.length < 10 || defensePrompt.length > 4000) return null;
  const rejectMarker = typeof body.rejectMarker === 'string' && body.rejectMarker.trim()
    ? body.rejectMarker.trim().slice(0, 100)
    : null;
  let limit = Number(body.limit);
  if (!Number.isInteger(limit) || limit < 1) limit = null;
  return { defensePrompt, rejectMarker, limit };
}

function defenseOptions(env, level, llm, defensePrompt, rejectMarker, payloads) {
  return {
    level,
    defensePrompt,
    payloads,
    benign: rejectMarker ? BENIGN_PROBES : null,
    rejectMarker: rejectMarker || undefined,
    llm,
    judge,
    concurrency: Number(env.EVAL_CONCURRENCY) || 4,
    // RAG 类关卡：跑分时同样注入检索上下文（闯关与跑分同一形状）
    contextFor: (lv, text) => buildRetrievalContext(lv, text).context,
    // 工具类关卡：跑分时同样允许工具调用（判定含工具参数）
    toolsFor: (lv) => (Array.isArray(lv.tools) && lv.tools.length > 0 ? lv.tools : null),
    executeTool: (name, args) => {
      const def = (Array.isArray(level.tools) ? level.tools : []).find((t) => t.name === name);
      return { record: { sent: true }, result: (def && def.result) || '已执行。' };
    }
  };
}

/** 收尾：审计 + 凭证签发 + 响应行组装（JSON 与流式两种出口共用）。 */
async function finalizeDefense(env, ip, session, level, defensePrompt, rejectMarker, report) {
  let tokens = 0;
  const errorCount = report.results.filter((r) => r.error).length;
  const firstError = (report.results.find((r) => r.error) || {}).error || '';
  const results = report.results.map((r) => {
    if (typeof r.tokens === 'number') tokens += r.tokens;
    return {
      kind: r.kind,
      id: r.id,
      text: r.text,
      passed: r.passed,
      output: r.output,
      toolCalls: r.toolCalls,
      fp: r.kind === 'benign' && rejectMarker && r.error === null && r.output.indexOf(rejectMarker) !== -1,
      error: r.error
    };
  });

  await store.insertAudit(env.DB, {
    ts: new Date().toISOString(), ip, route: 'defense', levelId: level.id,
    payloadChars: defensePrompt.length, tokens: tokens || null,
    outcome: 'defense-eval', githubLogin: session ? session.login : null,
    detail: JSON.stringify({
      total: report.attack.total, evaluated: report.attack.evaluated,
      blocked: report.attack.blocked, leaked: report.attack.leaked,
      errors: errorCount,
      falsePositives: report.benign ? report.benign.falsePositives : null
    })
  });

  let credential = null;
  if (report.attack.evaluated > 0 && env.ARENA_SESSION_SECRET) {
    const token = await signToken(
      env.ARENA_SESSION_SECRET,
      {
        kind: 'defense', levelId: level.id,
        blockRate: report.attack.blockRate, leakRate: report.attack.leakRate,
        fpRate: report.benign ? report.benign.falsePositiveRate : null,
        evaluated: report.attack.evaluated
      },
      CREDENTIAL_TTL_MS
    );
    credential = { kind: 'defense', token, blockRate: report.attack.blockRate };
  }

  // 份数榜计分（v0.6.0）：登录者考段完成即自动登记布防语料并 +1 份 +1 分；
  // 同关内布防相似度 ≥0.8 视为同一份。同步执行：评测子请求预算 41+4 < 50 上限。
  if (report.attack.evaluated > 0 && session) {
    try {
      const outcome = await store.insertDefenseCorpus(env.DB, {
        githubLogin: session.login,
        levelId: level.id,
        defensePrompt,
        ts: new Date().toISOString()
      }, isSimilarToAny);
      if (outcome === 'written') {
        await store.addPlayerStats(env.DB, session.login, { defenseDelta: 1, scoreDelta: 1 });
      }
    } catch (_) { /* 计分失败不影响评测报告 */ }
  }

  return { attack: { ...report.attack, errors: errorCount }, benign: report.benign, results, errorCount, firstError, credential };
}

async function postDefense(request, env, ctx, levelId, stream) {
  const level = LEVEL_BY_ID.get(levelId);
  if (!level) return jsonResponse({ error: '未知关卡' }, 404);

  const ip = clientIp(request);
  const session = await readSession(request, env);
  const rl = limiters(env).defense.check('defense:' + ip);
  if (!rl.allowed) {
    await store.insertAudit(env.DB, { ts: new Date().toISOString(), ip, route: 'defense', levelId: level.id, outcome: 'rate-limited', githubLogin: session ? session.login : null });
    return jsonResponse({ error: '考段太密，' + rl.retryAfterSeconds + ' 秒后再来（每次评测是语料数 × 真实 LLM 调用）。' }, 429, { 'retry-after': String(rl.retryAfterSeconds) });
  }

  const parsed = parseDefenseRequest(await safeJson(request));
  if (!parsed) return jsonResponse({ error: '布防内容需 10-4000 字。' }, 400);

  const parsedProvider = evalProvider(request, env);
  if (!parsedProvider.ok) return jsonResponse({ error: parsedProvider.error }, 400);

  // 子请求硬顶：免费版 Workers 每请求 ≤50 个子请求（LLM + D1 都计入）。
  // 适配器已关闭重试；带误杀判定时 8 条良性探针固定计入 → 攻击语料压到 32。
  const cap = parsed.rejectMarker
    ? Number(env.EVAL_CAP_MARKER) || 32
    : Number(env.EVAL_CAP_PLAIN) || 40;
  const corpus = selectCorpus(level, CORPORA);
  let payloads = corpus.payloads;
  payloads = payloads.slice(0, Math.min(parsed.limit || cap, cap, payloads.length));

  if (!stream) {
    let report;
    try {
      report = await evaluateDefense(defenseOptions(env, level, parsedProvider.provider, parsed.defensePrompt, parsed.rejectMarker, payloads));
    } catch (err) {
      await store.insertAudit(env.DB, { ts: new Date().toISOString(), ip, route: 'defense', levelId: level.id, outcome: 'eval-error', detail: String((err && err.message) || err).slice(0, 300), githubLogin: session ? session.login : null });
      return jsonResponse({ error: '评测失败：' + ((err && err.message) || err) }, 500);
    }
    const out = await finalizeDefense(env, ip, session, level, parsed.defensePrompt, parsed.rejectMarker, report);
    if (out.attack.evaluated === 0 && out.errorCount > 0) {
      return jsonResponse({ error: '评测失败：所有 payload 的 LLM 调用均失败（请检查 API Key 与额度）。首个错误：' + out.firstError }, 502);
    }
    return jsonResponse({ attack: out.attack, benign: out.benign, results: out.results, credential: out.credential });
  }

  // 流式考段：NDJSON——每行一个 {type:"start"|"progress"|"report"|"error"} 事件
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  const writeLine = (obj) => writer.write(encoder.encode(JSON.stringify(obj) + '\n')).catch(() => {});

  ctx.waitUntil((async () => {
    try {
      const totalCalls = payloads.length + (parsed.rejectMarker ? BENIGN_PROBES.length : 0);
      await writeLine({ type: 'start', total: totalCalls, benign: parsed.rejectMarker ? BENIGN_PROBES.length : 0, concurrency: Number(env.EVAL_CONCURRENCY) || 4, capped: payloads.length < corpus.payloads.length });
      let done = 0;
      let report;
      try {
        report = await evaluateDefense({
          ...defenseOptions(env, level, parsedProvider.provider, parsed.defensePrompt, parsed.rejectMarker, payloads),
          onResult: (r) => {
            done += 1;
            writeLine({ type: 'progress', done, id: r.id, kind: r.kind, leaked: r.passed === true, error: Boolean(r.error) });
          }
        });
      } catch (err) {
        await store.insertAudit(env.DB, { ts: new Date().toISOString(), ip, route: 'defense', levelId: level.id, outcome: 'eval-error', detail: String((err && err.message) || err).slice(0, 300), githubLogin: session ? session.login : null });
        await writeLine({ type: 'error', message: '评测失败：' + ((err && err.message) || err) });
        return;
      }
      const out = await finalizeDefense(env, ip, session, level, parsed.defensePrompt, parsed.rejectMarker, report);
      if (out.attack.evaluated === 0 && out.errorCount > 0) {
        await writeLine({ type: 'error', message: '评测失败：所有 payload 的 LLM 调用均失败（请检查 API Key 与额度）。首个错误：' + out.firstError });
        return;
      }
      await writeLine({ type: 'report', attack: out.attack, benign: out.benign, results: out.results, credential: out.credential });
    } finally {
      try { await writer.close(); } catch (_) { /* 客户端断开 */ }
    }
  })());

  return new Response(readable, {
    headers: { 'content-type': 'application/x-ndjson; charset=utf-8', 'cache-control': 'no-cache', ...SECURITY_HEADERS }
  });
}

// ---------------------------------------------------------------------------
// GitHub OAuth（client_secret 在 Worker secret，签发 HMAC 会话 Cookie）
// ---------------------------------------------------------------------------

function requireOAuthConfig(env) {
  if (!env.ARENA_GITHUB_CLIENT_ID || !env.ARENA_GITHUB_CLIENT_SECRET) {
    return '站长尚未配置 GitHub OAuth（ARENA_GITHUB_CLIENT_ID / ARENA_GITHUB_CLIENT_SECRET）。';
  }
  if (!env.ARENA_SESSION_SECRET) return '站长尚未配置 ARENA_SESSION_SECRET。';
  return null;
}

function originOf(request) {
  return new URL(request.url).origin;
}

async function oauthLogin(request, env) {
  const missing = requireOAuthConfig(env);
  if (missing) return jsonResponse({ error: missing }, 503);
  const redirectUri = env.ARENA_OAUTH_REDIRECT_URI || (originOf(request) + '/api/arena/auth/callback');
  const state = await signToken(env.ARENA_SESSION_SECRET, { kind: 'oauth' }, OAUTH_STATE_TTL_MS);
  const authorize = new URL('https://github.com/login/oauth/authorize');
  authorize.searchParams.set('client_id', env.ARENA_GITHUB_CLIENT_ID);
  authorize.searchParams.set('redirect_uri', redirectUri);
  authorize.searchParams.set('scope', '');
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('allow_signup', 'true');
  return Response.redirect(authorize.toString(), 302);
}

async function oauthCallback(request, env) {
  const missing = requireOAuthConfig(env);
  const origin = originOf(request);
  const front = env.ARENA_LOGIN_FRONT || (origin + '/arena/');
  if (missing) return Response.redirect(front + '?login=error', 302);

  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const statePayload = state ? await verifyToken(env.ARENA_SESSION_SECRET, state) : null;
  if (!code || !statePayload || statePayload.kind !== 'oauth') {
    return Response.redirect(front + '?login=error', 302);
  }

  const redirectUri = env.ARENA_OAUTH_REDIRECT_URI || (origin + '/api/arena/auth/callback');
  let accessToken = null;
  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ client_id: env.ARENA_GITHUB_CLIENT_ID, client_secret: env.ARENA_GITHUB_CLIENT_SECRET, code, redirect_uri: redirectUri })
    });
    const data = await tokenRes.json();
    accessToken = data && data.access_token;
  } catch (_) {
    accessToken = null;
  }
  if (!accessToken) return Response.redirect(front + '?login=error', 302);

  let login = null;
  let avatar = null;
  try {
    const userRes = await fetch('https://api.github.com/user', {
      headers: { authorization: 'Bearer ' + accessToken, 'user-agent': 'injectarena-worker', accept: 'application/vnd.github+json' }
    });
    const user = await userRes.json();
    if (user && typeof user.login === 'string') {
      login = user.login;
      avatar = typeof user.avatar_url === 'string' ? user.avatar_url : null;
    }
  } catch (_) {
    login = null;
  }
  if (!login) return Response.redirect(front + '?login=error', 302);

  const sessionToken = await signToken(env.ARENA_SESSION_SECRET, { kind: 'session', login, avatar }, SESSION_TTL_MS);
  await store.insertAudit(env.DB, {
    ts: new Date().toISOString(), ip: clientIp(request), route: 'oauth',
    outcome: 'login', githubLogin: login
  });
  return new Response(null, {
    status: 302,
    headers: { location: front + '?login=ok', 'set-cookie': sessionCookie(sessionToken, Math.floor(SESSION_TTL_MS / 1000)), ...SECURITY_HEADERS }
  });
}

async function authMe(request, env) {
  const session = await readSession(request, env);
  const stats = session ? await store.getPlayerStats(env.DB, session.login) : null;
  return jsonResponse({
    login: session ? session.login : null,
    avatarUrl: session ? session.avatar : null,
    // 等级设定已取消：返回攻/防份数与可消费积分（换位扣）
    stats: stats ? { breachCount: stats.breachCount, defenseCount: stats.defenseCount, score: stats.score } : null
  });
}

async function authLogout(env) {
  const headers = { 'set-cookie': sessionCookie('', 0), ...SECURITY_HEADERS };
  return jsonResponse({ ok: true }, 200, headers);
}

// ---------------------------------------------------------------------------
// 入口路由
// ---------------------------------------------------------------------------

async function route(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path !== '/api/arena' && !path.startsWith('/api/arena/')) {
    return jsonResponse({ error: '未找到资源' }, 404);
  }
  const sub = path.slice('/api/arena'.length) || '/';

  if (request.method === 'GET' && sub === '/health') {
    return jsonResponse({ ok: true, version: VERSION, levels: LEVELS.length, byok: true });
  }
  if (request.method === 'GET' && sub === '/levels') return await getLevels(env);
  if (request.method === 'GET' && sub === '/leaderboard') return await getLeaderboard(request, env);
  if (request.method === 'POST' && sub === '/records') return await postRecords(request, env);

  if (request.method === 'GET' && sub === '/board') return await getBoard(request, env);
  if (request.method === 'POST' && sub === '/board') return await postBoard(request, env);
  if (request.method === 'POST' && sub === '/board/swap') return await postBoardSwap(request, env);

  if (request.method === 'GET' && sub === '/auth/login') return await oauthLogin(request, env);
  if (request.method === 'GET' && sub === '/auth/callback') return await oauthCallback(request, env);
  if (request.method === 'GET' && sub === '/auth/me') return await authMe(request, env);
  if (request.method === 'POST' && sub === '/auth/logout') return await authLogout(env);

      const chatMatch = sub.match(/^\/levels\/([^/]+)\/chat$/);
      if (request.method === 'POST' && chatMatch) return await postChat(request, env, ctx, chatMatch[1]);
      const evalMatch = sub.match(/^\/levels\/([^/]+)\/defense\/evaluate$/);
      if (request.method === 'POST' && evalMatch) return await postDefense(request, env, ctx, evalMatch[1], false);
      const streamMatch = sub.match(/^\/levels\/([^/]+)\/defense\/evaluate\/stream$/);
      if (request.method === 'POST' && streamMatch) return await postDefense(request, env, ctx, streamMatch[1], true);

  return jsonResponse({ error: '未找到资源' }, 404);
}

export default {
  /**
   * CORS 统一在最外层补：生产同源无感（corsHeaders 返回空对象）；
   * 本地 wrangler dev 联调置 DEV_ALLOW_CORS="1" 后 localhost 前端可跨域调 API。
   */
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }
    let res;
    try {
      res = await route(request, env, ctx);
    } catch (err) {
      res = jsonResponse({ error: '服务内部错误：' + String((err && err.message) || err).slice(0, 200) }, 500);
    }
    const cors = corsHeaders(request, env);
    const keys = Object.keys(cors);
    if (keys.length === 0) return res;
    const headers = new Headers(res.headers);
    for (const k of keys) headers.set(k, cors[k]);
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  }
};
