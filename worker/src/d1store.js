'use strict';
/**
 * arena-worker —— D1 存储层：src/db.js（node:sqlite）的异步移植 + BYOK 身份扩展。
 *
 * 身份模型：actor 是唯一键（github_login 或 'guest:'+display_id），每玩家每关一行；
 * display_id 是自填的榜上展示名号；github_login / github_avatar 仅在「挂身份」时写入，
 * NULL 即「不挂」——榜单公开展示永不出现未同意的 GitHub 信息。
 *
 * 覆盖语义与 Node 版一致：
 *   名将榜：同 actor 更短招式覆盖（ON CONFLICT ... WHERE excluded.chars < 现值）；
 *   段位榜：拦截率更高者覆盖，同率取样本更大者。
 * 全部查询走参数绑定，无字符串拼 SQL。玩家 LLM Key 永不入库。
 */

function n(value) {
  return value === undefined || value === null ? null : value;
}

/** 审计保留期（天）：过期行在写入时顺手清除。改动保留策略只动这个常量。 */
const AUDIT_RETENTION_DAYS = 90;
const PRUNE_INTERVAL_MS = 3600 * 1000; // 每 isolate 每小时最多清一次，避免每请求多打 D1 子请求
let lastPruneAt = 0;

/**
 * 清除超过保留期的审计旧行（ts 为 ISO 字符串，与 cutoff 同构可直接比较）。
 * 独立导出以便单测；失败静默——修剪只是卫生措施，绝不影响主流程。
 */
export async function pruneAudit(db, nowMs) {
  const cutoff = new Date(nowMs - AUDIT_RETENTION_DAYS * 86400000).toISOString();
  await db.prepare('DELETE FROM audit_log WHERE ts < ?').bind(cutoff).run();
}

/** 审计日志：只追加、只存元数据（不含 payload 明文、不含 Key）。 */
export async function insertAudit(db, record) {
  await db
    .prepare(
      'INSERT INTO audit_log (ts, ip, route, level_id, payload_chars, tokens, passed, outcome, detail, github_login) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )
    .bind(
      record.ts,
      record.ip,
      record.route,
      record.levelId || null,
      n(record.payloadChars),
      n(record.tokens),
      record.passed === undefined || record.passed === null ? null : record.passed ? 1 : 0,
      record.outcome,
      record.detail || null,
      record.githubLogin || null
    )
    .run();

  // 顺手修剪：限流到每 isolate 每小时一次；失败不影响主写入
  const now = Date.now();
  if (now - lastPruneAt > PRUNE_INTERVAL_MS) {
    lastPruneAt = now;
    try {
      await pruneAudit(db, now);
    } catch (_) { /* 修剪失败不影响主流程 */ }
  }
}

/**
 * 名将榜落库（破阵凭证兑换时调用）。payload 明文单独落 breach_payloads（隔离层）：
 * 榜单表只存展示字段；仅当纪录实际写入/覆盖（更短）时才写 payload。
 * @returns {Promise<'written'|'kept'>} kept = 榜上已有更短招式，未覆盖
 */
export async function upsertBreachRecord(db, record) {
  const row = await db
    .prepare(
      'INSERT INTO breach_records (level_id, actor, display_id, chars, tokens, message, github_login, github_avatar, ts) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT(level_id, actor) DO UPDATE SET ' +
        'chars = excluded.chars, tokens = excluded.tokens, ' +
        'message = excluded.message, github_login = excluded.github_login, github_avatar = excluded.github_avatar, ts = excluded.ts ' +
        'WHERE excluded.chars < breach_records.chars ' +
        'RETURNING id'
    )
    .bind(
      record.levelId,
      record.actor,
      record.displayId,
      record.chars,
      n(record.tokens),
      n(record.message),
      n(record.githubLogin),
      n(record.githubAvatar),
      record.ts
    )
    .first();
  if (!row) return 'kept';
  await db
    .prepare(
      'INSERT INTO breach_payloads (breach_id, payload_text, ts) VALUES (?, ?, ?) ' +
        'ON CONFLICT(breach_id) DO UPDATE SET payload_text = excluded.payload_text, ts = excluded.ts'
    )
    .bind(row.id, record.payloadText, record.ts)
    .run();
  return 'written';
}

/**
 * 段位榜落库（守方考段凭证兑换时调用）。
 * @returns {Promise<'written'|'kept'>}
 */
export async function upsertDefenseRecord(db, record) {
  const res = await db
    .prepare(
      'INSERT INTO defense_records (level_id, actor, display_id, block_rate, leak_rate, fp_rate, evaluated, message, github_login, github_avatar, ts) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT(level_id, actor) DO UPDATE SET ' +
        'block_rate = excluded.block_rate, leak_rate = excluded.leak_rate, fp_rate = excluded.fp_rate, ' +
        'evaluated = excluded.evaluated, message = excluded.message, ' +
        'github_login = excluded.github_login, github_avatar = excluded.github_avatar, ts = excluded.ts ' +
        'WHERE excluded.block_rate > defense_records.block_rate ' +
        'OR (excluded.block_rate = defense_records.block_rate AND excluded.evaluated > defense_records.evaluated)'
    )
    .bind(
      record.levelId,
      record.actor,
      record.displayId,
      record.blockRate,
      record.leakRate,
      n(record.fpRate),
      record.evaluated,
      n(record.message),
      n(record.githubLogin),
      n(record.githubAvatar),
      record.ts
    )
    .run();
  return res.meta && res.meta.changes > 0 ? 'written' : 'kept';
}

/** 名将榜：按关卡分组、字符升序（不含 payload 明文）。 */
export async function listBreachRecords(db, limit) {
  const out = await db
    .prepare(
      'SELECT level_id AS levelId, display_id AS player, chars, tokens, message, github_login AS githubLogin, github_avatar AS githubAvatar, ts ' +
        'FROM breach_records ORDER BY level_id ASC, chars ASC LIMIT ?'
    )
    .bind(limit || 50)
    .all();
  return out.results || [];
}

/**
 * 导出用完整破阵记录（含 payload 明文）：只服务 /leaderboard?format=export
 * 显式导出通道（语料回流，治理规则 2）；payload 经 LEFT JOIN 单独取——
 * 榜单表本身零攻击原文；默认榜单视图永远不带 payload。
 */
export async function listBreachRecordsFull(db, limit) {
  const out = await db
    .prepare(
      'SELECT b.level_id AS levelId, b.display_id AS player, b.chars, b.tokens, p.payload_text AS payloadText, b.message, b.github_login AS githubLogin, b.ts ' +
        'FROM breach_records b LEFT JOIN breach_payloads p ON p.breach_id = b.id ' +
        'ORDER BY b.level_id ASC, b.chars ASC, b.id ASC LIMIT ?'
    )
    .bind(limit || 200)
    .all();
  return out.results || [];
}

/** 段位榜：按关卡分组、拦截率降序（同率样本大者优先）。 */
export async function listDefenseRecords(db, limit) {
  const out = await db
    .prepare(
      'SELECT level_id AS levelId, display_id AS player, block_rate AS blockRate, leak_rate AS leakRate, fp_rate AS fpRate, evaluated, message, github_login AS githubLogin, github_avatar AS githubAvatar, ts ' +
        'FROM defense_records ORDER BY level_id ASC, block_rate DESC, leak_rate ASC, evaluated DESC LIMIT ?'
    )
    .bind(limit || 50)
    .all();
  return out.results || [];
}
