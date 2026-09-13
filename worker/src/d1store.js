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

/**
 * 未上榜破阵落库（破阵判定 passed 即录，与上榜解耦）：语料回流专属，匿名——
 * 不存 player/actor/IP；同一关同一条 payload 幂等跳过，重复刷不膨胀。
 * @returns {Promise<'written'|'duplicate'>}
 */
export async function insertUnclaimedBreach(db, record) {
  const dup = await db
    .prepare('SELECT 1 FROM breach_unclaimed WHERE level_id = ? AND payload_text = ? LIMIT 1')
    .bind(record.levelId, record.payloadText)
    .first();
  if (dup) return 'duplicate';
  await db
    .prepare('INSERT INTO breach_unclaimed (level_id, payload_text, chars, tokens, ts) VALUES (?, ?, ?, ?, ?)')
    .bind(record.levelId, record.payloadText, record.chars, n(record.tokens), record.ts)
    .run();
  return 'written';
}

/** 未上榜破阵导出（含 payload 明文）：只服务 /leaderboard?format=export，导出边缘统一打码。 */
export async function listUnclaimedBreaches(db, limit) {
  const out = await db
    .prepare(
      'SELECT level_id AS levelId, payload_text AS payloadText, chars, tokens, ts ' +
        'FROM breach_unclaimed ORDER BY ts ASC LIMIT ?'
    )
    .bind(limit || 200)
    .all();
  return out.results || [];
}

/** 攻防榜：按总计份数（破阵+考段）降序取前五十。 */
export async function listRanking(db, limit) {
  const out = await db
    .prepare(
      'SELECT github_login AS login, breach_count AS breachCount, defense_count AS defenseCount, ' +
        'breach_count + defense_count AS total, score FROM player_stats ' +
        'WHERE breach_count + defense_count > 0 ORDER BY total DESC, score DESC, ts ASC LIMIT ?'
    )
    .bind(limit || 50)
    .all();
  return out.results || [];
}

/** 留言板全量（position 升序）。 */
export async function listBoard(db) {
  const out = await db
    .prepare('SELECT id, github_login AS login, display_name AS displayName, message, position, ts FROM message_board ORDER BY position ASC')
    .all();
  return out.results || [];
}

/**
 * 留言（一人一条 upsert）：新留言排到队尾（position = MAX+1，提交时间序）；
 * 已有留言者仅更新内容与时间，position 保留——换位成果不因重写留言丢失。
 * @returns {Promise<'written'|'updated'>}
 */
export async function upsertBoardMessage(db, record) {
  const existing = await db
    .prepare('SELECT id FROM message_board WHERE github_login = ?')
    .bind(record.githubLogin)
    .first();
  if (existing) {
    await db
      .prepare('UPDATE message_board SET display_name = ?, message = ?, ts = ? WHERE github_login = ?')
      .bind(record.displayName, record.message, record.ts, record.githubLogin)
      .run();
    return 'updated';
  }
  const maxRow = await db.prepare('SELECT COALESCE(MAX(position), 0) AS maxPos FROM message_board').first();
  await db
    .prepare('INSERT INTO message_board (github_login, display_name, message, position, ts) VALUES (?, ?, ?, ?, ?)')
    .bind(record.githubLogin, record.displayName, record.message, (maxRow?.maxPos ?? 0) + 1, record.ts)
    .run();
  return 'written';
}

/**
 * 换位：我的留言与目标留言互换 position，扣 |Δ| 积分（等级不变）。
 * 积分不足 / 目标不存在 / 与自己换 → 拒绝。
 */
export async function swapBoardPosition(db, login, targetId) {
  const mine = await db.prepare('SELECT id, position FROM message_board WHERE github_login = ?').bind(login).first();
  if (!mine) return { error: '你还没有留言，无法换位。' };
  const target = await db
    .prepare('SELECT id, position, github_login FROM message_board WHERE id = ?')
    .bind(targetId)
    .first();
  if (!target) return { error: '目标留言不存在。' };
  if (target.github_login === login) return { error: '不能与自己的留言换位。' };
  const delta = Math.abs(mine.position - target.position);
  if (delta === 0) return { error: '已在目标位置。' };
  const stats = await getPlayerStats(db, login);
  if (!stats || stats.score < delta) {
    return { error: `积分不足：换 ${delta} 位需 ${delta} 分，你只有 ${stats ? stats.score : 0} 分。` };
  }
  await db.batch([
    db.prepare('UPDATE message_board SET position = ? WHERE id = ?').bind(target.position, mine.id),
    db.prepare('UPDATE message_board SET position = ? WHERE id = ?').bind(mine.position, target.id),
    db.prepare('UPDATE player_stats SET score = score - ? WHERE github_login = ?').bind(delta, login),
  ]);
  return { swapped: true, delta };
}
