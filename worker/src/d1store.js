'use strict';
/**
 * arena-worker —— D1 存储层：src/db.js（node:sqlite）的异步移植 + v0.6.0 份数榜扩展。
 *
 * 当前六表模型（v0.7.0 起旧榜单三表 breach_records/breach_payloads/defense_records 已退役）：
 *   audit_log         审计元数据（90 天滚动清理，写入时顺手修剪）；
 *   breach_unclaimed  未上榜破阵匿名回流（同关同 payload 幂等，语料飞轮专属）；
 *   player_stats      攻/防份数与积分（github_login 主键；总计=攻+守，积分可消费）；
 *   breach_corpus     攻方语料登记（同登录同关相似度 ≥0.8 视为同一份，不重复计分）；
 *   defense_corpus    守方布防语料登记（对称）；
 *   message_board     留言板（一人一条，position 序列号，积分换位）。
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
 * 攻方语料登记（份数榜计分）：同登录同关内与既有语料比对，
 * 相似（isSimilarToAny 由调用方注入，阈值 0.8）视为同一份——不重复计分。
 * @returns {Promise<'written'|'duplicate'>}
 */
export async function insertBreachCorpus(db, record, isSimilarToAny) {
  const rows = await db
    .prepare('SELECT payload_text FROM breach_corpus WHERE github_login = ? AND level_id = ?')
    .bind(record.githubLogin, record.levelId)
    .all();
  if (isSimilarToAny(record.payloadText, (rows.results || []).map((r) => r.payloadText))) return 'duplicate';
  await db
    .prepare('INSERT INTO breach_corpus (github_login, level_id, payload_text, chars, ts) VALUES (?, ?, ?, ?, ?)')
    .bind(record.githubLogin, record.levelId, record.payloadText, record.chars, record.ts)
    .run();
  return 'written';
}

/**
 * 守方布防语料登记（对称）：同登录同关内布防提示词相似 ≥0.8 视为同一份。
 * @returns {Promise<'written'|'duplicate'>}
 */
export async function insertDefenseCorpus(db, record, isSimilarToAny) {
  const rows = await db
    .prepare('SELECT defense_prompt FROM defense_corpus WHERE github_login = ? AND level_id = ?')
    .bind(record.githubLogin, record.levelId)
    .all();
  if (isSimilarToAny(record.defensePrompt, (rows.results || []).map((r) => r.defensePrompt))) return 'duplicate';
  await db
    .prepare('INSERT INTO defense_corpus (github_login, level_id, defense_prompt, ts) VALUES (?, ?, ?, ?)')
    .bind(record.githubLogin, record.levelId, record.defensePrompt, record.ts)
    .run();
  return 'written';
}

/** 玩家统计读取（无行则 null）：攻/防份数与可消费积分。 */
export async function getPlayerStats(db, login) {
  const row = await db
    .prepare('SELECT breach_count AS breachCount, defense_count AS defenseCount, score FROM player_stats WHERE github_login = ?')
    .bind(login)
    .first();
  return row || null;
}

/**
 * 计分累加（行不存在则建）：攻/守份数与积分按增量累加；
 * 相似语料判重通过后才调用，保证「同一份」不重复升级。
 */
export async function addPlayerStats(db, login, delta) {
  await db
    .prepare(
      'INSERT INTO player_stats (github_login, breach_count, defense_count, score, ts) VALUES (?, ?, ?, ?, ?) ' +
        'ON CONFLICT (github_login) DO UPDATE SET ' +
        'breach_count = breach_count + excluded.breach_count, ' +
        'defense_count = defense_count + excluded.defense_count, ' +
        'score = score + excluded.score, ts = excluded.ts'
    )
    .bind(login, delta.breachDelta || 0, delta.defenseDelta || 0, delta.scoreDelta || 0, new Date().toISOString())
    .run();
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
