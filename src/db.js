'use strict';
/**
 * 攻心 InjectArena —— 审计日志（SQLite，node:sqlite 内置驱动，零额外依赖）。
 * 只追加、只记录元数据（不含 payload 明文），供运维排查用量与滥用；
 * 审计本身不参与任何判定逻辑。全部查询走参数绑定，无字符串拼 SQL。
 */

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const DDL = [
  'CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, ip TEXT NOT NULL, route TEXT NOT NULL, level_id TEXT, payload_chars INTEGER, tokens INTEGER, passed INTEGER, outcome TEXT NOT NULL, detail TEXT)',
  'CREATE TABLE IF NOT EXISTS breach_records (id INTEGER PRIMARY KEY AUTOINCREMENT, level_id TEXT NOT NULL, player TEXT NOT NULL, chars INTEGER NOT NULL, tokens INTEGER, payload_text TEXT NOT NULL, ts TEXT NOT NULL)',
  'CREATE TABLE IF NOT EXISTS defense_records (id INTEGER PRIMARY KEY AUTOINCREMENT, level_id TEXT NOT NULL, player TEXT NOT NULL, block_rate REAL NOT NULL, leak_rate REAL NOT NULL, fp_rate REAL, evaluated INTEGER NOT NULL, ts TEXT NOT NULL)'
];

/**
 * @param {string} dbPath SQLite 文件路径，或 ':memory:'
 */
function openAuditDb(dbPath) {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
  }
  const db = new DatabaseSync(dbPath);
  for (const ddl of DDL) db.prepare(ddl).run();
  return db;
}

/**
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {object} record {ts, ip, route, levelId?, payloadChars?, tokens?, passed?, outcome, detail?}
 */
function insertAudit(db, record) {
  db.prepare(
    'INSERT INTO audit_log (ts, ip, route, level_id, payload_chars, tokens, passed, outcome, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(
    record.ts,
    record.ip,
    record.route,
    record.levelId || null,
    record.payloadChars === undefined || record.payloadChars === null ? null : record.payloadChars,
    record.tokens === undefined || record.tokens === null ? null : record.tokens,
    record.passed === undefined || record.passed === null ? null : record.passed ? 1 : 0,
    record.outcome,
    record.detail || null
  );
}

/** 运维排查用（不暴露 HTTP 接口）。 */
function listAudit(db, limit) {
  return db
    .prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?')
    .all(limit || 50);
}

/**
 * IP 打码（榜单公开展示用）：IPv4 取前两段，IPv6 取前两组，其余截前 4 字符。
 * 打码不可逆，且同网段玩家合并展示——榜单只需要身份感，不需要身份。
 */
function maskIp(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return '未知';
  if (ip.includes(':')) {
    const groups = ip.split(':').filter(Boolean);
    return (groups.slice(0, 2).join(':') || ip) + '::*';
  }
  const parts = ip.split('.');
  if (parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p))) {
    return parts[0] + '.' + parts[1] + '.*.*';
  }
  return ip.slice(0, 4) + '*';
}

/**
 * 名将榜：记录每玩家每关的最短破阵纪录（更短者覆盖）。
 */
function upsertBreachRecord(db, record) {
  const existing = db
    .prepare('SELECT id, chars FROM breach_records WHERE level_id = ? AND player = ?')
    .get(record.levelId, record.player);
  if (!existing) {
    db.prepare('INSERT INTO breach_records (level_id, player, chars, tokens, payload_text, ts) VALUES (?, ?, ?, ?, ?, ?)')
      .run(record.levelId, record.player, record.chars, record.tokens === undefined ? null : record.tokens, record.payloadText, record.ts);
    return 'inserted';
  }
  if (record.chars < existing.chars) {
    db.prepare('UPDATE breach_records SET chars = ?, tokens = ?, payload_text = ?, ts = ? WHERE id = ?')
      .run(record.chars, record.tokens === undefined ? null : record.tokens, record.payloadText, record.ts, existing.id);
    return 'updated';
  }
  return 'kept';
}

/**
 * 段位榜：记录每玩家每关的最佳考段（拦截率更高者覆盖；同率取样本更大者）。
 */
function upsertDefenseRecord(db, record) {
  const existing = db
    .prepare('SELECT id, block_rate, evaluated FROM defense_records WHERE level_id = ? AND player = ?')
    .get(record.levelId, record.player);
  const better = !existing
    || record.blockRate > existing.block_rate
    || (record.blockRate === existing.block_rate && record.evaluated > existing.evaluated);
  if (!existing) {
    db.prepare('INSERT INTO defense_records (level_id, player, block_rate, leak_rate, fp_rate, evaluated, ts) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(record.levelId, record.player, record.blockRate, record.leakRate, record.fpRate === undefined ? null : record.fpRate, record.evaluated, record.ts);
    return 'inserted';
  }
  if (better) {
    db.prepare('UPDATE defense_records SET block_rate = ?, leak_rate = ?, fp_rate = ?, evaluated = ?, ts = ? WHERE id = ?')
      .run(record.blockRate, record.leakRate, record.fpRate === undefined ? null : record.fpRate, record.evaluated, record.ts, existing.id);
    return 'updated';
  }
  return 'kept';
}

/** 名将榜：按关卡分组、字符升序。 */
function listBreachRecords(db, limit) {
  return db
    .prepare('SELECT level_id AS levelId, player, chars, tokens, ts FROM breach_records ORDER BY level_id ASC, chars ASC LIMIT ?')
    .all(limit || 50);
}

/**
 * 导出用完整破阵记录（含 payload 明文）：只服务 /api/leaderboard?format=export
 * 这一条显式导出通道（语料回流走公开接口，治理规则 2）；默认榜单视图永远不带 payload_text。
 */
function listBreachRecordsFull(db, limit) {
  return db
    .prepare('SELECT level_id AS levelId, player, chars, tokens, payload_text AS payloadText, ts FROM breach_records ORDER BY level_id ASC, chars ASC, id ASC LIMIT ?')
    .all(limit || 200);
}

/** 段位榜：按关卡分组、拦截率降序（同率样本大者优先）。 */
function listDefenseRecords(db, limit) {
  return db
    .prepare('SELECT level_id AS levelId, player, block_rate AS blockRate, leak_rate AS leakRate, fp_rate AS fpRate, evaluated, ts FROM defense_records ORDER BY level_id ASC, block_rate DESC, leak_rate ASC, evaluated DESC LIMIT ?')
    .all(limit || 50);
}

module.exports = { openAuditDb, insertAudit, listAudit, maskIp, upsertBreachRecord, upsertDefenseRecord, listBreachRecords, listBreachRecordsFull, listDefenseRecords };
