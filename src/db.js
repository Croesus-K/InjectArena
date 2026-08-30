'use strict';
/**
 * 攻心 InjectArena —— 审计日志（SQLite，node:sqlite 内置驱动，零额外依赖）。
 * 只追加、只记录元数据（不含 payload 明文），供运维排查用量与滥用；
 * 审计本身不参与任何判定逻辑。全部查询走参数绑定，无字符串拼 SQL。
 */

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const DDL = 'CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, ip TEXT NOT NULL, route TEXT NOT NULL, level_id TEXT, payload_chars INTEGER, tokens INTEGER, passed INTEGER, outcome TEXT NOT NULL, detail TEXT)';

/**
 * @param {string} dbPath SQLite 文件路径，或 ':memory:'
 */
function openAuditDb(dbPath) {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
  }
  const db = new DatabaseSync(dbPath);
  db.prepare(DDL).run();
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

module.exports = { openAuditDb, insertAudit, listAudit };
