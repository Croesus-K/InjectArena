'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { openAuditDb, insertAudit, listAudit } = require('../src/db.js');

test('审计日志：插入、查询、字段齐全（临时文件库）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'injectarena-db-'));
  const dbPath = path.join(dir, 'audit.db');
  const db = openAuditDb(dbPath);

  insertAudit(db, {
    ts: '2026-08-31T00:00:00.000Z',
    ip: '1.2.3.4',
    route: 'chat',
    levelId: 'L1',
    payloadChars: 12,
    tokens: 34,
    passed: true,
    outcome: 'breached'
  });
  insertAudit(db, {
    ts: '2026-08-31T00:00:01.000Z',
    ip: '1.2.3.4',
    route: 'chat',
    levelId: 'L2',
    outcome: 'rate-limited'
  });

  const rows = listAudit(db, 10);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].outcome, 'rate-limited'); // 倒序
  const first = rows[1];
  assert.equal(first.level_id, 'L1');
  assert.equal(first.payload_chars, 12);
  assert.equal(first.tokens, 34);
  assert.equal(first.passed, 1);
  assert.equal(first.detail, null);

  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('审计日志：内存库可用（测试场景）', () => {
  const db = openAuditDb(':memory:');
  insertAudit(db, { ts: 't', ip: 'a', route: 'chat', outcome: 'defended', passed: false });
  assert.equal(listAudit(db, 5)[0].passed, 0);
  db.close();
});
