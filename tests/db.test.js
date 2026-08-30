'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { openAuditDb, insertAudit, listAudit, maskIp, upsertBreachRecord, upsertDefenseRecord, listBreachRecords, listDefenseRecords } = require('../src/db.js');

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

test('maskIp：IPv4 取前两段、IPv6 取前两组、异常输入兜底', () => {
  assert.equal(maskIp('203.0.113.45'), '203.0.*.*');
  assert.equal(maskIp('1.2.3.4'), '1.2.*.*');
  assert.equal(maskIp('2001:db8:1:2::7'), '2001:db8::*');
  assert.equal(maskIp(''), '未知');
  assert.equal(maskIp(null), '未知');
  assert.equal(maskIp('weird'), 'weir*');
});

test('名将榜：插入、更短覆盖、更长保留', () => {
  const db = openAuditDb(':memory:');
  const base = { levelId: 'L1', player: '1.2.*.*', tokens: 40, ts: '2026-08-31T00:00:00Z' };
  assert.equal(upsertBreachRecord(db, { ...base, chars: 50, payloadText: '长招式' }), 'inserted');
  assert.equal(upsertBreachRecord(db, { ...base, chars: 70, payloadText: '更长的招式' }), 'kept', '更长不覆盖');
  assert.equal(upsertBreachRecord(db, { ...base, chars: 20, payloadText: '极短招' }), 'updated', '更短覆盖');

  const rows = listBreachRecords(db, 10);
  assert.equal(rows.length, 1, '每玩家每关只保一条');
  assert.equal(rows[0].chars, 20);
  assert.equal(rows[0].payload_text, undefined, '榜单查询不含 payload 明文（防误展示）');
  db.close();
});

test('段位榜：插入、更优覆盖、同率样本大者优先', () => {
  const db = openAuditDb(':memory:');
  const base = { levelId: 'L2', player: '5.6.*.*', leakRate: 0.1, fpRate: null, ts: '2026-08-31T00:00:00Z' };
  assert.equal(upsertDefenseRecord(db, { ...base, blockRate: 0.8, evaluated: 50 }), 'inserted');
  assert.equal(upsertDefenseRecord(db, { ...base, blockRate: 0.7, evaluated: 50 }), 'kept', '更差不覆盖');
  assert.equal(upsertDefenseRecord(db, { ...base, blockRate: 0.8, evaluated: 60 }), 'updated', '同率样本更大者覆盖');
  assert.equal(upsertDefenseRecord(db, { ...base, blockRate: 0.95, evaluated: 10 }), 'updated', '更高拦截率覆盖');

  const rows = listDefenseRecords(db, 10);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].blockRate, 0.95);
  db.close();
});

test('两榜按关卡分组排序', () => {
  const db = openAuditDb(':memory:');
  upsertBreachRecord(db, { levelId: 'L2', player: 'a.*.*', chars: 30, payloadText: 'x', ts: 't' });
  upsertBreachRecord(db, { levelId: 'L1', player: 'b.*.*', chars: 40, payloadText: 'y', ts: 't' });
  const rows = listBreachRecords(db, 10);
  assert.deepEqual(rows.map((r) => r.levelId), ['L1', 'L2'], '关卡升序在前、字符升序在后');
  db.close();
});
