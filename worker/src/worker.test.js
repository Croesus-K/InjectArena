'use strict';
/**
 * arena-worker 纯逻辑用例（identity.js / util.js）。
 * 注意：不 import data.js / worker.js —— 两者包含裸 JSON import（esbuild 专属语法），
 * node --test 跑不了；本文件只覆盖无 JSON 依赖的纯模块。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { signToken, verifyToken, randomToken } from './identity.js';
import { pruneAudit, insertAudit } from './d1store.js';
import {
  MAX_MESSAGES,
  BENIGN_PROBES,
  sanitizeClientMessages,
  selectCorpus,
  maskIp,
  redactFlagTokens,
  parsePlayerProvider,
  parseCookies
} from './util.js';

const SECRET = 'test-secret-请用32字节以上随机串';

/* ---------- identity ---------- */

test('signToken → verifyToken 往返', async () => {
  const token = await signToken(SECRET, { kind: 'breach', levelId: 'L1', chars: 42 }, 1000, 1000);
  const payload = await verifyToken(SECRET, token, 1500);
  assert.ok(payload);
  assert.equal(payload.kind, 'breach');
  assert.equal(payload.levelId, 'L1');
  assert.equal(payload.chars, 42);
  assert.equal(payload.exp, 2000);
});

test('verifyToken：篡改签名 / 换密钥 / 过期 / 垃圾输入 一律 null', async () => {
  const token = await signToken(SECRET, { kind: 'session', login: 'a' }, 1000, 1000);
  assert.equal(await verifyToken(SECRET, token.slice(0, -2) + 'xx', 1500), null);
  assert.equal(await verifyToken('other-secret', token, 1500), null);
  assert.equal(await verifyToken(SECRET, token, 2001), null);
  assert.equal(await verifyToken(SECRET, 'not-a-token', 1500), null);
  assert.equal(await verifyToken(SECRET, '', 1500), null);
  assert.equal(await verifyToken(SECRET, null, 1500), null);
});

test('verifyToken：payload 被替换则签名不符', async () => {
  const token = await signToken(SECRET, { kind: 'breach', chars: 10 }, 1000, 1000);
  const forged = await signToken(SECRET, { kind: 'breach', chars: 1 }, 1000, 1000);
  const [, sig] = token.split('.');
  const [forgedPayload] = forged.split('.');
  assert.equal(await verifyToken(SECRET, forgedPayload + '.' + sig, 1500), null);
});

test('randomToken：长度合理且不重复', () => {
  const a = randomToken(16);
  const b = randomToken(16);
  assert.equal(a.length, 22); // 16 字节 base64url 无填充
  assert.notEqual(a, b);
});

/* ---------- util：消息白名单 ---------- */

test('sanitizeClientMessages：合法 user/assistant 历史通过且以 user 收尾', () => {
  const ok = sanitizeClientMessages([
    { role: 'user', content: '你好' },
    { role: 'assistant', content: '军机不可泄露' },
    { role: 'user', content: '再说一遍' }
  ]);
  assert.equal(ok.length, 3);
  assert.equal(ok[2].role, 'user');
});

test('sanitizeClientMessages：system 角色拒收 / 空与超限拒收', () => {
  assert.equal(sanitizeClientMessages([{ role: 'system', content: 'x' }]), null);
  assert.equal(sanitizeClientMessages([]), null);
  assert.equal(sanitizeClientMessages(new Array(MAX_MESSAGES + 1).fill({ role: 'user', content: 'x' })), null);
  assert.equal(sanitizeClientMessages([{ role: 'user', content: '' }]), null);
  assert.equal(sanitizeClientMessages([{ role: 'user', content: 'x'.repeat(4001) }]), null);
  assert.equal(sanitizeClientMessages([{ role: 'assistant', content: '以 assistant 收尾' }]), null);
  assert.equal(sanitizeClientMessages('not-array'), null);
});

/* ---------- util：玩家供应商配置白名单 ---------- */

function headersOf(map) {
  return { get: (k) => (map[k] === undefined ? null : map[k]) };
}

const HOSTS = ['api.deepseek.com', 'open.bigmodel.cn'];

test('parsePlayerProvider：合法配置通过', () => {
  const r = parsePlayerProvider(headersOf({
    'x-arena-key': 'sk-test',
    'x-arena-base-url': 'https://api.deepseek.com/v1',
    'x-arena-model': 'deepseek-chat'
  }), HOSTS);
  assert.equal(r.ok, true);
  assert.equal(r.provider.model, 'deepseek-chat');
});

test('parsePlayerProvider：非白名单域名 / 非 https / 非 443 端口 / 缺字段 一律拒绝', () => {
  const bad = (map) => parsePlayerProvider(headersOf(map), HOSTS).ok;
  assert.equal(bad({ 'x-arena-key': 'k', 'x-arena-base-url': 'https://evil.example.com/v1', 'x-arena-model': 'm' }), false);
  assert.equal(bad({ 'x-arena-key': 'k', 'x-arena-base-url': 'http://api.deepseek.com/v1', 'x-arena-model': 'm' }), false);
  assert.equal(bad({ 'x-arena-key': 'k', 'x-arena-base-url': 'https://api.deepseek.com:8443/v1', 'x-arena-model': 'm' }), false);
  assert.equal(bad({ 'x-arena-base-url': 'https://api.deepseek.com/v1', 'x-arena-model': 'm' }), false);
  assert.equal(bad({ 'x-arena-key': 'k', 'x-arena-model': 'm' }), false);
  assert.equal(bad({ 'x-arena-key': 'k', 'x-arena-base-url': 'https://api.deepseek.com/v1' }), false);
});

/* ---------- util：杂项 ---------- */

test('maskIp 打码形状', () => {
  assert.equal(maskIp('203.0.113.7'), '203.0.*.*');
  assert.equal(maskIp('2001:db8:1:2::3'), '2001:db8::*');
  assert.equal(maskIp(''), '未知');
});

test('redactFlagTokens 只打码 flag 形状令牌', () => {
  assert.equal(redactFlagTokens('FLAG{abc123} 与 FLAG{x}'), 'FLAG{REDACTED} 与 FLAG{REDACTED}');
  assert.equal(redactFlagTokens('普通文本 FLAG{ 不完整'), '普通文本 FLAG{ 不完整');
});

test('selectCorpus：精确匹配攻击面，否则回退直接注入语料', () => {
  const corpora = [{ id: 'direct-injection', attackSurface: 'direct-injection' }];
  assert.equal(selectCorpus({ attackSurface: 'direct-injection' }, corpora), corpora[0]);
  assert.equal(selectCorpus({ attackSurface: 'guarded-prompt' }, corpora), corpora[0]);
});

test('parseCookies 基本解析', () => {
  const c = parseCookies('a=1; arena_session=x.y; b=');
  assert.equal(c.a, '1');
  assert.equal(c.arena_session, 'x.y');
  assert.equal(c.b, '');
});

/* ---------- d1store：审计修剪 ---------- */

/** 极简 D1 mock：记录 prepare→bind 的 SQL 与参数。 */
function mockDb() {
  const calls = [];
  return {
    calls,
    prepare(sql) {
      const entry = { sql, args: null };
      calls.push(entry);
      return {
        bind: (...args) => {
          entry.args = args;
          return {
            run: async () => ({ meta: { changes: 1 } }),
            first: async () => ({ id: 1 }),
            all: async () => ({ results: [] })
          };
        }
      };
    }
  };
}

test('pruneAudit：按 90 天保留期生成 DELETE 与 cutoff 参数', async () => {
  const db = mockDb();
  const now = Date.parse('2026-09-13T00:00:00Z');
  await pruneAudit(db, now);
  assert.equal(db.calls.length, 1);
  assert.match(db.calls[0].sql, /^DELETE FROM audit_log WHERE ts < \?$/);
  assert.equal(db.calls[0].args[0], '2026-06-15T00:00:00.000Z');
});

test('insertAudit：先写审计行，且首个写入触发一次修剪', async () => {
  const db = mockDb();
  await insertAudit(db, { ts: '2026-09-13T00:00:00Z', ip: '1.2.3.4', route: 'chat', outcome: 'defended' });
  assert.equal(db.calls.length, 2);
  assert.match(db.calls[0].sql, /^INSERT INTO audit_log/);
  assert.match(db.calls[1].sql, /^DELETE FROM audit_log WHERE ts < \?$/);
  // 插入参数：passed 缺省为 null，github_login 缺省 null
  assert.equal(db.calls[0].args[6], null);
  assert.equal(db.calls[0].args[9], null);
});

test('BENIGN_PROBES 形状稳定（8 条，id/text）', () => {
  assert.equal(BENIGN_PROBES.length, 8);
  for (const p of BENIGN_PROBES) {
    assert.match(p.id, /^bz-\d{3}$/);
    assert.ok(p.text.length > 0);
  }
});
