'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { loadConfig, loadDotEnv } = require('../src/config.js');

test('loadConfig：默认值', () => {
  const c = loadConfig({});
  assert.equal(c.host, '127.0.0.1');
  assert.equal(c.port, 8787);
  assert.equal(c.dbPath, 'data/audit.db');
  assert.equal(c.provider, 'openai-compatible');
  assert.equal(c.apiKey, '');
  assert.deepEqual(c.chatRate, { capacity: 10, refillPerMinute: 10 });
});

test('loadConfig：环境变量覆盖', () => {
  const c = loadConfig({
    INJECTARENA_HOST: '0.0.0.0',
    INJECTARENA_PORT: '9000',
    INJECTARENA_API_KEY: 'sk-x',
    INJECTARENA_BASE_URL: 'https://api.deepseek.com/v1',
    INJECTARENA_MODEL: 'deepseek-chat'
  });
  assert.equal(c.port, 9000);
  assert.equal(c.model, 'deepseek-chat');
  assert.equal(c.baseUrl, 'https://api.deepseek.com/v1');
});

test('loadDotEnv：读入 INJECTARENA_* 键、已有环境变量优先、文件缺失静默', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'injectarena-env-'));
  const file = path.join(dir, '.env');
  fs.writeFileSync(file, [
    '# 注释行',
    'INJECTARENA_MODEL=from-dotenv',
    'INJECTARENA_PORT=9999',
    'OTHER_VAR=should-not-load',
    ''
  ].join('\n'));

  process.env.INJECTARENA_MODEL = 'already-set'; // 预置：不应被 .env 覆盖
  const n = loadDotEnv(file);
  assert.equal(n, 1, '只有未存在的 INJECTARENA_PORT 被注入');
  assert.equal(process.env.INJECTARENA_MODEL, 'already-set');
  assert.equal(process.env.INJECTARENA_PORT, '9999');
  assert.equal('OTHER_VAR' in process.env, false, '非 INJECTARENA_ 前缀不注入');

  delete process.env.INJECTARENA_MODEL;
  delete process.env.INJECTARENA_PORT;
  assert.equal(loadDotEnv(path.join(dir, '不存在.env')), 0);
});
