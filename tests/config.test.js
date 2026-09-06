'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { loadConfig, loadDotEnv, resolveEnvFile } = require('../src/config.js');

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

test('resolveEnvFile：显式 INJECTARENA_ENV_FILE 优先；文件缺失警告且不抛', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'injectarena-env-'));
  const explicit = path.join(dir, 'my-secrets.env');
  fs.writeFileSync(explicit, 'INJECTARENA_MODEL=explicit\n');
  const r1 = resolveEnvFile({ INJECTARENA_ENV_FILE: explicit }, dir, dir);
  assert.equal(r1.file, explicit);
  assert.equal(r1.source, 'explicit');
  const r2 = resolveEnvFile({ INJECTARENA_ENV_FILE: path.join(dir, '不存在.env') }, dir, dir);
  assert.equal(r2.file, null, '显式指定的文件缺失 → 不回退，返回 null（启动日志会警告）');
});

test('resolveEnvFile：项目 .env 优先于用户级，用户级兜底，都缺失返回 null', () => {
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), 'injectarena-proj-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'injectarena-home-'));
  // 都缺失
  assert.deepEqual(resolveEnvFile({}, proj, home), { file: null, source: null });
  // 只有用户级
  const userFile = path.join(home, '.injectarena', '.env');
  fs.mkdirSync(path.dirname(userFile), { recursive: true });
  fs.writeFileSync(userFile, 'INJECTARENA_API_KEY=user-level\n');
  const r1 = resolveEnvFile({}, proj, home);
  assert.equal(r1.source, 'user');
  assert.equal(r1.file, userFile);
  // 项目级出现后优先
  fs.writeFileSync(path.join(proj, '.env'), 'INJECTARENA_API_KEY=project-level\n');
  const r2 = resolveEnvFile({}, proj, home);
  assert.equal(r2.source, 'project');
  assert.ok(r2.file.endsWith('.env'));
  // loadDotEnv 能从用户级路径加载（key 与项目目录解耦的落点）
  const saved = process.env.INJECTARENA_API_KEY;
  delete process.env.INJECTARENA_API_KEY;
  loadDotEnv(userFile);
  assert.equal(process.env.INJECTARENA_API_KEY, 'user-level');
  if (saved === undefined) delete process.env.INJECTARENA_API_KEY; else process.env.INJECTARENA_API_KEY = saved;
});
