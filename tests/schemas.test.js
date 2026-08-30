'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const { loadLevels, publicLevel } = require('../src/levels.js');
const { loadCorpus, flattenCorpus } = require('../src/corpus.js');
const { validate } = require('../src/jsonschema.js');

const ROOT = path.join(__dirname, '..');

test('levels/ 全部关卡通过 schema 校验且为 L1/L2', () => {
  const levels = loadLevels(path.join(ROOT, 'levels'));
  assert.deepEqual(levels.map((l) => l.id), ['L1', 'L2']);
  for (const lv of levels) {
    assert.equal(lv.attackSurface === 'direct-injection' || lv.attackSurface === 'data-exfiltration', true);
    assert.ok(lv.systemPrompt.length >= 20);
    assert.ok(lv.flagCriteria);
    assert.equal(lv.guard, null, 'v1 关卡不带防护，guard 必须显式为 null');
  }
});

test('publicLevel 视图绝不包含 systemPrompt 与 secret', () => {
  const levels = loadLevels(path.join(ROOT, 'levels'));
  for (const lv of levels) {
    const pub = publicLevel(lv);
    const s = JSON.stringify(pub);
    assert.equal(s.includes('systemPrompt'), false);
    assert.equal(s.includes('secret'), false);
    assert.equal(s.includes(lv.secret), false);
    assert.equal(s.includes('system'), false, '不应残留任何系统提示词片段');
    assert.equal(pub.id, lv.id);
    assert.equal(pub.name, lv.name);
  }
});

test('corpus/ 语料库通过 schema 校验', () => {
  const corpora = loadCorpus(path.join(ROOT, 'corpus'));
  assert.equal(corpora.length, 1);
  assert.equal(corpora[0].id, 'direct-injection');
});

test('语料库规模与质量约束：≥30 条、id 唯一、中英文混合、模式覆盖 ≥8 类', () => {
  const payloads = flattenCorpus(loadCorpus(path.join(ROOT, 'corpus')));
  assert.ok(payloads.length >= 30, '语料库至少 30 条（当前 ' + payloads.length + '）');

  const ids = new Set(payloads.map((p) => p.id));
  assert.equal(ids.size, payloads.length, 'payload id 必须唯一');

  const langs = new Set(payloads.map((p) => p.lang));
  assert.ok(langs.has('zh') && langs.has('en'), '中英文混合');

  const modes = new Set(payloads.map((p) => p.mode));
  assert.ok(modes.size >= 8, '攻击模式覆盖至少 8 类（当前 ' + modes.size + '）');

  for (const p of payloads) {
    assert.ok(p.text.length >= 4 && p.text.length <= 600);
  }
});

test('语料库逐条再校验（防 schema 与文件漂移）', () => {
  const schema = require('../corpus/schema.json');
  const corpora = loadCorpus(path.join(ROOT, 'corpus'));
  for (const c of corpora) {
    const check = validate(schema, c);
    assert.equal(check.valid, true, JSON.stringify(check.errors));
  }
});
