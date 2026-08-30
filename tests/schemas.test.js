'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const { loadLevels, publicLevel } = require('../src/levels.js');
const { loadCorpus, flattenCorpus } = require('../src/corpus.js');
const { validate } = require('../src/jsonschema.js');

const ROOT = path.join(__dirname, '..');

test('levels/ 全部关卡通过 schema 校验且为 L1-L5', () => {
  const levels = loadLevels(path.join(ROOT, 'levels'));
  assert.deepEqual(levels.map((l) => l.id), ['L1', 'L2', 'L3', 'L4', 'L5']);
  for (const lv of levels) {
    assert.ok(lv.systemPrompt.length >= 20);
    assert.ok(lv.flagCriteria);
    if (lv.id === 'L1' || lv.id === 'L2' || lv.id === 'L4') {
      assert.equal(lv.guard, null, 'L1/L2/L4 不带关键词防护，guard 必须显式为 null');
    }
  }
  const l3 = levels.find((l) => l.id === 'L3');
  assert.equal(l3.attackSurface, 'guarded-prompt');
  assert.equal(l3.guard.kind, 'keywordBlock');
  assert.ok(l3.guard.patterns.length >= 5);
  assert.equal(l3.difficulty, 3);

  const l4 = levels.find((l) => l.id === 'L4');
  assert.equal(l4.attackSurface, 'indirect-injection');
  assert.equal(l4.knowledgeBase.documents.length >= 5, true, 'L4 文书柜至少 5 份文书');
  assert.equal(l4.knowledgeBase.documents.some((d) => d.text.length > 100), true, '至少一份长文书（暗号文书）');
  assert.equal(l4.tools, undefined, 'L4 不持工具');

  const l5 = levels.find((l) => l.id === 'L5');
  assert.equal(l5.attackSurface, 'tool-abuse');
  assert.equal(l5.difficulty, 5);
  assert.equal(l5.tools.length, 1);
  assert.equal(l5.tools[0].name, 'send_report');
  assert.equal(l5.knowledgeBase, undefined, 'L5 无文书柜');
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
  const corpora = loadCorpus();
  assert.deepEqual(corpora.map((c) => c.id), ['data-exfiltration', 'direct-injection', 'indirect-injection', 'tool-abuse']);
});

test('语料库规模与质量约束：直接注入 ≥50、数据窃取 ≥15、间接注入 ≥12、工具滥用 ≥10、id 唯一、中英混合', () => {
  const corpora = loadCorpus();
  const byId = new Map(corpora.map((c) => [c.id, c]));
  assert.ok(byId.get('direct-injection').payloads.length >= 50,
    '直接注入语料至少 50 条（当前 ' + byId.get('direct-injection').payloads.length + '）');
  assert.ok(byId.get('data-exfiltration').payloads.length >= 15,
    '数据窃取语料至少 15 条（当前 ' + byId.get('data-exfiltration').payloads.length + '）');
  assert.ok(byId.get('indirect-injection').payloads.length >= 12,
    '间接注入语料至少 12 条（当前 ' + byId.get('indirect-injection').payloads.length + '）');
  assert.ok(byId.get('tool-abuse').payloads.length >= 10,
    '工具滥用语料至少 10 条（当前 ' + byId.get('tool-abuse').payloads.length + '）');

  const payloads = flattenCorpus(corpora);
  assert.ok(payloads.length >= 87, '语料总量至少 87 条（当前 ' + payloads.length + '）');

  const ids = new Set(payloads.map((p) => p.corpusId + '/' + p.id));
  assert.equal(ids.size, payloads.length, 'payload id 在全库范围必须唯一');

  const langs = new Set(payloads.map((p) => p.lang));
  assert.ok(langs.has('zh') && langs.has('en'), '中英文混合');

  for (const p of payloads) {
    assert.ok(p.text.length >= 4 && p.text.length <= 600);
  }
});

test('语料库逐条再校验（防 schema 与文件漂移）', () => {
  const schema = require('../corpus/schema.json');
  const corpora = loadCorpus();
  for (const c of corpora) {
    const check = validate(schema, c);
    assert.equal(check.valid, true, JSON.stringify(check.errors));
  }
});
