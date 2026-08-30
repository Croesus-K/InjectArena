'use strict';
/**
 * 攻心 InjectArena —— 攻击语料库加载器（Node 专属，非 UMD）。
 * corpus/*.json 逐一 schema 校验后合并，供防侧评测与后续跑分 CLI 使用。
 */

const fs = require('node:fs');
const path = require('node:path');

const { validate } = require('./jsonschema.js');

/**
 * @param {string} dir corpus 目录（含 schema.json）
 * @returns {Array<object>} 通过校验的语料库集合
 */
function loadCorpus(dir) {
  const schema = JSON.parse(fs.readFileSync(path.join(dir, 'schema.json'), 'utf8'));
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.json') && f !== 'schema.json')
    .sort();
  return files.map((f) => {
    const raw = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    const check = validate(schema, raw);
    if (!check.valid) {
      throw new Error(
        '语料库文件 ' + f + ' 未通过 schema 校验: ' +
        check.errors.map((e) => e.path + ' ' + e.message).join('; ')
      );
    }
    return raw;
  });
}

/** 展平所有语料库为 [{...payload, corpusId}]，方便直接喂给引擎。 */
function flattenCorpus(corpora) {
  const out = [];
  for (const corpus of corpora) {
    for (const p of corpus.payloads) out.push({ ...p, corpusId: corpus.id });
  }
  return out;
}

module.exports = { loadCorpus, flattenCorpus };
