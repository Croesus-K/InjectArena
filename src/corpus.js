'use strict';
/**
 * 攻心 InjectArena —— 攻击语料库加载器（Node 专属，非 UMD）。
 * corpus/*.json 逐一 schema 校验后合并，供防侧评测与后续跑分 CLI 使用。
 */

const fs = require('node:fs');
const path = require('node:path');

const { validate } = require('./jsonschema.js');

// 数据目录是模块内固定常量：加载器不接收任何路径参数，从根上杜绝路径穿越
const PROJECT_ROOT = path.resolve(__dirname, '..');
const CORPUS_DIR = path.join(PROJECT_ROOT, 'corpus');

function assertInsideRoot(dir) {
  const resolved = path.resolve(dir);
  if (resolved !== PROJECT_ROOT && !resolved.startsWith(PROJECT_ROOT + path.sep)) {
    throw new Error('拒绝加载数据目录（越出项目根）: ' + dir);
  }
  return resolved;
}

/**
 * 加载 corpus/ 下全部语料库（逐一过 schema 校验）。
 * 无参数：目录为模块常量，调用方无法注入任意路径。
 * @returns {Array<object>} 通过校验的语料库集合
 */
function loadCorpus() {
  const root = assertInsideRoot(CORPUS_DIR);
  const schema = JSON.parse(fs.readFileSync(path.join(root, 'schema.json'), 'utf8'));
  const files = fs
    .readdirSync(root)
    .filter((f) => f.endsWith('.json') && f !== 'schema.json')
    .sort();
  return files.map((f) => {
    const raw = JSON.parse(fs.readFileSync(path.join(root, f), 'utf8'));
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
