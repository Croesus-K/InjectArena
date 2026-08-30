'use strict';
/**
 * 攻心 InjectArena —— 关卡加载器（Node 专属，非 UMD）。
 * 启动时对 levels/*.json 逐一做 schema 校验，不合格直接抛错拒启——数据结构先行的落地。
 */

const fs = require('node:fs');
const path = require('node:path');

const { validate } = require('./jsonschema.js');

/**
 * @param {string} dir levels 目录（含 schema.json）
 * @returns {Array<object>} 通过校验的关卡定义，按文件名排序
 */
function loadLevels(dir) {
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
        '关卡文件 ' + f + ' 未通过 schema 校验: ' +
        check.errors.map((e) => e.path + ' ' + e.message).join('; ')
      );
    }
    return raw;
  });
}

/**
 * 关卡的对外（HTTP）视图：绝不包含 systemPrompt 与 secret——
 * secret 一旦离开服务端，判定就失去了秘密性。
 */
function publicLevel(level) {
  return {
    id: level.id,
    name: level.name,
    attackSurface: level.attackSurface,
    difficulty: level.difficulty,
    brief: level.brief,
    defenseBrief: level.defenseBrief,
    hints: level.hints || [],
    hasGuard: Boolean(level.guard)
  };
}

module.exports = { loadLevels, publicLevel };
