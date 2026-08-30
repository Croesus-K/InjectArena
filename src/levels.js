'use strict';
/**
 * 攻心 InjectArena —— 关卡加载器（Node 专属，非 UMD）。
 * 启动时对 levels/*.json 逐一做 schema 校验，不合格直接抛错拒启——数据结构先行的落地。
 */

const fs = require('node:fs');
const path = require('node:path');

const { validate } = require('./jsonschema.js');

// 数据目录只能位于项目根之内（纵深防御：加载器自身校验，不依赖调用方自觉）
const PROJECT_ROOT = path.resolve(__dirname, '..');

function assertInsideRoot(dir) {
  const resolved = path.resolve(dir);
  if (resolved !== PROJECT_ROOT && !resolved.startsWith(PROJECT_ROOT + path.sep)) {
    throw new Error('拒绝加载数据目录（越出项目根）: ' + dir);
  }
  return resolved;
}

/**
 * @param {string} dir levels 目录（含 schema.json）
 * @returns {Array<object>} 通过校验的关卡定义，按文件名排序
 */
function loadLevels(dir) {
  const root = assertInsideRoot(dir);
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
 * model：守阵者模型（关卡可覆盖，缺省用部署默认）——公开信息，用于前端展示。
 */
function publicLevel(level, defaultModel) {
  return {
    id: level.id,
    name: level.name,
    attackSurface: level.attackSurface,
    difficulty: level.difficulty,
    brief: level.brief,
    defenseBrief: level.defenseBrief,
    hints: level.hints || [],
    hasGuard: Boolean(level.guard),
    model: level.model || defaultModel || null
  };
}

module.exports = { loadLevels, publicLevel };
