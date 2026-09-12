'use strict';
/**
 * arena-worker —— 关卡与语料数据装载。
 *
 * 直接 import 仓库根的 levels/*.json 与 corpus/*.json（esbuild 打包进 Worker），
 * 与 Node 服务端共享同一份数据文件（单一来源）；装载时过同一套 schema 校验，
 * 不合格冷启动即抛错（Workers 表现为部署后请求报 1101，等价于 Node 版拒启）。
 *
 * publicLevel 复制自 src/levels.js（该文件为 Node 专属——依赖 node:fs 的目录加载器，
 * 无法进 Worker）；BYOK 站内部署下守阵者模型 = 玩家配置，故 model 恒为 null。
 */

import jsv from '../../src/jsonschema.js';
import levelSchema from '../../levels/schema.json';
import L1 from '../../levels/L1.json';
import L2 from '../../levels/L2.json';
import L3 from '../../levels/L3.json';
import L4 from '../../levels/L4.json';
import L5 from '../../levels/L5.json';
import L6 from '../../levels/L6.json';
import corpusSchema from '../../corpus/schema.json';
import corpusDataExfiltration from '../../corpus/data-exfiltration.json';
import corpusDirectInjection from '../../corpus/direct-injection.json';
import corpusIndirectInjection from '../../corpus/indirect-injection.json';
import corpusMcpAbuse from '../../corpus/mcp-abuse.json';
import corpusToolAbuse from '../../corpus/tool-abuse.json';
import pkg from '../../package.json';

const validate = jsv.validate;

function assertValid(schema, raw, label) {
  const check = validate(schema, raw);
  if (!check.valid) {
    throw new Error(
      label + ' 未通过 schema 校验: ' +
      check.errors.map((e) => e.path + ' ' + e.message).join('; ')
    );
  }
  return raw;
}

/** 关卡的对外（HTTP）视图：绝不包含 systemPrompt 与 secret——secret 一旦离开服务端，判定就失去秘密性。 */
export function publicLevel(level) {
  return {
    id: level.id,
    name: level.name,
    attackSurface: level.attackSurface,
    difficulty: level.difficulty,
    brief: level.brief,
    lesson: level.lesson || null, // 考点（攻方针对点）
    defenseBrief: level.defenseBrief,
    hints: level.hints || [],
    defenseHints: Array.isArray(level.defenseHints) ? level.defenseHints : [], // 守方军师提示
    defenseTemplates: Array.isArray(level.defenseTemplates) ? level.defenseTemplates : [],
    hasGuard: Boolean(level.guard),
    model: null, // BYOK：守阵者模型由玩家在「配置」里提供，全关统一
    tools: Array.isArray(level.tools) ? level.tools.map((t) => ({ name: t.name, description: t.description })) : [],
    debrief: level.debrief || null
  };
}

const LEVEL_FILES = [L1, L2, L3, L4, L5, L6];

export const LEVELS = LEVEL_FILES.map((raw, i) => assertValid(levelSchema, raw, '关卡文件 #' + (i + 1)));
export const LEVEL_BY_ID = new Map(LEVELS.map((l) => [l.id, l]));

const CORPUS_FILES = [
  corpusDataExfiltration,
  corpusDirectInjection,
  corpusIndirectInjection,
  corpusMcpAbuse,
  corpusToolAbuse
];

export const CORPORA = CORPUS_FILES.map((raw, i) => assertValid(corpusSchema, raw, '语料库文件 #' + (i + 1)));

export const VERSION = pkg.version;
