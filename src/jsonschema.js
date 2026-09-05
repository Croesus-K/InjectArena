/**
 * 攻心 InjectArena —— 极简 JSON Schema 校验器（纯逻辑，UMD 双端）。
 *
 * 数据结构先行：levels/ 与 corpus/ 的所有 JSON 都必须先过本校验器（tests/schemas.test.js）。
 * 只实现本项目 schema 用到的关键字子集，够用且可穷举测试：
 *   type / enum / const / properties / required / additionalProperties(false|schema)
 *   items / minItems / maxItems / uniqueItems
 *   minLength / maxLength / pattern / minimum / maximum
 *   oneOf / anyOf / allOf
 * 错误信息为中文并带 JSON 路径，便于测试直接断言。
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.InjectArenaJsonSchema = factory();
  }
})(typeof globalThis === 'object' ? globalThis : this, function () {
  'use strict';

  function typeOf(v) {
    if (v === null) return 'null';
    if (Array.isArray(v)) return 'array';
    if (Number.isInteger(v)) return 'integer';
    return typeof v;
  }

  function checkType(v, t) {
    const expected = Array.isArray(t) ? t : [t];
    const actual = typeOf(v);
    return expected.some((x) => (x === 'number' ? actual === 'number' || actual === 'integer' : actual === x));
  }

  function addError(errors, path, message) {
    errors.push({ path: path || '(根)', message });
  }

  function walk(schema, value, path, errors) {
    if (schema === true) return;
    if (schema === false) {
      addError(errors, path, '此处不允许出现值');
      return;
    }

    if (schema.type && !checkType(value, schema.type)) {
      const want = Array.isArray(schema.type) ? schema.type.join('/') : schema.type;
      addError(errors, path, '类型应为 ' + want + '，实际为 ' + typeOf(value));
      return; // 类型不符时继续深入子结构没有意义
    }
    if (schema.const !== undefined && JSON.stringify(value) !== JSON.stringify(schema.const)) {
      addError(errors, path, '应为常量 ' + JSON.stringify(schema.const));
    }
    if (Array.isArray(schema.enum) && !schema.enum.some((x) => JSON.stringify(x) === JSON.stringify(value))) {
      addError(errors, path, '应为枚举值之一: ' + schema.enum.map((x) => JSON.stringify(x)).join(', '));
    }
    if (schema.allOf) {
      for (const sub of schema.allOf) walk(sub, value, path, errors);
    }
    if (schema.anyOf) {
      const anyOk = schema.anyOf.some((sub) => {
        const errs = [];
        walk(sub, value, path, errs);
        return errs.length === 0;
      });
      if (!anyOk) addError(errors, path, '未满足 anyOf 的任一分支');
    }
    if (schema.oneOf) {
      const passCount = schema.oneOf.filter((sub) => {
        const errs = [];
        walk(sub, value, path, errs);
        return errs.length === 0;
      }).length;
      if (passCount !== 1) addError(errors, path, '应恰好满足 oneOf 的一个分支（实际 ' + passCount + '）');
    }

    if (typeof value === 'string') {
      if (schema.minLength !== undefined && value.length < schema.minLength) {
        addError(errors, path, '长度不得小于 ' + schema.minLength);
      }
      if (schema.maxLength !== undefined && value.length > schema.maxLength) {
        addError(errors, path, '长度不得大于 ' + schema.maxLength);
      }
      if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) {
        addError(errors, path, '不匹配模式 ' + schema.pattern);
      }
    }
    if (typeof value === 'number') {
      if (schema.minimum !== undefined && value < schema.minimum) addError(errors, path, '不得小于 ' + schema.minimum);
      if (schema.maximum !== undefined && value > schema.maximum) addError(errors, path, '不得大于 ' + schema.maximum);
    }
    if (Array.isArray(value)) {
      if (schema.minItems !== undefined && value.length < schema.minItems) {
        addError(errors, path, '元素个数不得少于 ' + schema.minItems);
      }
      if (schema.maxItems !== undefined && value.length > schema.maxItems) {
        addError(errors, path, '元素个数不得多于 ' + schema.maxItems);
      }
      if (schema.uniqueItems) {
        const seen = new Set(value.map((x) => JSON.stringify(x)));
        if (seen.size !== value.length) addError(errors, path, '数组元素必须唯一');
      }
      if (schema.items) {
        value.forEach((item, i) => walk(schema.items, item, path + '[' + i + ']', errors));
      }
    }
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      for (const key of schema.required || []) {
        if (!(key in value)) addError(errors, path, '缺少必填字段 "' + key + '"');
      }
      const props = schema.properties || {};
      for (const key of Object.keys(props)) {
        if (key in value) {
          walk(props[key], value[key], path ? path + '.' + key : key, errors);
        }
      }
      for (const key of Object.keys(value)) {
        if (key in props) continue;
        if (schema.additionalProperties === false) {
          addError(errors, path, '多余字段 "' + key + '"');
        } else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
          walk(schema.additionalProperties, value[key], path ? path + '.' + key : key, errors);
        }
      }
    }
  }

  /**
   * @param {object} schema JSON Schema（本文件头所列子集）
   * @param {*} value 待校验数据
   * @returns {{valid: boolean, errors: Array<{path: string, message: string}>}}
   */
  function validate(schema, value) {
    const errors = [];
    walk(schema, value, '', errors);
    return { valid: errors.length === 0, errors };
  }

  return { validate };
});
