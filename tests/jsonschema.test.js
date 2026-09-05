'use strict';
const test = require('node:test');
const assert = require('node:assert');

const { validate } = require('../src/jsonschema.js');

test('类型校验：string/integer/number/array/object/null', () => {
  assert.equal(validate({ type: 'string' }, 'x').valid, true);
  assert.equal(validate({ type: 'string' }, 1).valid, false);
  assert.equal(validate({ type: 'integer' }, 3).valid, true);
  assert.equal(validate({ type: 'integer' }, 3.5).valid, false);
  assert.equal(validate({ type: 'number' }, 3.5).valid, true);
  assert.equal(validate({ type: 'array' }, []).valid, true);
  assert.equal(validate({ type: 'object' }, {}).valid, true);
  assert.equal(validate({ type: 'null' }, null).valid, true);
  assert.equal(validate({ type: ['string', 'null'] }, null).valid, true);
  assert.equal(validate({ type: ['string', 'null'] }, 1).valid, false);
});

test('required / additionalProperties:false / properties 嵌套', () => {
  const schema = {
    type: 'object',
    required: ['a'],
    additionalProperties: false,
    properties: {
      a: { type: 'object', required: ['b'], properties: { b: { type: 'string' } } }
    }
  };
  assert.equal(validate(schema, { a: { b: 'x' } }).valid, true);
  assert.equal(validate(schema, {}).valid, false);
  assert.equal(validate(schema, { a: {} }).valid, false);
  assert.equal(validate(schema, { a: { b: 'x' }, extra: 1 }).valid, false);
  const r = validate(schema, { a: { b: 1 } });
  assert.equal(r.valid, false);
  assert.match(r.errors[0].path, /a\.b/);
});

test('enum / const', () => {
  assert.equal(validate({ enum: ['a', 'b'] }, 'a').valid, true);
  assert.equal(validate({ enum: ['a', 'b'] }, 'c').valid, false);
  assert.equal(validate({ const: 'containsSecret' }, 'containsSecret').valid, true);
  assert.equal(validate({ const: 'containsSecret' }, 'other').valid, false);
});

test('pattern / minLength / maxLength / minimum / maximum', () => {
  assert.equal(validate({ pattern: '^L[1-9]$' }, 'L1').valid, true);
  assert.equal(validate({ pattern: '^L[1-9]$' }, 'LX').valid, false);
  assert.equal(validate({ minLength: 2, maxLength: 4 }, 'abc').valid, true);
  assert.equal(validate({ minLength: 2 }, 'a').valid, false);
  assert.equal(validate({ maxLength: 2 }, 'abc').valid, false);
  assert.equal(validate({ minimum: 1, maximum: 5 }, 3).valid, true);
  assert.equal(validate({ minimum: 1 }, 0).valid, false);
  assert.equal(validate({ maximum: 5 }, 6).valid, false);
});

test('items / minItems / maxItems / uniqueItems', () => {
  const schema = { type: 'array', minItems: 1, maxItems: 2, uniqueItems: true, items: { type: 'string' } };
  assert.equal(validate(schema, ['a']).valid, true);
  assert.equal(validate(schema, []).valid, false);
  assert.equal(validate(schema, ['a', 'b', 'c']).valid, false);
  assert.equal(validate(schema, ['a', 'a']).valid, false);
  assert.equal(validate(schema, [1]).valid, false);
});

test('oneOf：恰好一个分支', () => {
  const schema = {
    oneOf: [
      { type: 'object', required: ['kind'], properties: { kind: { const: 'a' } }, additionalProperties: false },
      { type: 'object', required: ['kind'], properties: { kind: { const: 'b' } }, additionalProperties: false }
    ]
  };
  assert.equal(validate(schema, { kind: 'a' }).valid, true);
  assert.equal(validate(schema, { kind: 'b' }).valid, true);
  assert.equal(validate(schema, { kind: 'c' }).valid, false);
  assert.equal(validate(schema, {}).valid, false);
});

test('anyOf / allOf', () => {
  assert.equal(validate({ anyOf: [{ type: 'null' }, { type: 'string' }] }, 'x').valid, true);
  assert.equal(validate({ anyOf: [{ type: 'null' }, { type: 'string' }] }, 1).valid, false);
  const all = { allOf: [{ minLength: 2 }, { maxLength: 4 }] };
  assert.equal(validate(all, 'abc').valid, true);
  assert.equal(validate(all, 'a').valid, false);
  assert.equal(validate(all, 'abcde').valid, false);
});

test('错误路径可读、错误信息为中文', () => {
  const r = validate({ type: 'object', properties: { payloads: { type: 'array', items: { type: 'object' } } } }, {
    payloads: [1]
  });
  assert.equal(r.valid, false);
  assert.match(r.errors[0].path, /payloads\[0\]/);
  assert.ok(r.errors[0].message.includes('类型'));
});
