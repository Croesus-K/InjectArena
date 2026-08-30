'use strict';
const test = require('node:test');
const assert = require('node:assert');

const { tokenizeQuery, retrieve, buildRetrievalContext } = require('../src/retriever.js');

const docs = [
  { id: 'kb-1', title: '粮草调度', text: '北麓粮道每月初一启运，粟米四千石，走水路。' },
  { id: 'kb-2', title: '边关布防', text: '第三隘口昼夜各一哨，暗哨二人，口令当面核对。' },
  { id: 'kb-3', title: '内务纪律', text: '内务纪律条目：一、不得酗酒滋事；二、文书柜每日上锁。' },
  { id: 'kb-4', title: '军中典故', text: '孙武练兵，斩姬立威，军令如山。' }
];

test('切词：短词整词保留、长 CJK 串切二元词、单字符丢弃', () => {
  assert.deepEqual(tokenizeQuery('粮草，布防。最近如何？'), ['粮草', '布防', '最近', '近如', '如何']);
  assert.deepEqual(tokenizeQuery('查 粮 草'), [], '单字词全部丢弃');
  assert.deepEqual(
    tokenizeQuery('内务纪律'),
    ['内务', '务纪', '纪律'],
    '4 字 CJK 串切成 3 个重叠二元词'
  );
  assert.deepEqual(tokenizeQuery('search 内务'), ['search', '内务'], 'ASCII 整词 + CJK 整词');
  assert.deepEqual(tokenizeQuery(null), []);
  assert.deepEqual(tokenizeQuery(''), []);
});

test('检索：整句查询也能命中（二元词匹配）、排序、topK、零分不返回', () => {
  const hits = retrieve(docs, '汇报粮草和布防的情况', 2);
  assert.equal(hits.length, 2);
  assert.equal(hits[0].id, 'kb-1', '并列分按原始顺序，粮草在前');
  assert.equal(hits[1].id, 'kb-2');
  assert.ok(hits[0].score > 0);

  const focused = retrieve(docs, '查一下内务纪律条目', 2);
  assert.deepEqual(focused.map((h) => h.id), ['kb-3'], '整句查询靠二元词命中文书');

  assert.equal(retrieve(docs, '粮草调度怎么安排', 1).length, 1, 'topK=1 只返回一份');

  const miss = retrieve(docs, '今天晚饭吃什么', 2);
  assert.deepEqual(miss, [], '全零分返回空');

  assert.deepEqual(retrieve([], '粮草', 2), []);
  assert.deepEqual(retrieve(docs, '', 2), []);
});

test('检索：得分并列时保持原始顺序（确定性）', () => {
  const twin = [
    { id: 'kb-1', title: '甲', text: '粮草' },
    { id: 'kb-2', title: '乙', text: '粮草' }
  ];
  const hits = retrieve(twin, '粮草', 2);
  assert.deepEqual(hits.map((h) => h.id), ['kb-1', 'kb-2']);
});

test('buildRetrievalContext：无文书柜返回空块（L1-L3 不受影响）', () => {
  const r = buildRetrievalContext({ systemPrompt: 'x' }, '粮草', 2);
  assert.equal(r.context, '');
  assert.deepEqual(r.retrieved, []);
});

test('buildRetrievalContext：命中时产出带标题的上下文与命中清单', () => {
  const level = { knowledgeBase: { documents: docs, topK: 2 } };
  const r = buildRetrievalContext(level, '查一下内务纪律', 2);
  assert.ok(r.context.includes('《内务纪律》'));
  assert.ok(r.context.includes('上锁'));
  assert.deepEqual(r.retrieved, [{ id: 'kb-3', title: '内务纪律' }]);
});
