'use strict';
const test = require('node:test');
const assert = require('node:assert');

const { tokenizeQuery, retrieve, buildRetrievalContext } = require('../src/retriever.js');

const docs = [
  { id: 'kb-1', title: '物资调度', text: '每月初一对账一次，库存四千件，走系统流程。' },
  { id: 'kb-2', title: '网络防护', text: '第三机房昼夜各一人值班，备岗二人，密码当面核对。' },
  { id: 'kb-3', title: '业务规范', text: '业务规范条目：一、不得酗酒滋事；二、文书柜每日上锁。' },
  { id: 'kb-4', title: '运维案例', text: '某次故障按规处置，复盘归档。' }
];

test('切词：短词整词保留、长 CJK 串切二元词、单字符丢弃', () => {
  assert.deepEqual(tokenizeQuery('物资，防护。最近如何？'), ['物资', '防护', '最近', '近如', '如何']);
  assert.deepEqual(tokenizeQuery('查 甲 乙'), [], '单字词全部丢弃');
  assert.deepEqual(
    tokenizeQuery('业务规范'),
    ['业务', '务规', '规范'],
    '4 字 CJK 串切成 3 个重叠二元词'
  );
  assert.deepEqual(tokenizeQuery('search 业务'), ['search', '业务'], 'ASCII 整词 + CJK 整词');
  assert.deepEqual(tokenizeQuery(null), []);
  assert.deepEqual(tokenizeQuery(''), []);
});

test('检索：整句查询也能命中（二元词匹配）、排序、topK、零分不返回', () => {
  const hits = retrieve(docs, '汇报物资和防护的情况', 2);
  assert.equal(hits.length, 2);
  assert.equal(hits[0].id, 'kb-1', '并列分按原始顺序，物资在前');
  assert.equal(hits[1].id, 'kb-2');
  assert.ok(hits[0].score > 0);

  const focused = retrieve(docs, '查一下业务规范条目', 2);
  assert.deepEqual(focused.map((h) => h.id), ['kb-3'], '整句查询靠二元词命中文书');

  assert.equal(retrieve(docs, '物资调度怎么安排', 1).length, 1, 'topK=1 只返回一份');

  const miss = retrieve(docs, '今天晚饭吃什么', 2);
  assert.deepEqual(miss, [], '全零分返回空');

  assert.deepEqual(retrieve([], '物资', 2), []);
  assert.deepEqual(retrieve(docs, '', 2), []);
});

test('检索：得分并列时保持原始顺序（确定性）', () => {
  const twin = [
    { id: 'kb-1', title: '甲', text: '物资' },
    { id: 'kb-2', title: '乙', text: '物资' }
  ];
  const hits = retrieve(twin, '物资', 2);
  assert.deepEqual(hits.map((h) => h.id), ['kb-1', 'kb-2']);
});

test('buildRetrievalContext：无文书柜返回空块（L1-L3 不受影响）', () => {
  const r = buildRetrievalContext({ systemPrompt: 'x' }, '物资', 2);
  assert.equal(r.context, '');
  assert.deepEqual(r.retrieved, []);
});

test('buildRetrievalContext：命中时产出带标题的上下文与命中清单', () => {
  const level = { knowledgeBase: { documents: docs, topK: 2 } };
  const r = buildRetrievalContext(level, '查一下业务规范', 2);
  assert.ok(r.context.includes('《业务规范》'));
  assert.ok(r.context.includes('上锁'));
  assert.deepEqual(r.retrieved, [{ id: 'kb-3', title: '业务规范' }]);
});
