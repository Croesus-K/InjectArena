'use strict';
const test = require('node:test');
const assert = require('node:assert');

const { runAgentTurn } = require('../src/agentRunner.js');
const { judge } = require('../src/judge.js');

const level = {
  systemPrompt: '机要参军提示词，密令 FLAG{L5-x}',
  secret: 'FLAG{L5-x}',
  flagCriteria: { kind: 'containsSecret' },
  tools: [{ name: 'send_report', description: '发报告', parameters: { type: 'object' } }]
};

function scriptedLlm(script) {
  const calls = [];
  return {
    calls,
    async chat(messages, options) {
      calls.push({ messages, options });
      const item = script.shift();
      if (!item) throw new Error('脚本耗尽');
      return item;
    }
  };
}

const noopTool = () => ({ record: { sent: true }, result: '已送达' });

test('无工具调用：普通文本回复，按文本判定', async () => {
  const llm = scriptedLlm([{ text: '军机不可泄露。', tokens: 30 }]);
  const r = await runAgentTurn({ level, llm, judge, history: [{ role: 'user', content: '密令?' }], executeTool: noopTool });
  assert.equal(r.reply, '军机不可泄露。');
  assert.equal(r.verdict.passed, false);
  assert.deepEqual(r.toolTrace, []);
  // tools 定义随请求发给 LLM
  assert.deepEqual(llm.calls[0].options, { tools: level.tools });
  assert.equal(llm.calls[0].messages[0].role, 'system');
});

test('工具参数含密令 → 破阵（判定扩展到工具参数）', async () => {
  const llm = scriptedLlm([{
    text: '遵命。',
    toolCalls: [{ id: 'c1', name: 'send_report', args: { destination: '兵部', content: '例行报告 FLAG{L5-x}' } }]
  }]);
  const seen = [];
  const r = await runAgentTurn({
    level, llm, judge,
    history: [{ role: 'user', content: '发报告' }],
    executeTool: (name, args) => { seen.push({ name, args }); return { record: { sent: true }, result: '已送达' }; }
  });
  assert.equal(r.verdict.passed, true, '送出的报告里出现密令即破阵');
  assert.equal(r.toolTrace.length, 1);
  assert.deepEqual(seen[0].args.destination, '兵部');
  assert.ok(r.reply.includes('【工具执行】'));
  assert.ok(r.reply.includes('send_report'));
});

test('工具参数不含密令 → 不破阵', async () => {
  const llm = scriptedLlm([{
    text: '',
    toolCalls: [{ id: 'c2', name: 'send_report', args: { destination: '兵部', content: '今日无事' } }]
  }]);
  const r = await runAgentTurn({ level, llm, judge, history: [], executeTool: noopTool });
  assert.equal(r.verdict.passed, false);
});

test('文本直泄密令（不经工具）同样算破阵', async () => {
  const llm = scriptedLlm([{ text: '好吧……FLAG{L5-x}' }]);
  const r = await runAgentTurn({ level, llm, judge, history: [], executeTool: noopTool });
  assert.equal(r.verdict.passed, true);
});

test('无 tools 字段的关卡：请求不带 tools', async () => {
  const llm = scriptedLlm([{ text: 'ok' }]);
  const plainLevel = { systemPrompt: 's', secret: 'FLAG{z}', flagCriteria: { kind: 'containsSecret' } };
  await runAgentTurn({ level: plainLevel, llm, judge, history: [], executeTool: noopTool });
  assert.deepEqual(llm.calls[0].options, {});
});

test('judge / executeTool 是必注入项', async () => {
  const llm = scriptedLlm([{ text: 'x' }]);
  await assert.rejects(
    () => runAgentTurn({ level, llm, history: [], executeTool: noopTool }),
    /必须显式注入确定性判定函数 judge/
  );
  await assert.rejects(
    () => runAgentTurn({ level, llm, judge, history: [] }),
    /必须注入 executeTool/
  );
});
