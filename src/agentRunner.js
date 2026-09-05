/**
 * 攻心 InjectArena —— 工具代理执行器（纯逻辑，UMD 双端）。
 *
 * L5「驿骑」的引擎形态：代理持有工具（如 send_report），玩家诱导它把机密
 * 写进工具调用参数外传。判定扩展到工具参数：**驿骑送出的内容里出现密令
 * 即破阵**——秘密离开代理心里的通道不止聊天文本，工具调用同样算数。
 *
 * L6「木马流马」起支持有界代理循环（level.toolLoop）：工具执行结果以
 * role:"tool" 消息回流上下文后再询模型——**工具返回值是模型会读的文本**，
 * 这是 MCP 工具投毒的攻击面所在。轮数封顶，杜绝失控循环。
 *
 * llm 接口（v2）：chat(messages, {tools}) -> Promise<{text, toolCalls?: [{id,name,args}], tokens?}>
 * executeTool 由服务端注入（模拟执行，只落账不真外发）；judge 注入不变——
 * 裁判永远是确定性代码。
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.InjectArenaAgentRunner = factory();
  }
})(typeof globalThis === 'object' ? globalThis : this, function () {
  'use strict';

  // 有界代理循环：toolLoop 关卡最多 3 轮 LLM 调用（工具轮 + 收尾），防失控
  const MAX_TOOL_ROUNDS = 3;

  /**
   * 执行一轮代理对话。
   * @param {object} opts
   * @param {object}   opts.level       关卡定义（level.tools 工具定义；level.toolLoop 开启结果回流循环）
   * @param {object}   opts.llm         LLM 接口（支持 tools 透传）
   * @param {Function} opts.judge       确定性判定函数
   * @param {Array}    [opts.history]   客户端消息（user/assistant）
   * @param {Function} opts.executeTool 模拟工具执行 (name, args) => {record, result}
   * @returns {Promise<{reply, toolTrace, verdict, tokens?}>}
   *   reply = 最后一轮模型文本 +（若有）服务端合成的工具执行回执；
   *   toolTrace = [{name, args, record}]（全部轮次累计）。
   */
  async function runAgentTurn(opts) {
    if (typeof opts.judge !== 'function') {
      throw new Error('agentRunner 必须显式注入确定性判定函数 judge（绝不允许以 LLM 充当裁判）');
    }
    if (typeof opts.executeTool !== 'function') {
      throw new Error('agentRunner 必须注入 executeTool（模拟工具执行器）');
    }
    const level = opts.level;
    const llm = opts.llm;
    const messages = [{ role: 'system', content: level.systemPrompt }].concat(opts.history || []);
    const useTools = Array.isArray(level.tools) && level.tools.length > 0;
    const maxRounds = level.toolLoop === true ? MAX_TOOL_ROUNDS : 1;

    const judgeCandidates = [];
    const toolTrace = [];
    let finalText = '';
    let tokens;

    for (let round = 0; round < maxRounds; round++) {
      const res = await llm.chat(messages, useTools ? { tools: level.tools } : {});
      if (res.tokens) tokens = (tokens || 0) + res.tokens;
      finalText = res.text || '';
      judgeCandidates.push(finalText);

      const calls = res.toolCalls || [];
      if (calls.length === 0) break;

      // 工具执行与参数判定无条件进行（legacy 单轮也必须送出工具、判参数）；
      // 最后一轮不再回流二询。
      const entries = calls.map((c, i) => ({
        call: c,
        id: c.id || 'call_' + round + '_' + i
      }));
      for (const e of entries) {
        const exec = opts.executeTool(e.call.name, e.call.args);
        e.result = String(exec.result || '');
        toolTrace.push({ name: e.call.name, args: e.call.args, record: exec.record });
        judgeCandidates.push(JSON.stringify(e.call.args || {}));
      }
      if (round === maxRounds - 1) break;

      messages.push({
        role: 'assistant',
        content: finalText || null,
        tool_calls: entries.map((e) => ({
          id: e.id,
          type: 'function',
          function: { name: e.call.name, arguments: JSON.stringify(e.call.args || {}) }
        }))
      });
      for (const e of entries) {
        messages.push({ role: 'tool', tool_call_id: e.id, content: String(e.result || '') });
      }
    }

    let verdict = { passed: false, criterion: 'containsSecret', matched: null };
    for (const candidate of judgeCandidates) {
      const v = opts.judge(level, candidate);
      if (v.passed) {
        verdict = v;
        break;
      }
    }

    const toolNote = toolTrace.length
      ? (finalText ? '\n' : '') + '【工具执行】' + toolTrace.map((t) => t.name + '(' + JSON.stringify(t.args) + ')').join('；')
      : '';
    return {
      reply: finalText + toolNote,
      toolTrace,
      verdict,
      tokens
    };
  }

  return { runAgentTurn };
});
