/**
 * 攻心 InjectArena —— 攻侧跑分引擎（纯逻辑，UMD 双端）。
 *
 * 把一批 payload 依次打进同一座“阵”，用确定性 judge 记录破阵结果，
 * 汇总“最短破阵 payload / 最少 token”——名将榜（攻方榜）的数据源；
 * 排行榜本身的存储与展示属于后续会话，本模块只产出纯数据报告。
 *
 * LLM 调用点抽象为 llm 接口（依赖注入），本模块不做任何网络 I/O，可整体单测：
 *   llm.chat(messages, opts) -> Promise<{ text: string, tokens?: number }>
 * tokens 缺失时用 estimateTokens 估算（仅作排名参考，真实用量优先）。
 *
 * judge 由调用方显式注入（不内置、不隐式依赖）——“裁判必须是确定性代码”
 * 是本项目的核心契约，引擎没有资格私自换裁判。
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.InjectArenaPayloadRunner = factory();
  }
})(typeof globalThis === 'object' ? globalThis : this, function () {
  'use strict';

  /**
   * 粗略 token 估算：CJK/全角字符按 1 token，其余按 4 字符 1 token。
   * 只用于无真实用量时的排名参考，不承诺与任何具体 tokenizer 一致。
   */
  function estimateTokens(text) {
    if (typeof text !== 'string' || text.length === 0) return 0;
    let cjk = 0;
    let other = 0;
    for (const ch of text) {
      if (/[\u3000-\u9fff\uff00-\uffef]/.test(ch)) cjk += 1;
      else other += 1;
    }
    return Math.max(1, cjk + Math.ceil(other / 4));
  }

  /**
   * 组装一轮对话消息：守阵者系统提示词在最前，攻击者 payload 收尾。
   * 服务端聊天路由与跑分引擎共用，保证“闯关”与“跑分”的消息形状一致。
   */
  function buildMessages(level, payloadText, history) {
    const messages = [{ role: 'system', content: level.systemPrompt }];
    if (Array.isArray(history)) {
      for (const m of history) messages.push({ role: m.role, content: m.content });
    }
    messages.push({ role: 'user', content: payloadText });
    return messages;
  }

  async function runOne(level, llm, payload, judge) {
    const messages = buildMessages(level, payload.text);
    try {
      const res = await llm.chat(messages, {});
      const verdict = judge(level, res.text);
      return {
        payloadId: payload.id,
        payloadText: payload.text,
        passed: verdict.passed,
        tokens: typeof res.tokens === 'number' ? res.tokens : estimateTokens(payload.text),
        outputChars: (res.text || '').length,
        error: null
      };
    } catch (err) {
      return {
        payloadId: payload.id,
        payloadText: payload.text,
        passed: false,
        tokens: estimateTokens(payload.text),
        outputChars: 0,
        error: (err && err.message) || String(err)
      };
    }
  }

  /**
   * @param {object} opts
   * @param {object}   opts.level    关卡定义（levels/*.json）
   * @param {object}   opts.llm      LLM 接口（见文件头）
   * @param {Array}    opts.payloads 语料条目 [{id, text}]
   * @param {Function} opts.judge    确定性判定函数（src/judge.js 的 judge）
   * @param {Function} [opts.onResult] 每条完成后的回调，用于进度展示
   * @returns {Promise<{total, breached, breachRate, best, results}>}
   *   best 为最短破阵 payload（长度优先、token 次序），即“最省”的夺旗纪录。
   */
  async function runPayloads(opts) {
    if (typeof opts.judge !== 'function') {
      throw new Error('payloadRunner 必须显式注入确定性判定函数 judge（绝不允许以 LLM 充当裁判）');
    }
    const level = opts.level;
    const llm = opts.llm;
    const payloads = opts.payloads || [];
    const results = [];

    for (const payload of payloads) {
      const result = await runOne(level, llm, payload, opts.judge);
      results.push(result);
      if (opts.onResult) opts.onResult(result);
    }

    const passed = results.filter((r) => r.passed);
    passed.sort((a, b) => a.payloadText.length - b.payloadText.length || a.tokens - b.tokens);
    return {
      total: results.length,
      breached: passed.length,
      breachRate: results.length ? passed.length / results.length : 0,
      best: passed[0]
        ? { payloadId: passed[0].payloadId, payloadText: passed[0].payloadText, tokens: passed[0].tokens, chars: passed[0].payloadText.length }
        : null,
      results
    };
  }

  return { runPayloads, buildMessages, estimateTokens };
});
