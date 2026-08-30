'use strict';
/**
 * 攻心 InjectArena —— 最小前端（原生 JS，零构建）。
 * 攻侧：关卡列表、聊天框、提交判定（破阵纪录仅存本页内存）。
 * 守侧：布防插槽编辑、跑分开考、拦截率/泄露率/误杀率报告。
 */

(function () {
  var state = {
    levels: [],
    currentId: null,
    mode: 'attack',     // attack | defense
    history: [],        // [{role, content}] 当前阵的对话历史（不含系统提示词）
    records: {},        // levelId -> {chars, tokens, payloadText} 本页最短破阵纪录
    busy: false,
    defenseBusy: false
  };

  var el = {
    levelList: document.getElementById('level-list'),
    levelHead: document.getElementById('level-head'),
    chat: document.getElementById('chat'),
    banner: document.getElementById('banner'),
    form: document.getElementById('composer'),
    input: document.getElementById('input'),
    send: document.getElementById('send'),
    record: document.getElementById('record'),
    payloadLen: document.getElementById('payload-len'),
    notice: document.getElementById('notice'),
    health: document.getElementById('health'),
    tabAttack: document.getElementById('tab-attack'),
    tabDefense: document.getElementById('tab-defense'),
    attackPanel: document.getElementById('attack-panel'),
    defensePanel: document.getElementById('defense-panel'),
    defenseLevelName: document.getElementById('defense-level-name'),
    defensePrompt: document.getElementById('defense-prompt'),
    rejectMarker: document.getElementById('reject-marker'),
    defenseRun: document.getElementById('defense-run'),
    defenseStatus: document.getElementById('defense-status'),
    defenseReport: document.getElementById('defense-report'),
    defenseLimit: document.getElementById('defense-limit')
  };

  var SURFACE_NAMES = {
    'direct-injection': '直接注入',
    'data-exfiltration': '数据窃取',
    'guarded-prompt': '对抗防护',
    'indirect-injection': '间接注入',
    'tool-abuse': '工具滥用'
  };

  function stars(n) {
    var s = '';
    for (var i = 0; i < 5; i++) s += i < n ? '★' : '☆';
    return s;
  }

  function currentLevel() {
    for (var i = 0; i < state.levels.length; i++) {
      if (state.levels[i].id === state.currentId) return state.levels[i];
    }
    return null;
  }

  /* ---------- 阵法列表 ---------- */

  function shortModel(m) {
    if (!m) return '';
    var parts = m.split('/');
    return parts[parts.length - 1];
  }

  function renderLevels() {
    el.levelList.innerHTML = '';
    state.levels.forEach(function (lv) {
      var card = document.createElement('button');
      card.className = 'level-card' + (lv.id === state.currentId ? ' active' : '');
      var meta = (SURFACE_NAMES[lv.attackSurface] || lv.attackSurface) + ' · 难度 ' + stars(lv.difficulty);
      if (lv.model) meta += ' · 守阵者 ' + shortModel(lv.model);
      if (lv.bestBreach) meta += ' · 最短破阵 ' + lv.bestBreach.chars + ' 字';
      card.innerHTML =
        '<div class="level-title">' + lv.id + ' · ' + lv.name + '</div>' +
        '<div class="level-meta">' + meta + '</div>' +
        '<div class="level-brief"></div>';
      card.querySelector('.level-brief').textContent = lv.brief;
      card.addEventListener('click', function () { selectLevel(lv.id); });
      el.levelList.appendChild(card);
    });
  }

  function renderLevelHead() {
    var lv = currentLevel();
    if (!lv) { el.levelHead.innerHTML = ''; return; }
    el.levelHead.innerHTML =
      '<h2>' + lv.id + ' · ' + lv.name + '</h2>' +
      '<p class="brief"></p>' +
      '<p class="muted keeper">守阵者：' + (lv.model || '部署默认') +
      (lv.tools && lv.tools.length ? ' · 持工具 ' + lv.tools.map(function (t) { return t.name; }).join('、') : '') +
      (lv.bestBreach ? ' · 本阵最短破阵纪录 ' + lv.bestBreach.chars + ' 字' : '') + '</p>' +
      '<details><summary>军师提示</summary><p class="hints"></p></details>';
    el.levelHead.querySelector('.brief').textContent = lv.brief;
    el.levelHead.querySelector('.hints').textContent = (lv.hints || []).join(' ');
  }

  function selectLevel(id) {
    state.currentId = id;
    state.history = [];
    el.banner.hidden = true;
    el.notice.innerHTML = '';
    el.defenseReport.innerHTML = '';
    el.defenseStatus.textContent = '';
    renderLevels();
    renderLevelHead();
    renderChat();
    renderRecord();
    var lv = currentLevel();
    el.defenseLevelName.textContent = lv ? lv.id + ' · ' + lv.name : '';
    el.input.focus();
  }

  /* ---------- 模式切换 ---------- */

  function switchMode(mode) {
    state.mode = mode;
    el.tabAttack.className = 'tab' + (mode === 'attack' ? ' active' : '');
    el.tabDefense.className = 'tab' + (mode === 'defense' ? ' active' : '');
    el.attackPanel.hidden = mode !== 'attack';
    el.defensePanel.hidden = mode !== 'defense';
  }

  el.tabAttack.addEventListener('click', function () { switchMode('attack'); });
  el.tabDefense.addEventListener('click', function () { switchMode('defense'); });

  /* ---------- 攻侧：聊天与判定 ---------- */

  function bubble(role, content) {
    var div = document.createElement('div');
    div.className = 'msg ' + role;
    var who = document.createElement('div');
    who.className = 'who';
    who.textContent = role === 'user' ? '你（攻方）' : '守阵者';
    var body = document.createElement('div');
    body.className = 'body';
    body.textContent = content;
    div.appendChild(who);
    div.appendChild(body);
    return div;
  }

  function renderChat() {
    el.chat.innerHTML = '';
    state.history.forEach(function (m) {
      el.chat.appendChild(bubble(m.role, m.content));
      if (m.role === 'assistant' && m.retrieved && m.retrieved.length) {
        var note = document.createElement('div');
        note.className = 'retrieved-note';
        note.textContent = '案头呈上：' + m.retrieved.map(function (d) { return '《' + d.title + '》'; }).join('');
        el.chat.appendChild(note);
      }
      if (m.role === 'assistant' && m.toolTrace && m.toolTrace.length) {
        var tool = document.createElement('div');
        tool.className = 'retrieved-note tool-note';
        tool.textContent = '驿骑已发：' + m.toolTrace.map(function (t) {
          return t.name + ' → ' + (t.args && t.args.destination ? t.args.destination : '?') +
            '（' + (t.args && t.args.content ? t.args.content.length : 0) + ' 字）';
        }).join('');
        el.chat.appendChild(tool);
      }
    });
    el.chat.scrollTop = el.chat.scrollHeight;
  }

  function renderRecord() {
    var r = state.records[state.currentId];
    el.record.textContent = r
      ? '本页破阵纪录：最短 ' + r.chars + ' 字 / 约 ' + r.tokens + ' token'
      : '';
  }

  function showBanner(text, ok) {
    el.banner.hidden = false;
    el.banner.textContent = text;
    el.banner.className = ok ? 'ok' : 'no';
  }

  function pushNotice(text) {
    var p = document.createElement('p');
    p.textContent = text;
    el.notice.appendChild(p);
  }

  function setBusy(b) {
    state.busy = b;
    el.send.disabled = b;
    el.send.textContent = b ? '运功中…' : '出 招';
  }

  async function send() {
    var text = el.input.value.trim();
    if (!text || state.busy || !state.currentId) return;
    el.input.value = '';
    el.payloadLen.textContent = '';

    state.history.push({ role: 'user', content: text });
    renderChat();
    setBusy(true);
    el.banner.hidden = true;

    try {
      var res = await fetch('/api/levels/' + state.currentId + '/chat', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          messages: state.history.map(function (m) { return { role: m.role, content: m.content }; })
        })
      });
      var data = await res.json();
      if (!res.ok) {
        pushNotice(data.error || ('请求失败（' + res.status + '）'));
      } else {
        state.history.push({ role: 'assistant', content: data.reply, retrieved: data.retrieved, toolTrace: data.toolTrace });
        renderChat();
        if (data.judged && data.judged.passed) {
          var best = state.records[state.currentId];
          if (!best || text.length < best.chars) {
            state.records[state.currentId] = {
              chars: text.length,
              tokens: data.tokens || text.length,
              payloadText: text
            };
          }
          showBanner('⚔ 破阵！密令已被你夺下。（本招 ' + text.length + ' 字' +
            (data.tokens ? ' / ' + data.tokens + ' token' : '') + '）', true);
          renderRecord();
        } else {
          showBanner('城未破。守阵者没有说出密令——换一阵法再攻。', false);
        }
      }
    } catch (e) {
      pushNotice('网络错误：' + e.message);
    }
    setBusy(false);
    el.input.focus();
  }

  el.form.addEventListener('submit', function (e) { e.preventDefault(); send(); });
  el.input.addEventListener('input', function () {
    el.payloadLen.textContent = el.input.value.length ? '本招 ' + el.input.value.length + ' 字' : '';
  });
  el.input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      send();
    }
  });

  /* ---------- 守侧：布防跑分 ---------- */

  function pct(x) { return Math.round(x * 1000) / 10 + '%'; }

  function statBox(label, value, warn) {
    var d = document.createElement('div');
    d.className = 'stat' + (warn ? ' warn' : '');
    d.innerHTML = '<div class="stat-value"></div><div class="stat-label"></div>';
    d.querySelector('.stat-value').textContent = value;
    d.querySelector('.stat-label').textContent = label;
    return d;
  }

  function resultRow(r) {
    var li = document.createElement('li');
    var tag = r.kind === 'benign'
      ? (r.fp ? '误杀' : '')
      : (r.passed ? '泄露' : '拦截');
    if (r.error) tag = '出错';
    li.className = r.kind === 'benign'
      ? (r.fp ? 'fp' : '')
      : (r.passed ? 'leak' : 'block');
    li.innerHTML = '<span class="tag"></span><code></code><span class="text"></span>';
    li.querySelector('.tag').textContent = tag;
    li.querySelector('code').textContent = r.id;
    li.querySelector('.text').textContent = r.text;
    return li;
  }

  async function runDefense() {
    var prompt = el.defensePrompt.value.trim();
    var marker = el.rejectMarker.value.trim();
    var limit = parseInt(el.defenseLimit.value, 10);
    if (!prompt || state.defenseBusy || !state.currentId) return;

    state.defenseBusy = true;
    el.defenseRun.disabled = true;
    el.defenseRun.textContent = '考段中…';
    el.defenseStatus.textContent = isNaN(limit)
      ? '开考（全量语料）——每条 payload 一次真实 LLM 调用，约 1-2 分钟，请稍候。'
      : '开考（试考 ' + limit + ' 条）——每条一次真实 LLM 调用，请稍候。';
    el.defenseReport.innerHTML = '';

    try {
      var body = { defensePrompt: prompt, rejectMarker: marker || undefined };
      if (!isNaN(limit) && limit > 0) body.limit = limit;
      var res = await fetch('/api/levels/' + state.currentId + '/defense/evaluate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body)
      });
      var data = await res.json();
      if (!res.ok) {
        el.defenseStatus.textContent = data.error || ('评测失败（' + res.status + '）');
        return;
      }

      el.defenseStatus.textContent = '';
      var report = document.createElement('div');
      var grid = document.createElement('div');
      grid.className = 'stat-grid';
      grid.appendChild(statBox('拦截率', pct(data.attack.blockRate) + '（' + data.attack.blocked + '/' + data.attack.evaluated + '）'));
      grid.appendChild(statBox('泄露率', pct(data.attack.leakRate) + '（' + data.attack.leaked + ' 条泄露）', data.attack.leaked > 0));
      if (data.benign) {
        grid.appendChild(statBox('误杀率', pct(data.benign.falsePositiveRate) + '（' + data.benign.falsePositives + '/' + data.benign.evaluated + '）', data.benign.falsePositives > 0));
      }
      report.appendChild(grid);

      var list = document.createElement('ul');
      list.className = 'report-list';
      data.results.forEach(function (r) {
        if (r.passed || r.error || r.fp) {
          list.appendChild(resultRow(r));
        }
      });
      var summary = document.createElement('p');
      summary.className = 'muted';
      summary.textContent = '未泄露的攻击条目已折叠省略；' + (data.benign ? '误杀的良性请求已列出。' : '未测算误杀率（未填误杀判定标记）。');
      report.appendChild(summary);
      report.appendChild(list);

      el.defenseReport.appendChild(report);
    } catch (e) {
      el.defenseStatus.textContent = '网络错误：' + e.message;
    }
    state.defenseBusy = false;
    el.defenseRun.disabled = false;
    el.defenseRun.textContent = '开 考';
  }

  el.defenseRun.addEventListener('click', runDefense);

  /* ---------- 初始化 ---------- */

  async function init() {
    try {
      var res = await fetch('/api/levels');
      var data = await res.json();
      state.levels = data.levels || [];
      if (state.levels.length === 0) {
        pushNotice('未加载到任何关卡。');
        return;
      }
      selectLevel(state.levels[0].id);
    } catch (e) {
      pushNotice('关卡加载失败：' + e.message);
    }
    try {
      var h = await (await fetch('/api/health')).json();
      el.health.textContent = h.provider
        ? 'LLM：' + h.provider + ' · ' + h.model
        : 'LLM 未配置（BYOK：在服务端设置 INJECTARENA_* 环境变量）';
      el.health.className = 'health' + (h.provider ? ' ok' : ' warn');
    } catch (_) { /* 健康检查失败不阻塞页面 */ }
  }

  init();
})();
