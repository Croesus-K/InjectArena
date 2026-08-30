'use strict';
/**
 * 攻心 InjectArena —— 最小前端（原生 JS，零构建）。
 * 只做三件事：关卡列表、聊天框、提交判定。破阵纪录仅存本页内存（无排行榜）。
 */

(function () {
  var state = {
    levels: [],
    currentId: null,
    history: [],        // [{role, content}] 当前阵的对话历史（不含系统提示词）
    records: {},        // levelId -> {chars, tokens, payloadText} 本页最短破阵纪录
    busy: false
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
    health: document.getElementById('health')
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

  function renderLevels() {
    el.levelList.innerHTML = '';
    state.levels.forEach(function (lv) {
      var card = document.createElement('button');
      card.className = 'level-card' + (lv.id === state.currentId ? ' active' : '');
      card.innerHTML =
        '<div class="level-title">' + lv.id + ' · ' + lv.name + '</div>' +
        '<div class="level-meta">' + (SURFACE_NAMES[lv.attackSurface] || lv.attackSurface) + ' · 难度 ' + stars(lv.difficulty) + '</div>' +
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
      '<details><summary>军师提示</summary><p class="hints"></p></details>';
    el.levelHead.querySelector('.brief').textContent = lv.brief;
    el.levelHead.querySelector('.hints').textContent = (lv.hints || []).join(' ');
  }

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

  function selectLevel(id) {
    state.currentId = id;
    state.history = [];
    el.banner.hidden = true;
    el.notice.innerHTML = '';
    renderLevels();
    renderLevelHead();
    renderChat();
    renderRecord();
    el.input.focus();
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
        state.history.push({ role: 'assistant', content: data.reply });
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
