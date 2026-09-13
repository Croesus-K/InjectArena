'use strict';
/**
 * 攻心 InjectArena —— 前端（原生 JS，零构建，BYOK 站内部署版）。
 * 攻侧：关卡列表、聊天框、破阵判定（破阵后凭服务端签发的凭证自填名号上榜）。
 * 守侧：布防插槽编辑、跑分开考、拦截率/泄露率/误杀率报告。
 * BYOK：玩家 Key 只存本机 localStorage，随请求头经站内 Worker 中转发给供应商。
 * 身份：GitHub OAuth 登录（可选），上榜可挂头像与用户名。
 */

(function () {
  var API = '/api/arena';
  var CONFIG_KEY = 'arenaPlayerConfig';   // {baseUrl, model, key}

  var state = {
    levels: [],
    currentId: null,
    mode: 'attack',     // attack | defense | board
    history: [],        // [{role, content}] 当前阵的对话历史（不含系统提示词）
    records: {},        // levelId -> {chars, tokens, payloadText} 本页最短破阵纪录
    busy: false,
    defenseBusy: false,
    config: null,       // {baseUrl, model, key} | null
    session: null,      // {login, avatar} | null
    boardData: null,    // 份数榜缓存（attackRanking/defenseRanking）
    boardView: 'attack',// 观星台当前页：attack | defense | messages
    messages: null      // 留言板缓存
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
    btnConfig: document.getElementById('btn-config'),
    authArea: document.getElementById('auth-area'),
    tabAttack: document.getElementById('tab-attack'),
    tabDefense: document.getElementById('tab-defense'),
    tabBoard: document.getElementById('tab-board'),
    attackPanel: document.getElementById('attack-panel'),
    defensePanel: document.getElementById('defense-panel'),
    boardPanel: document.getElementById('board-panel'),
    boardView: document.getElementById('board-view'),
    viewAttack: document.getElementById('view-attack'),
    viewDefense: document.getElementById('view-defense'),
    viewMessages: document.getElementById('view-messages'),
    boardAttack: document.getElementById('board-attack'),
    boardDefense: document.getElementById('board-defense'),
    boardEmpty: document.getElementById('board-empty'),
    messagesList: document.getElementById('messages-list'),
    meStats: document.getElementById('me-stats'),
    defenseLevelName: document.getElementById('defense-level-name'),
    defensePrompt: document.getElementById('defense-prompt'),
    rejectMarker: document.getElementById('reject-marker'),
    defenseRun: document.getElementById('defense-run'),
    defenseStatus: document.getElementById('defense-status'),
    defenseReport: document.getElementById('defense-report'),
    defenseLimit: document.getElementById('defense-limit'),
    defenseTemplates: document.getElementById('defense-templates'),
    defenseLesson: document.getElementById('defense-lesson'),
    defenseHints: document.getElementById('defense-hints'),
    defenseHintsList: document.getElementById('defense-hints-list'),
    configDialog: document.getElementById('config-dialog'),
    cfgPreset: document.getElementById('cfg-preset'),
    cfgBaseUrl: document.getElementById('cfg-baseurl'),
    cfgModel: document.getElementById('cfg-model'),
    cfgKey: document.getElementById('cfg-key'),
    cfgError: document.getElementById('cfg-error'),
    recordDialog: document.getElementById('record-dialog'),
    recordTitle: document.getElementById('record-title'),
    recordSummary: document.getElementById('record-summary'),
    recordSubmit: document.getElementById('record-submit'),
    recordLoginHint: document.getElementById('record-login-hint'),
    recordMessage: document.getElementById('record-message'),
    recordError: document.getElementById('record-error')
  };

  var SURFACE_NAMES = {
    'direct-injection': '直接注入',
    'data-exfiltration': '数据窃取',
    'guarded-prompt': '对抗防护',
    'indirect-injection': '间接注入',
    'tool-abuse': '工具滥用',
    'mcp-poisoning': 'MCP 投毒'
  };

  /* ---------- BYOK 配置 ---------- */

  function loadPlayerConfig() {
    try {
      var raw = localStorage.getItem(CONFIG_KEY);
      if (!raw) return null;
      var cfg = JSON.parse(raw);
      if (cfg && cfg.baseUrl && cfg.model && cfg.key) return cfg;
      return null;
    } catch (_) {
      return null;
    }
  }

  function savePlayerConfig(cfg) {
    localStorage.setItem(CONFIG_KEY, JSON.stringify(cfg));
    state.config = cfg;
    renderHealth();
  }

  function clearPlayerConfig() {
    localStorage.removeItem(CONFIG_KEY);
    state.config = null;
    renderHealth();
  }

  function providerHeaders() {
    var cfg = state.config;
    return {
      'x-arena-key': cfg.key,
      'x-arena-base-url': cfg.baseUrl,
      'x-arena-model': cfg.model
    };
  }

  /** 没配 Key 时不发请求：打开配置面板引导。返回 null 表示中断。 */
  function requireConfig() {
    if (state.config) return state.config;
    pushNotice('请先配置你的 LLM API Key（BYOK）——Key 只存本机浏览器，站主不经手。');
    openConfigDialog();
    return null;
  }

  var PRESETS = {
    deepseek: { baseUrl: 'https://api.deepseek.com/v1', model: 'deepseek-chat' },
    glm: { baseUrl: 'https://open.bigmodel.cn/api/paas/v4', model: 'glm-4-flash' },
    kimi: { baseUrl: 'https://api.moonshot.cn/v1', model: 'kimi-k2-0711-preview' },
    qwen: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', model: 'qwen-plus' },
    openai: { baseUrl: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
    openrouter: { baseUrl: 'https://openrouter.ai/api/v1', model: '' }
  };

  function shortHost(u) {
    try { return new URL(u).hostname; } catch (_) { return u; }
  }

  function renderHealth() {
    if (state.config) {
      el.health.textContent = '已配置 · ' + state.config.model + ' @ ' + shortHost(state.config.baseUrl);
      el.health.className = 'health ok';
    } else {
      el.health.textContent = '未配置 Key —— 点「配置」开始（BYOK）';
      el.health.className = 'health warn';
    }
  }

  function openConfigDialog() {
    el.cfgError.textContent = '';
    var cfg = state.config || {};
    el.cfgPreset.value = '';
    el.cfgBaseUrl.value = cfg.baseUrl || '';
    el.cfgModel.value = cfg.model || '';
    el.cfgKey.value = cfg.key || '';
    if (el.configDialog.showModal) el.configDialog.showModal();
    else el.configDialog.setAttribute('open', '');
  }

  el.btnConfig.addEventListener('click', openConfigDialog);

  el.cfgPreset.addEventListener('change', function () {
    var p = PRESETS[el.cfgPreset.value];
    if (!p) return;
    el.cfgBaseUrl.value = p.baseUrl;
    if (p.model) el.cfgModel.value = p.model;
  });

  document.getElementById('cfg-save').addEventListener('click', function () {
    var baseUrl = el.cfgBaseUrl.value.trim();
    var model = el.cfgModel.value.trim();
    var key = el.cfgKey.value.trim();
    if (!baseUrl || !model || !key) {
      el.cfgError.textContent = '三项都要填：服务地址、模型名、API Key。';
      return;
    }
    if (baseUrl.indexOf('https://') !== 0) {
      el.cfgError.textContent = '服务地址必须以 https:// 开头。';
      return;
    }
    savePlayerConfig({ baseUrl: baseUrl, model: model, key: key });
    if (el.configDialog.close) el.configDialog.close();
  });

  document.getElementById('cfg-clear').addEventListener('click', function () {
    if (!window.confirm('确定清除本机保存的 API Key 与供应商配置？')) return;
    clearPlayerConfig();
    el.cfgBaseUrl.value = '';
    el.cfgModel.value = '';
    el.cfgKey.value = '';
    el.cfgError.textContent = '已清除本机 Key。';
  });

  document.getElementById('cfg-close').addEventListener('click', function () {
    if (el.configDialog.close) el.configDialog.close();
  });

  /* ---------- GitHub 登录 ---------- */

  function renderAuthArea() {
    el.authArea.innerHTML = '';
    if (state.session) {
      var img = document.createElement('img');
      img.className = 'auth-avatar';
      img.src = state.session.avatar || '';
      img.alt = '';
      img.referrerPolicy = 'no-referrer';
      var name = document.createElement('span');
      name.className = 'auth-name';
      name.textContent = state.session.login;
      var out = document.createElement('button');
      out.type = 'button';
      out.className = 'ghost-btn';
      out.textContent = '退出';
      out.addEventListener('click', logout);
      el.authArea.appendChild(img);
      el.authArea.appendChild(name);
      el.authArea.appendChild(out);
    } else {
      var a = document.createElement('a');
      a.className = 'ghost-btn';
      a.href = API + '/auth/login';
      a.textContent = 'GitHub 登录';
      el.authArea.appendChild(a);
    }
  }

  async function loadMe() {
    try {
      var res = await fetch(API + '/auth/me');
      var data = await res.json();
      state.session = data.login ? { login: data.login, avatar: data.avatarUrl } : null;
      state.stats = data.stats || null;
    } catch (_) {
      state.session = null;
      state.stats = null;
    }
    renderAuthArea();
    renderMeStats();
  }

  /** 「我」的等级与积分：等级 = 有效语料份数（攻+守，只增）；积分可消费（换位扣）。 */
  function renderMeStats() {
    if (!el.meStats) return;
    if (state.session && state.stats) {
      el.meStats.textContent = state.session.login + ' · 等级 ' + state.stats.level + ' · 积分 ' + state.stats.score;
    } else if (state.session) {
      el.meStats.textContent = state.session.login + ' · 尚无语料份数';
    } else {
      el.meStats.textContent = '未登录 GitHub —— 份数榜与留言需要登录';
    }
  }

  async function logout() {
    var clearKey = window.confirm(
      '退出 GitHub 登录？\n\n「确定」= 退出并清除本机保存的 API Key\n「取消」= 仅退出（Key 保留在本机）'
    );
    try { await fetch(API + '/auth/logout', { method: 'POST' }); } catch (_) { /* 会话 Cookie 清理失败不影响本地 */ }
    state.session = null;
    if (clearKey) clearPlayerConfig();
    renderAuthArea();
  }

  /* ---------- 阵法列表 ---------- */

  function stars(n) {
    // 难度上限随关卡数据动态扩展（L6 起为 6 星），星盘总数取全库最大难度
    var max = 5;
    for (var i = 0; i < state.levels.length; i++) {
      if (state.levels[i].difficulty > max) max = state.levels[i].difficulty;
    }
    var s = '';
    for (var j = 0; j < max; j++) s += j < n ? '★' : '☆';
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
      var meta = (SURFACE_NAMES[lv.attackSurface] || lv.attackSurface) + ' · 难度 ' + stars(lv.difficulty);
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
      (lv.lesson ? '<p class="lesson"></p>' : '') +
      '<p class="brief"></p>' +
      '<p class="muted keeper">守阵者：你配置的模型（全关统一 · BYOK）' +
      (lv.tools && lv.tools.length ? ' · 持工具 ' + lv.tools.map(function (t) { return t.name; }).join('、') : '') +
      (lv.bestBreach ? ' · 本阵最短破阵纪录 ' + lv.bestBreach.chars + ' 字' : '') + '</p>' +
      '<details><summary>军师提示</summary><p class="hints"></p></details>';
    if (lv.lesson) el.levelHead.querySelector('.lesson').textContent = '考点 · ' + lv.lesson;
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
    removeLooseDebrief();
    renderLevels();
    renderLevelHead();
    renderChat();
    renderRecord();
    var lv = currentLevel();
    el.defenseLevelName.textContent = lv ? lv.id + ' · ' + lv.name : '';
    renderDefenseTemplates();
    // 已破过的阵：军师提示下方常驻复盘（默认收起）
    if (lv && state.records[id]) {
      var node = debriefElement(lv, false);
      if (node) el.levelHead.appendChild(node);
    }
    el.input.focus();
  }

  /* ---------- 守侧：布防模板库（一键套用）+ 守方教学 ---------- */

  function renderDefenseTemplates() {
    var lv = currentLevel();
    var tpls = (lv && lv.defenseTemplates) || [];
    el.defenseTemplates.innerHTML = '';
    if (!tpls.length) {
      el.defenseTemplates.hidden = true;
    } else {
      el.defenseTemplates.hidden = false;
      var label = document.createElement('span');
      label.className = 'defense-templates-label';
      label.textContent = '布防模板 · 一键套用：';
      el.defenseTemplates.appendChild(label);
      tpls.forEach(function (t) {
        var chip = document.createElement('button');
        chip.type = 'button';
        chip.className = 'tpl-chip';
        chip.textContent = t.label;
        if (t.desc) chip.title = t.desc;
        chip.addEventListener('click', function () {
          el.defensePrompt.value = t.prompt;
          var chips = el.defenseTemplates.querySelectorAll('.tpl-chip');
          for (var i = 0; i < chips.length; i++) chips[i].classList.remove('active');
          chip.classList.add('active');
          el.defenseStatus.textContent = '已套用模板「' + t.label + '」——可直接开考，或在其基础上再编辑。';
        });
        el.defenseTemplates.appendChild(chip);
      });
    }

    // 守方针对点（每关的防守考点）+ 守方军师提示（递进思路）
    el.defenseLesson.textContent = lv && lv.defenseBrief ? '守方针对点 · ' + lv.defenseBrief : '';
    el.defenseHintsList.innerHTML = '';
    var dh = (lv && lv.defenseHints) || [];
    el.defenseHints.hidden = dh.length === 0;
    dh.forEach(function (h) {
      var li = document.createElement('li');
      li.textContent = h;
      el.defenseHintsList.appendChild(li);
    });
  }

  /* ---------- 模式切换 ---------- */

  function switchMode(mode) {
    state.mode = mode;
    el.tabAttack.className = 'tab' + (mode === 'attack' ? ' active' : '');
    el.tabDefense.className = 'tab' + (mode === 'defense' ? ' active' : '');
    el.tabBoard.className = 'tab' + (mode === 'board' ? ' active' : '');
    el.attackPanel.hidden = mode !== 'attack';
    el.defensePanel.hidden = mode !== 'defense';
    el.boardPanel.hidden = mode !== 'board';
    if (mode === 'board') showBoardView(state.boardView);
  }

  el.tabAttack.addEventListener('click', function () { switchMode('attack'); });
  el.tabDefense.addEventListener('click', function () { switchMode('defense'); });
  el.tabBoard.addEventListener('click', function () { switchMode('board'); });

  /** 观星台三页切换：攻榜 / 守榜 / 留言板（数据各自惰性加载）。 */
  function showBoardView(view) {
    state.boardView = view;
    el.boardView.value = view;
    el.viewAttack.hidden = view !== 'attack';
    el.viewDefense.hidden = view !== 'defense';
    el.viewMessages.hidden = view !== 'messages';
    el.boardEmpty.textContent = '';
    if (view === 'attack' || view === 'defense') {
      if (!state.boardData) loadBoard(); else renderBoard();
    } else {
      loadMessages();
    }
  }
  el.boardView.addEventListener('change', function () { showBoardView(el.boardView.value); });

  /* ---------- 榜 · 观星台（份数榜前十） ---------- */

  /** cells 元素可以是字符串（textContent 安全渲染）或已建好的 DOM 节点。 */
  function boardTable(headers, rows) {
    var table = document.createElement('table');
    table.className = 'board-table';
    var thead = document.createElement('thead');
    var trh = document.createElement('tr');
    headers.forEach(function (h) {
      var th = document.createElement('th');
      th.textContent = h;
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);
    var tbody = document.createElement('tbody');
    rows.forEach(function (cells) {
      var tr = document.createElement('tr');
      cells.forEach(function (c) {
        var td = document.createElement('td');
        if (c && c.nodeType === 1) td.appendChild(c);
        else td.textContent = c;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    return table;
  }

  function shortTs(ts) {
    return typeof ts === 'string' ? ts.slice(0, 16).replace('T', ' ') : '';
  }

  async function loadBoard() {
    el.boardAttack.innerHTML = '';
    el.boardDefense.innerHTML = '';
    el.boardEmpty.textContent = '加载中……';
    try {
      state.boardData = await (await fetch(API + '/leaderboard')).json();
      renderBoard();
    } catch (e) {
      el.boardEmpty.textContent = '榜单加载失败：' + e.message;
    }
  }

  /** 份数榜（v0.6.0）：有效语料份数前十，仅 GitHub 登录者。 */
  function renderBoard() {
    el.boardAttack.innerHTML = '';
    el.boardDefense.innerHTML = '';
    el.boardEmpty.textContent = '';
    if (!state.boardData) return;
    var isAttack = state.boardView === 'attack';
    var rows = isAttack ? (state.boardData.attackRanking || []) : (state.boardData.defenseRanking || []);
    var host = isAttack ? el.boardAttack : el.boardDefense;

    if (rows.length) {
      host.appendChild(boardTable(
        ['名号', '份数', '积分'],
        rows.map(function (r, i) { return [rankName(i + 1, r.login), r.count, r.score]; })
      ));
    } else {
      el.boardEmpty.textContent = '虚位以待——' + (isAttack ? '破阵' : '考段') + '即自动计入（需 GitHub 登录）。';
    }
  }

  function rankName(rank, login) {
    return '#' + rank + ' ' + login;
  }

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

  function debriefElement(lv, open) {
    var d = lv && lv.debrief;
    if (!d) return null;
    var det = document.createElement('details');
    det.className = 'debrief';
    if (open) det.open = true;
    var sum = document.createElement('summary');
    sum.textContent = '复盘 · 兵法讲解';
    var body = document.createElement('div');
    body.innerHTML =
      '<p class="debrief-label">攻击原理</p><p class="debrief-body"></p>' +
      '<p class="debrief-label">真实案例</p><ul class="debrief-cases"></ul>' +
      '<p class="debrief-label">OWASP LLM Top 10（2025）映射</p><p class="debrief-body"></p>' +
      '<p class="debrief-label">防御要点</p><p class="debrief-body"></p>' +
      '<p class="debrief-label">布防参考 · 可直接粘贴到「守 · 布防」开考</p><p class="debrief-body debrief-sample"></p>';
    var ps = body.querySelectorAll('.debrief-body');
    ps[0].textContent = d.principle;
    ps[1].textContent = d.owasp.join('；');
    ps[2].textContent = d.defense;
    if (d.defenseSample) ps[3].textContent = d.defenseSample;
    var ul = body.querySelector('.debrief-cases');
    (d.cases || []).forEach(function (c) {
      var li = document.createElement('li');
      li.textContent = c;
      ul.appendChild(li);
    });
    det.appendChild(sum);
    det.appendChild(body);
    return det;
  }

  /** 破阵复盘挂在 banner 之后、随关切换——切关与重复破阵前先清掉上一份，避免跨关堆积。 */
  function removeLooseDebrief() {
    var parent = el.banner.parentElement;
    if (!parent) return;
    var nodes = parent.querySelectorAll(':scope > details.debrief');
    for (var i = 0; i < nodes.length; i++) nodes[i].remove();
  }

  function showDebrief(lv, open) {
    removeLooseDebrief();
    var node = debriefElement(lv, open);
    if (node) el.banner.insertAdjacentElement('afterend', node);
    return node;
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

  /* ---------- 留言弹窗（破阵/考段凭证兑换为留言；份数已自动计入） ---------- */

  var pendingRecord = null; // {kind, credential, level}

  function openRecordDialog(info) {
    pendingRecord = info;
    el.recordError.textContent = '';
    var isBreach = info.kind === 'breach';
    el.recordTitle.textContent = isBreach ? '破阵成功 · 留言' : '考段完成 · 留言';
    el.recordSummary.textContent = isBreach
      ? info.level.id + ' · ' + info.level.name + ' —— 本招 ' + info.credential.chars + ' 字' +
        (info.credential.tokens ? ' / ' + info.credential.tokens + ' token' : '') + '。份数已自动计入（登录者），留言凭证 2 小时内有效。'
      : info.level.id + ' · ' + info.level.name + ' —— 拦截率 ' + Math.round(info.credential.blockRate * 1000) / 10 + '%。布防份数已自动计入（登录者），留言凭证 2 小时内有效。';
    el.recordLoginHint.hidden = Boolean(state.session);
    el.recordMessage.value = '';
    el.recordSubmit.disabled = !state.session;
    if (el.recordDialog.showModal) el.recordDialog.showModal();
  }

  document.getElementById('record-submit').addEventListener('click', async function () {
    if (!pendingRecord) return;
    var message = el.recordMessage.value.trim();
    if (!message) {
      el.recordError.textContent = '留言不能为空。';
      return;
    }
    try {
      var res = await fetch(API + '/board', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          credential: pendingRecord.credential.token,
          message: message
        })
      });
      var data = await res.json();
      if (!res.ok) {
        el.recordError.textContent = data.error || ('提交失败（' + res.status + '）');
        return;
      }
      if (el.recordDialog.close) el.recordDialog.close();
      pushNotice(data.outcome === 'written'
        ? '已留言！到「榜 · 观星 → 言 · 留言板」可见你的名号。'
        : '留言已更新（一人一条，位置保留）。');
    } catch (e) {
      el.recordError.textContent = '网络错误：' + e.message;
    }
  });

  document.getElementById('record-skip').addEventListener('click', function () {
    pendingRecord = null;
    if (el.recordDialog.close) el.recordDialog.close();
  });

  /* ---------- 攻侧：出招 ---------- */

  async function send() {
    var text = el.input.value.trim();
    if (!text || state.busy || !state.currentId) return;
    if (!requireConfig()) return;
    el.input.value = '';
    el.payloadLen.textContent = '';

    state.history.push({ role: 'user', content: text });
    renderChat();
    setBusy(true);
    el.banner.hidden = true;

    try {
      var res = await fetch(API + '/levels/' + state.currentId + '/chat', {
        method: 'POST',
        headers: Object.assign({ 'content-type': 'application/json' }, providerHeaders()),
        body: JSON.stringify({
          messages: state.history.map(function (m) { return { role: m.role, content: m.content }; })
        })
      });
      var data = await res.json();
      if (!res.ok) {
        pushNotice(data.error || ('请求失败（' + res.status + '）'));
        state.history.pop(); // 失败的招式不入对话史，可原地重出
        renderChat();
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
          showDebrief(currentLevel(), true);
          renderRecord();
          if (data.credential && data.credential.token) {
            openRecordDialog({ kind: 'breach', credential: data.credential, level: currentLevel() });
          } else {
            pushNotice('本站暂未启用上榜（站长未完成凭证配置）——破阵已记录在本页。');
          }
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

  function renderDefenseReport(data) {
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
  }

  async function runDefense() {
    var prompt = el.defensePrompt.value.trim();
    var marker = el.rejectMarker.value.trim();
    var limit = parseInt(el.defenseLimit.value, 10);
    if (!prompt || state.defenseBusy || !state.currentId) return;
    if (!requireConfig()) return;

    state.defenseBusy = true;
    el.defenseRun.disabled = true;
    el.defenseRun.textContent = '考段中…';
    el.defenseReport.innerHTML = '';
    el.defenseStatus.textContent = '正在开考…';

    // 进度条：NDJSON 流式事件驱动（start → progress×N → report/error）
    var progressLine = document.createElement('div');
    progressLine.className = 'progress-line';
    var bar = document.createElement('div');
    bar.className = 'progress-bar';
    var barFill = document.createElement('div');
    barFill.className = 'progress-fill';
    bar.appendChild(barFill);
    progressLine.appendChild(bar);
    var progressText = document.createElement('span');
    progressLine.appendChild(progressText);
    el.defenseReport.appendChild(progressLine);

    function showProgress(done, total, leaked) {
      barFill.style.width = total ? Math.round((done / total) * 100) + '%' : '0%';
      progressText.textContent = ' 已考 ' + done + '/' + total + (leaked ? '，泄露 ' + leaked : '');
    }

    try {
      var body = { defensePrompt: prompt, rejectMarker: marker || undefined };
      if (!isNaN(limit) && limit > 0) body.limit = limit;
      var res = await fetch(API + '/levels/' + state.currentId + '/defense/evaluate/stream', {
        method: 'POST',
        headers: Object.assign({ 'content-type': 'application/json' }, providerHeaders()),
        body: JSON.stringify(body)
      });

      if (!res.ok) {
        var errData = await res.json();
        el.defenseStatus.textContent = errData.error || ('评测失败（' + res.status + '）');
        progressLine.remove();
        state.defenseBusy = false;
        el.defenseRun.disabled = false;
        el.defenseRun.textContent = '开 考';
        return;
      }

      var reader = res.body.getReader();
      var decoder = new TextDecoder();
      var buffer = '';
      var report = null;
      var total = 0;
      var leakedCount = 0;

      var pump = function (done) {
        if (done) return Promise.resolve();
        return reader.read().then(function (chunk) {
          if (chunk.done) return Promise.resolve();
          buffer += decoder.decode(chunk.value, { stream: true });
          var idx;
          while ((idx = buffer.indexOf('\n')) >= 0) {
            var line = buffer.slice(0, idx).trim();
            buffer = buffer.slice(idx + 1);
            if (!line) continue;
            var ev = JSON.parse(line);
            if (ev.type === 'start') {
              total = ev.total;
              showProgress(0, total, 0);
              if (ev.capped) {
                el.defenseStatus.textContent = '语料超出单次上限（平台子请求限制），本次按前 ' + total + ' 条开考；可分多次考完。';
              }
            } else if (ev.type === 'progress') {
              if (ev.leaked) leakedCount += 1;
              showProgress(ev.done, total, leakedCount);
            } else if (ev.type === 'report') {
              report = ev;
            } else if (ev.type === 'error') {
              el.defenseStatus.textContent = ev.message;
            }
          }
          return pump(chunk.done);
        });
      };
      await pump(false);

      progressLine.remove();
      if (report) {
        renderDefenseReport(report);
        if (report.credential && report.credential.token) {
          openRecordDialog({
            kind: 'defense',
            credential: Object.assign({}, report.credential, { blockRate_sampleCount: report.attack.evaluated }),
            level: currentLevel()
          });
        }
      }
    } catch (e) {
      el.defenseStatus.textContent = '网络错误：' + e.message;
      progressLine.remove();
    }
    state.defenseBusy = false;
    el.defenseRun.disabled = false;
    el.defenseRun.textContent = '开 考';
  }

  el.defenseRun.addEventListener('click', runDefense);

  /* ---------- 初始化 ---------- */

  async function refreshLevels() {
    try {
      var res = await fetch(API + '/levels');
      var data = await res.json();
      state.levels = data.levels || [];
      if (!state.currentId && state.levels.length === 0) {
        pushNotice('未加载到任何关卡。');
        return;
      }
      var keep = state.currentId;
      if (!keep || !state.levels.some(function (lv) { return lv.id === keep; })) {
        keep = state.levels.length ? state.levels[0].id : null;
      }
      if (keep !== state.currentId || !state.currentId) {
        state.currentId = null;
        selectLevel(keep);
      } else {
        renderLevels();
        renderLevelHead();
      }
    } catch (e) {
      pushNotice('关卡加载失败：' + e.message);
    }
  }

  async function init() {
    state.config = loadPlayerConfig();
    renderHealth();

    // GitHub 登录回跳参数（?login=ok|error）——提示后清掉，避免刷新重复提示
    var params = new URLSearchParams(location.search);
    if (params.get('login') === 'ok') pushNotice('GitHub 登录成功——破阵上榜可挂你的头像与用户名了。');
    if (params.get('login') === 'error') pushNotice('GitHub 登录失败，可重试；不登录也能正常闯关上榜。');
    if (params.has('login')) history.replaceState(null, '', location.pathname);

    await loadMe();
    await refreshLevels();

    try {
      var h = await (await fetch(API + '/health')).json();
      if (!h.ok) return;
      // 服务端健康信息并入页脚备注（BYOK 模式下 provider/model 由玩家配置决定）
      var footer = document.querySelector('footer');
      if (footer && h.version) footer.setAttribute('data-version', 'v' + h.version);
    } catch (_) { /* 健康检查失败不阻塞页面 */ }
  }

  init();
})();
