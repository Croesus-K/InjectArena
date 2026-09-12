-- arena-worker D1 schema —— src/db.js 三表的 D1 移植 + BYOK 身份扩展。
-- 与 Node 版差异：
--   * player 列拆成 actor（唯一键：github login 或 'guest:'+display_id）+ display_id（自填展示名号）；
--   * 新增 message（上榜一句话留言）、github_login / github_avatar（挂身份时才写入，NULL = 不挂）；
--   * audit_log 增加 github_login（审计仍只存元数据，永不记玩家 Key）。

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  ip TEXT NOT NULL,
  route TEXT NOT NULL,
  level_id TEXT,
  payload_chars INTEGER,
  tokens INTEGER,
  passed INTEGER,
  outcome TEXT NOT NULL,
  detail TEXT,
  github_login TEXT
);

CREATE TABLE IF NOT EXISTS breach_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  display_id TEXT NOT NULL,
  chars INTEGER NOT NULL,
  tokens INTEGER,
  payload_text TEXT NOT NULL,
  message TEXT,
  github_login TEXT,
  github_avatar TEXT,
  ts TEXT NOT NULL,
  UNIQUE(level_id, actor)
);

CREATE TABLE IF NOT EXISTS defense_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  display_id TEXT NOT NULL,
  block_rate REAL NOT NULL,
  leak_rate REAL NOT NULL,
  fp_rate REAL,
  evaluated INTEGER NOT NULL,
  message TEXT,
  github_login TEXT,
  github_avatar TEXT,
  ts TEXT NOT NULL,
  UNIQUE(level_id, actor)
);
