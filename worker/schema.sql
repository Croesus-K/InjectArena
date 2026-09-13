-- arena-worker D1 schema —— src/db.js 三表的 D1 移植 + BYOK 身份扩展。
-- 与 Node 版差异：
--   * player 列拆成 actor（唯一键：github login 或 'guest:'+display_id）+ display_id（自填展示名号）；
--   * 新增 message（上榜一句话留言）、github_login / github_avatar（挂身份时才写入，NULL = 不挂）；
--   * audit_log 增加 github_login（审计仍只存元数据，永不记玩家 Key）；
--   * audit_log 保留期 90 天：worker 写入时顺手清除旧行（worker/src/d1store.js 常量 AUDIT_RETENTION_DAYS）；
--   * 破阵 payload 明文拆出独立表 breach_payloads（隔离层）：榜单表本身零攻击原文，
--     只有导出通道（/leaderboard?format=export，语料回流）按需 JOIN，FLAG 在导出边缘打码。

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
  message TEXT,
  github_login TEXT,
  github_avatar TEXT,
  ts TEXT NOT NULL,
  UNIQUE(level_id, actor)
);

-- 破阵 payload 明文（原始攻击串，含 FLAG）：与榜单记录 1:1，仅服务端可见
CREATE TABLE IF NOT EXISTS breach_payloads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  breach_id INTEGER NOT NULL UNIQUE,
  payload_text TEXT NOT NULL,
  ts TEXT NOT NULL
);

-- 未上榜破阵（破阵判定 passed 即录，与上榜解耦）：语料回流专属，匿名——
-- 不存 player/actor/IP；同关同 payload 幂等跳过；仅导出通道读取，边缘统一打码
CREATE TABLE IF NOT EXISTS breach_unclaimed (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level_id TEXT NOT NULL,
  payload_text TEXT NOT NULL,
  chars INTEGER NOT NULL,
  tokens INTEGER,
  ts TEXT NOT NULL
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

-- ---------------------------------------------------------------------------
-- 份数榜与留言板（v0.6.0）：榜单 = 有效语料份数前十（仅 GitHub 登录者）；
-- 破阵/考段完成即自动计分（相似度 ≥0.8 视为同一份，不重复计）；积分可消费（换位），等级只增。
-- ---------------------------------------------------------------------------

-- 玩家统计：等级 = breach_count + defense_count（只增）；score = 可消费积分
CREATE TABLE IF NOT EXISTS player_stats (
  github_login TEXT PRIMARY KEY,
  breach_count INTEGER NOT NULL DEFAULT 0,
  defense_count INTEGER NOT NULL DEFAULT 0,
  score INTEGER NOT NULL DEFAULT 0,
  ts TEXT NOT NULL
);

-- 攻方语料登记（相似度去重依据：同 login 同 level 内两两比对）
CREATE TABLE IF NOT EXISTS breach_corpus (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  github_login TEXT NOT NULL,
  level_id TEXT NOT NULL,
  payload_text TEXT NOT NULL,
  chars INTEGER NOT NULL,
  ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_breach_corpus_player ON breach_corpus (github_login, level_id);

-- 守方布防语料登记（对称：布防提示词相似度去重）
CREATE TABLE IF NOT EXISTS defense_corpus (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  github_login TEXT NOT NULL,
  level_id TEXT NOT NULL,
  defense_prompt TEXT NOT NULL,
  ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_defense_corpus_player ON defense_corpus (github_login, level_id);

-- 留言板：一人一条（重复破阵可更新内容，position 保留）；position 即序列号（初始=提交时间序）
CREATE TABLE IF NOT EXISTS message_board (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  github_login TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  message TEXT NOT NULL,
  position INTEGER NOT NULL UNIQUE,
  ts TEXT NOT NULL
);
