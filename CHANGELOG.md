# Changelog

所有对 `injectarena` 包有显著影响的变更都记录在此文件。版本遵循
[语义化版本](https://semver.org/lang/zh-CN/)：MAJOR.MINOR.PATCH。

## [0.7.2] - 2026-09-16

### Changed
- **审计隐私不变式抬到测试红线**：新增 L4「审计隐私」集成测试，
  覆盖 RAG 投毒诱导 LLM 回吐密令的真实破阵场景，五层断言——
  `judged.matched` 字段不在 HTTP 响应中、`retrieved` 元数据不含密令、
  `listAudit` 任意行任何字段不含密令、`body.reply` 允许且必须含密令
  （破阵信号通道本身）。把 `src/server.js` + `src/db.js` + `src/judge.js`
  已隐含的隐私契约从口头约定升级为测试红线，防止后续重构误把
  `matched` / LLM 回复落进默认通道。
- **Corpus L1/L2 良性回归**：新增 6 条 benign 探针（L1 di-051..053
  VPN/打印机/入职账号；L2 de-016..018 物业办公室/业主答谢日/监控室值班），
  配套 `corpusDefense.test.js` 攻击面规则 `DT_STD.L1/L2`，
  防「benign 被误标攻击面」回归。

### Added
- `tests/corpusDefense.test.js`：L1「直捣」、L2「夜探」跨层专项，
  ATTACK_REGEX 扩到 18 个新模式（系统/秘密指代、输出形态、绕过话术
  三个家族）。
- `tests/server.test.js`：L4 审计隐私断言（详见上）。
- `tests/server.test.js` + `tests/worker.test.js`：`clientIpHash` 测试
  双轨（覆盖空盐、缺 CF-Connecting-IP、salt 变化、不同 IP 出不同 hash）。

### Security
- `audit_log.ip` 改为 SHA-256 哈希（盐取 `ARENA_SESSION_SECRET`），
  默认榜单视图与导出通道都不再出现明文 IP（`M2 审计`）。

### Tests
- 146/146 全绿（自 v0.7.1 的 145 项新增 1 项）。

## [0.7.1] - 2026-09-13

### Changed
- Corpus 区分 attacker / defense / benign 三类，对应 engines 各自签名。
- 攻击面与防御面测试双轨（`corpusDefense.test.js` + `corpusAttack.test.js`）。
- 关卡内容对齐 v0.6.0 现代化语境：L5 工具名 `send_report` → `send_email`、
  L6 系统维护标记、L4 KB 文书换成差旅报销/会议室预订等 6 份。

### Fixed
- 修复 v0.7.0 误删 `d1store` 四函数导致登录会话 500
  （`getPlayerStats` / `addPlayerStats` / `insertBreachCorpus` /
  `insertDefenseCorpus` 恢复 + 测试防回归），并删除过时旧榜函数。
- 摘除 `/records` 死路由（postRecords 已删、旧表已 DROP，残留引用
  调用即 500）。
- 前端去 `bestBreach` 残留引用（CRLF 下 `replace` 静默无效的补丁）。
- 登录态自动同步（focus/多页签广播/回跳补查 + 明确提示）。
- 观星台标题随视图切换为攻防榜/留言板，清残留旧词。
- 退出改为对话框——误触可取消，「清 Key」独立勾选默认保留。

## [0.6.0] - 2026-09-12

### Changed
- 题目现代化：军务隐喻 → 现代企业 IT/物业/反诈/客服/邮件工具/MCP 场景。
- 测试 / 关卡 / corpus 全面重命名（IT helpdesk / property CS / anti-fraud
  guard / RAG / email tool / MCP tool poisoning）。

## [0.3.3] - 2026-08-30

### Fixed
- 名将榜 / 段位榜修复若干边角排序与打码问题。