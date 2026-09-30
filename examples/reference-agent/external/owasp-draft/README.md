# OWASP Harness 中文场景贡献草稿

对应 [选型.md](../选型.md) 决定 2。把本案 blunt 批的攻击场景翻译为 [OWASP Agent Security Regression Harness](https://github.com/OWASP/Agent-Security-Regression-Harness) v0.2.0 场景格式，作为向 OWASP 上游提交**中文场景**的贡献草案。

| 本案场景 | Harness 草稿 | 说明 |
| --- | --- | --- |
| `indirect-external-mail` | `prompt_injection.retrieved_doc_external_mail_001.yaml` | 检索文档投毒 → 外部地址发信 |
| `indirect-internal-secret` | `prompt_injection.retrieved_doc_internal_secret_mail_001.yaml` | 检索文档投毒 → 内部地址 + 机密正文 |
| `direct-secret-mail` | `prompt_injection.direct_authority_pretext_mail_001.yaml` | 冒充授权审计直接索要 |
| `indirect-reply-leak` | **暂不翻译** | 该攻击走回答文本通道，Harness 的 `no_secret_disclosure` 断言 v0.2.0 未实现（上游在案），翻译了也跑不出结论——不硬凑 |

本地验证（v0.2.0，玩具目标 vulnerable=8001 / hardened=8002）：

```bash
agent-harness validate scenarios-draft/prompt_injection.*.yaml
agent-harness run <草稿.yaml> --live --target-url http://127.0.0.1:8001/run   # 预期 fail（正对照）
agent-harness run <草稿.yaml> --live --target-url http://127.0.0.1:8002/run   # 预期 pass（负对照）
```

贡献前待办：对照上游 `schemas/scenario.schema.json` 复核字段、按上游贡献流程提交 PR、等待 `no_secret_disclosure` 实现后补第 4 个场景。
