# CTF Expert — dsh CTF 能力插件 / Agent 预设

Reward-driven autonomous CTF agent for dsh: CVE 复现 · PoC 验证 · exploit 生成。
为 Agent 预设 `CTF Expert` 提供奖励惩罚机制（专注最大得分）+ 自主探路 + loop 熔断 +
技能路由（which skill used）+ 终局保证（goal=ACHIEVED 前不得宣告完成）。

## 安装

把本目录放入 `~/.dsh/.agent-presets/ctf-expert/`（或你的 preset root），
在 dsh Web 的 Agent Preset 选择器里选 **CTF Expert** 开新会话。

## 组成

| 文件 | 作用 |
|---|---|
| `agent.cordis.yml` | 预设组合（31 rows，无重复 id） |
| `preset.yml` | 展示元数据（name/description） |
| `ctf-engine.mjs` | 纯逻辑零依赖引擎：分层奖励/惩罚/停滞 BACKTRACK/一次性里程碑/哈希链账本/纪律看门狗/reward-hack/技能路由/终局状态 |
| `ctf-bootstrap.mjs` | 运行时插件：6 工具 + assemble 三阶段门控（极简一轮思考→标准全工具→奖惩攻坚）+ tools/result 看门狗 + 可选账本持久化 |

## 设计溯源

- 奖励/熔断：本地 AI 自主执行优化方案 PDF P4–P7（分层奖励、里程碑一次性结算、步成本、重复指数惩罚、停滞熔断、双 Skill、中间件强制评估）。
- 技能路由（v0.5.0）：借用 https://github.com/zhaoxuya520/reverse-skill 的路由模型（题型→最窄下游技能），仅保留轻量索引，不内联外部代码。
- 测试/文档/变更账本在 /home/xiatian/default/ctf-expert/（TRACE.md 每次改动溯源）。
