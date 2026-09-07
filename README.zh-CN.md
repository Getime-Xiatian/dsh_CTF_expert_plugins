# CTF Expert — dsh CTF 能力插件 / Agent 预设（v0.9.0）

> [English](README.md) | **简体中文**

面向 dsh 的奖励驱动自主 CTF Agent：**CVE 复现 · PoC 验证 · exploit 生成**。
为 Agent 预设 `CTF Expert` 提供一套**奖励惩罚机制**（专注最大得分）+ **自主探路** +
**loop 熔断** + **技能路由（which skill used）**。
**Round-1 协议**：极简深思考轮先产出 plan + which skill used（纯文本），由
**subagent 排查完善**后再解锁执行工具；完善后的 plan（v1 + audit deltas）**落账为结构化
plan 记录**（v0.8.2）。
**v0.9.0：去除 flag 验证环节**——目标完成 = **用户提示词目标完成**，由模型用新工具
`ctf_complete` **显式声明**（goal=ACHIEVED / +10 里程碑）；plan audit 通过后先用
`todo_write` 把计划写成任务再执行。
插件所有 LLM 可见 prompt 均为英文，并在每个阶段强制 English thinking。

> **v0.8.1 三修复（实测）**：① 极简产物步后经 `agent/turn-stopping` 自动唤醒进入 review
> （旧版在 session/event 观察器内 append 被同会话重入拒绝，唤醒静默丢失）；② ctf_* 工具经
> 运行时 `exec.agent.session` 绑定会话（旧版 "no agent session"）；③ 委托子代理
> （origin=subagent / delegationDepth>0）跳过全部 CTF 协议——audit 子代理只回
> verdict + deltas，不再复述整份 plan。

> **v0.8.2 细化**：① plan 落账——`ctf_plan` 存结构化初版（text/objective/hypothesis/
> firstProbe/milestone/skill），audit 通过后 `ctf_review` 把 deltas 并入并置
> plan=AUDITED（`ctf_status`/`ctf_export`/账本持久化可读回）；② 目标框架去 flag-grep——
> 目标是**启发式完成挑战目标**（完整利用链/提权证据），flag 仅是真实输出时的终局确认，
> 明令禁止盲扫 `ctf{`/`flag{` 字面量（检测正则不变）。

## 安装

1. 把本目录放入 `~/.dsh/.agent-presets/ctf-expert/`（或你的 preset root）；
2. 在 dsh Web 的 Agent Preset 选择器里选 **CTF Expert** 开一个新会话；
3. 下发 CTF 任务（如「复现 CVE-2026-43499 并给出 PoC」）。

## 提示词注入契约（v0.7.0）

系统提示词**只**注入内置极简模式的那一句 persona（逐字）：

> You are a helpful software engineer assistant.

其余一切 CTF 指引（阶段规则、产物 plan + which skill used、English thinking、实时账本状态）一律作为**用户提示词**注入——经 assembly 的 `contexts` 通道渲染为 user-role 快照（自动取代旧快照），绝不进 system。

## Round-1 协议 + 三阶段设计（v0.8.0）

| 阶段 | 名称 | 行为 |
|---|---|---|
| phase 0 | think（极简深思考轮） | **严格镜像 harness 内置 `minimal` 预设**：system = 仅内置 persona 一句、工具面 = shell + `str_replace_editor` 双工具。**本轮零工具调用**：只深思考、不急着给结论。本轮产物（纯文本）= **plan + which skill used**；产物文本步结束即同轮唤醒进入 review 门控 |
| phase 1 | standard（含 review 门控） | **先审后行**：review=PENDING 时执行工具被**物理锁死**（目录只剩 ctf_* + subagent 系，无 shell/file/探测）。顺序 = 补齐 plan 文本 → `ctf_plan` 落账 → **`subagent`**（run_in_background:false）排查完善 plan → `ctf_review`（review=DONE）解锁；随后开放完整 Standard 目录 + 结算规矩（每次环境交互后必须 `ctf_step` 结算）。仅 review=DONE 后才可能进入 phase 2 |
| phase 2 | hunt（攻坚） | 首个里程碑或 8 步后：奖惩机制全文 + loop 熔断强化 + 失败轨迹上下文净化（PDF P7）注入每轮 user 通道 |

> **v0.8.0 死循环修复（实测）**：CTF 会话日志显示 agent 在极简轮无限 bash 探测（phase 恒
> 0、无 plan 产物）——根因是旧版在 assemble 用 `session.events` 判首个 tool/call，而运行期
> Session 类不暴露 `.events`（durable API 是 `snapshotEvents()`），推进恒不触发。现已改用
> **`ctx.on('session/event')` 持久事件钩子** + 双形状读取助手：首个 tool/call、或 phase-0
> 文本步（assistant text 无 tool）在事件**发生当时**同步推进 phase 1。

> **语言策略（v0.6.0）**：极简轮 persona、phase 指引、statusText、工具描述与返回、
> 技能目录字段全部为英文（纯 ASCII）；persona 明令 "Think and reason in English only"。
> 引擎/预设内部注释保留中文作溯源标注，不进入 prompt。

## 模型侧工具（每会话自动注册）

| 工具 | 作用 |
|---|---|
| `ctf_status` | 实时账本：phase / totalScore / 停滞计数 / 里程碑 / hackMode / skill / goal / `review=PENDING\|DONE` / `product=DELIVERED` / 待执行指令 |
| `ctf_step` | **必调**：结算一次环境交互（命令 + 输出/摘要）→ 得分 + 指令（state_inspector + reward_evaluator 合一）；未结算动作在此扣纪律分 |
| `ctf_plan` | 记录分支/目标/假说/首探 + **which skill used**（技能取值见 `CTF_SKILLS`） |
| `ctf_review` | **v0.8.0**：登记 subagent 排查完成（review=DONE）→ 解锁执行工具；review=PENDING 时 shell/file/探测工具不在目录（"完善后再执行"由工具面强制） |
| `ctf_complete` | **v0.9.0**：显式声明**用户提示词目标完成**（goal=ACHIEVED，+10 里程碑，替代 flag 验证） |
| `ctf_backtrack` | 熔断回溯：收到 `BACKTRACK` 后强制换方向，停滞/重复计数清零 |
| `ctf_hack` | **奖励黑客（reward-hack）**：非常规思维转向，激活 hackMode 并外推攻击面（计分/Oracle/flag 交付、数据/供应链/权限边、侧信道、质疑题目假设）；hackMode 下新里程碑按乘数结算 |
| `ctf_export` | 导出 append-only + FNV-1a 哈希链账本 JSON（溯源/审计/存档） |

## 机制摘要

- **Round-1 协议（v0.8.0）**：phase 0 只深思考产 plan + which skill used；产物先由
  **subagent 排查完善**（ctf_plan → subagent → ctf_review）后才解锁 shell/file 执行工具——
  门控由**工具面锁**强制，不依赖模型自觉；引擎新增 `productDelivered`/`reviewState` 随账本持久化。
- **奖励黑客（v0.4.0）**：常规路径停滞或存在更快路径时允许并鼓励非常规思维；首次 `ctf_hack`
  把会话置为 `hackMode=ON`，此后新里程碑按 `rewardHackMultiplier` 结算（默认 1.0，可配 >1）。
  证据仍须来自真实命令回显。
- **纪律看门狗（v0.3）**：`tools/result` 监听每个非 ctf 工具动作并记账；未用 `ctf_step` 结算
  的动作在下次结算按 -0.05/个 扣分（P7 强制评估近似）。v0.8.0：subagent*/send_message/
  list_agents/interrupt_agent/job_* 等推理/委托工具豁免。
- **账本哈希链**：每条 journal 记录带 FNV-1a 链式哈希，`ctf_export` 可复核完整性（篡改可检出）。
- **技能路由 + 终局保证（v0.5.0）**：`CTF_SKILLS` 12 项题型→技能索引（web-runtime /
  reverse-pwn / crypto-mobile / identity-windows / cloud-container / pcap-protocol /
  stego-forensic / patch-diff / code-audit / malware-config / zip-archive / llm-agent，
  借用 [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) 的路由模型）；
  `goalAchieved` 由 `ctf_complete` 显式声明（v0.9.0，替代 flag 自动结算）。

## 账本持久化（可选）

`agent.cordis.yml` → `ctf-bootstrap` → `config.persistDir` 配一个绝对目录即启用：
每次结算/回溯/计划/阶段推进自动把引擎快照写入 `<persistDir>/<sessionId>.json`，
进程重启后同会话自动恢复续跑。缺省 off（仅内存，最安全）。

## 文件

- `agent.cordis.yml` — 预设组合（31 rows，无重复 id）
- `preset.yml` — 展示元数据（name/description）
- `ctf-engine.mjs` — 纯逻辑零依赖引擎（分层奖励/惩罚、停滞 BACKTRACK、一次性里程碑、
  FNV-1a 哈希链账本、纪律看门狗、reward-hack、CTF_SKILLS 路由、goalAchieved、
  round-1 门控 productDelivered/reviewState）
- `ctf-bootstrap.mjs` — 运行时插件（8 工具含 ctf_review/ctf_complete + 三阶段门控 + review 工具面锁 +
  session/event 推进 + tools/result 看门狗 + 可选持久化）
- 设计文档 / 测试 / 变更溯源（`TRACE.md`）在工作区 `/home/xiatian/default/ctf-expert/`

## 状态（v0.9.0）

- [x] 引擎（分层奖励 / 步成本 / 重复指数惩罚 / 停滞 BACKTRACK / 一次性里程碑 / 快照恢复）
- [x] 奖励黑客机制（`ctf_hack` + hackMode + 非常规攻击面向量库 + 乘数结算）
- [x] 纪律看门狗（subagent*/委托工具豁免）+ 账本 FNV-1a 哈希链（篡改可检出）
- [x] 技能路由（v0.5.0）
- [x] **极简模式严格对齐内置 minimal + 全英文 prompt + 强制英语思考（v0.6.0）**
- [x] **system 只注入内置 persona 一句，其余全部走用户提示词通道（v0.7.0）**
- [x] **死循环修复 + Round-1 协议（v0.8.0）** + **v0.8.1 三修复（自动唤醒/exec 会话绑定/子代理跳过协议）**
- [x] **结构化 plan 落账 + 去 flag-grep（v0.8.2）**
- [x] **去除 flag 验证、目标完成 = 用户提示词目标 + ctf_complete 显式声明；audit 通过后 todo_write 写计划（v0.9.0）**
- [x] 预设结构校验（31 rows，无重复 id）与真实挂载验证（standingKeyFor = MOUNT OK）
- [ ] 最终验收：用户在 picker 开 CTF Expert 会话，确认 round-1 产物 → subagent 排查 → todo 执行 → ctf_complete 全链路
- [x] 发布：代码已 push 到本仓库 `main`（v0.9.0 待推送）

## 测试

```bash
node test/engine.test.mjs      # 84 断言（奖励/惩罚/停滞/熔断/快照/哈希链/看门狗/reward-hack/技能/round-1门控/结构化plan/ctf_complete 目标声明）
node test/bootstrap.sim.mjs    # 62 断言（工具注册 8 + session/event 推进 + review 门控工具锁 + todo 引导 + ctf_complete + 三阶段门控 + 持久化 + 看门狗 + 英文断言）
```
