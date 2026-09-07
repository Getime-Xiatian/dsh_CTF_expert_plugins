/**
 * ctf-bootstrap — CTF Expert 预设的运行时插件（零外部依赖，模式同 router-bootstrap）。
 *
 * 三阶段路由（对应目标要求：先极简一轮思考 → 后标准全工具 → 然后引入奖惩/熔断）：
 *   phase 0 think    极简：首轮请求工具面 = shell + 少量 CTF 工具，上下文体被清空，
 *                    提示词要求先做 ONE focused planning round 再动手（"专注于一轮思考"）。
 *   phase 1 standard 首个持久工具调用后：开放完整 Standard 工具目录，注入结算规矩
 *                    （每次环境交互后必须 ctf_step 结算，自主探路）。
 *   phase 2 hunt     首个里程碑 / 步数达标后：奖惩机制全文 + loop 熔断强化 +
 *                    失败轨迹上下文净化（PDF P7）注入每轮 system。
 *
 * 阶段判定全部基于持久 session 事件（tool/call），resume/reload 后保持一致；
 * 引擎账本（ctf-engine）始终在跑：BACKTRACK 熔断在 phase 1 起即实时可见。
 *
 * v0.5.0：极简一轮思考产物明确为 plan + which skill used —— CTF_SKILLS 技能路由
 * （借用 zhaoxuya520/reverse-skill 的题型分类，仅索引不内联代码）；ctf_plan 带
 * skill 参数；状态行与注入文案携带 goal=ACHIEVED/PENDING 终局保证位。
 */

import { createEngine, ENGINE_VERSION, HACK_VECTORS, CTF_SKILLS } from './ctf-engine.mjs'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

export const name = 'ctf-bootstrap'

export const inject = ['systemPrompt', 'tools']

/** 可被 agent.cordis.yml 的 config 覆盖的默认值。 */
const DEFAULTS = {
  /** phase 0 保留的工具面（shell 自动补上）。 */
  phase0Tools: [
    'str_replace_editor', 'ctf_status', 'ctf_plan', 'ctf_step', 'ctf_backtrack', 'ctf_export', 'ctf_hack',
  ],
  /** phase 1 → 2 的步数阈值（或任一里程碑出现即提前进入）。 */
  phase2AfterSteps: 8,
  /** 传给引擎的覆盖（停滞上限等）。 */
  engine: {},
  /**
   * 账本跨重启持久化目录。留空/缺省 = 仅内存（不写盘，最安全）。
   * 设为绝对目录后：每次结算/回溯/计划/阶段推进自动把引擎快照写为
   * `<persistDir>/<sessionId>.json`，进程重启后 engineFor 自动恢复。
   */
  persistDir: '',
}

/** 极简一轮思考（phase 0）。产物要求 = plan + which skill used（见 ctf_plan 的 skill 参数）。 */
const THINK_SECTION = [
  '【CTF Expert · 阶段 0 · 极简 · 一轮思考】',
  '当前为极简模式：只保留 shell 与少量结算/规划工具，先专注一轮分析，不急着铺开。',
  '本轮产物必须包含两部分：',
  '1. plan —— 识别目标（资产/服务/版本/暴露面），提出一个明确假说，选定 ONE 个最高价值的首个探测动作，',
  '    并想清楚证据：拿到什么输出才算进展（里程碑）？',
  '2. which skill used —— 声明你为本轮选定的技能路由（CTF_SKILLS 之一：' +
    CTF_SKILLS.map((s) => s.id).join(' / ') + '）；',
  '    在调用 ctf_plan 时把 skill 参数一并填上。',
  '禁止：无目标扫描、重复已做过的检查、在缺乏证据时盲目扩大攻击面、plan 与 skill 缺项。',
].join('\n')

/** 标准模式（phase 1）：全工具 + 结算规矩。 */
const STANDARD_SECTION = [
  '【CTF Expert · 阶段 1 · 标准模式 · 结算规矩】',
  '工具目录已全量开放。自主探路要求：',
  '1. 每次与环境交互后，必须调用 ctf_step 结算（附上命令与输出/关键摘要）——跳过结算 = 该步不算进展；',
  '2. 实时账本见 ctf_status：累计分 totalScore 是你唯一的优化目标，里程碑首达一次性加分；',
  '3. 每步有成本、连续重复命令会指数扣分、语法/失败调用扣分；',
  '4. 停滞计数达 3 时你会收到 BACKTRACK 熔断指令——必须立即换方向，不得原地打转。',
  '5. 换分支/换方向时用 ctf_plan 记录 objective + which skill used（见 ctf_status 的技能路由表，',
  '按主导证据面选最窄的技能：Web→web-runtime、二进制/pwn→reverse-pwn、密码/移动→crypto-mobile、',
  '域/身份→identity-windows、云/容器→cloud-container、抓包→pcap-protocol、隐写取证→stego-forensic、',
  'N-day/CVE→patch-diff、源码→code-audit、样本→malware-config、ZIP→zip-archive、AI 应用→llm-agent）。',
  '6. 得分是唯一目标：常规路径卡住或存在更快路径时，允许并鼓励非常规思维——',
  '用 ctf_hack 外推攻击面（攻计分/判题/Oracle/flag 交付面、数据/供应链/权限边、侧信道、质疑题目假设），',
  '挖掘漏洞与捷径；证据必须来自真实命令回显，自述不算。',
  '终局保证：flag 证据未结算（goal=ACHIEVED）前，不得宣告任务完成；继续探路/换技能/换分支。',
  '目标：让 totalScore 持续上升，直到取得 flag。',
].join('\n')

/** 攻坚模式（phase 2）：奖惩机制全文 + loop 熔断强化 + 上下文净化（PDF P5–P7）。 */
const HUNT_SECTION = [
  '【CTF Expert · 阶段 2 · 攻坚模式 · 奖惩机制（生效中）】',
  '得分规则：新服务/端口首达 +1.0 · 漏洞确认 +2.0 · 提取哈希 +2.0 · 获取权限 +3.0 · 取得 flag +10.0；',
  '首个新命令组合 +0.1（自主探路鼓励）；每步 -0.05；连续重复命令 -0.2/-0.4/-0.8 指数递增；无效/失败调用 -0.5。',
  '防刷分：同一里程碑只结算一次，来回横跳不赚分；flag 必须由真实输出证据结算，自述不算。',
  '熔断（loop break）：若上一条指令是 BACKTRACK，先调用 ctf_backtrack 说明原因并选择全新切入点，',
  '然后才可继续——不得重试同一命令或其变体。',
  '上下文净化：失败的长输出只保留一句话总结（如 [记录: 路径 X 失败，原因：…]），不要让旧错误轨迹持续污染判断。',
  '每一轮都应让 totalScore 单调上升；连续 2 轮无新证据视为当前分支死亡，强制换分支（ctf_plan 记录分支）。',
  '奖励黑客（reward-hack）：常规分支两度熔断或长时间无里程碑时，调用 ctf_hack 转入非常规思维——',
  '把"判题/计分/flag 交付"本身纳入攻击面：评分 API/Oracle 端点、隐藏数据与备份、供应链缓存、',
  '权限边界（越权/符号链接/临时文件）、侧信道差异、以及"题目假设本身是错的"。',
  '非常规突破一旦得手就是真实的里程碑加分（reward-hack 模式下里程碑可能带乘数）。',
  '终局：取得 flag 后调用 ctf_export 导出账本，作为任务完成的证据链；goal=ACHIEVED 之前禁止宣告完成。',
].join('\n')

/** 一行的实时状态（每轮注入，指令可见性核心）。 */
function statusText(st) {
  let line = `[CTF] phase=${st.phase}(${st.phaseName}) score=${st.totalScore} step=${st.stepCount} stagnant=${st.stagnantSteps}/${st.stagnantLimit} directive=${st.lastDirective}`
  if (st.hackMode) line += ' hackMode=ON'
  if (st.lastSkill) line += ` skill=${st.lastSkill}`
  line += st.goalAchieved ? ' goal=ACHIEVED' : ' goal=PENDING'
  if (st.milestonesHit.length) line += ` milestones=[${st.milestonesHit.join(',')}]`
  if (st.pendingActions > 0) {
    line += ` unsettled=${st.pendingActions}`
  }
  if (st.lastDirective === 'BACKTRACK') {
    line += '\n⚠ 熔断中：当前思路连续无收益。必须先 ctf_backtrack 换方向，禁止重复同一命令。'
  }
  if (st.hackMode) {
    line += `\n🎯 reward-hack 模式：常规路径不受信任。用 ctf_hack 枚举非常规攻击面并挑一条立刻探测；里程碑按乘数 ${st.multiplier ?? 1}x 结算（突破 ${st.hackBreakthroughs} 次）。`
  }
  if (st.pendingActions > 0) {
    line += '\n⚠ 纪律：有未用 ctf_step 结算的环境动作；下次结算会按 -0.05/个 扣分。每次环境交互后必须结算。'
  }
  if (!st.goalAchieved) {
    line += '\n🎯 终局保证：尚未取得 flag 证据。在 GOAL_ACHIEVED 之前不得宣告任务完成——继续探路或换技能，直到 ctf_status 显示 goal=ACHIEVED。'
  }
  return line
}

export function apply(ctx, config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  cfg.phase0Tools = [...(cfg.phase0Tools || DEFAULTS.phase0Tools)]
  const engines = new Map() // session.id -> engine

  function persistFileFor(sessionId) {
    const safe = String(sessionId).replace(/[^A-Za-z0-9._-]/g, '_')
    return join(cfg.persistDir, safe + '.json')
  }

  /** 仅当配置了 persistDir 才写盘；失败静默（内存账本不受影响）。 */
  function maybeSave(sessionId) {
    if (!cfg.persistDir) return
    const eng = engines.get(sessionId)
    if (eng === undefined) return
    try {
      mkdirSync(cfg.persistDir, { recursive: true })
      writeFileSync(persistFileFor(sessionId), JSON.stringify(eng.snapshot()), 'utf8')
    } catch { /* 写盘失败不阻断会话 */ }
  }

  function engineFor(sessionId) {
    let eng = engines.get(sessionId)
    if (eng === undefined) {
      eng = createEngine(sessionId, { config: cfg.engine || {} })
      if (cfg.persistDir) {
        try {
          const file = persistFileFor(sessionId)
          if (existsSync(file)) {
            const raw = readFileSync(file, 'utf8')
            eng.restore(JSON.parse(raw)) // 进程重启后按快照续跑
          }
        } catch { /* 无快照或损坏：全新开始 */ }
      }
      engines.set(sessionId, eng)
    }
    return eng
  }

  function currentSession() {
    const agent = ctx.get('agent')
    return agent?.session
  }

  // ── 工具注册（与 router-bootstrap 相同的零依赖方式）───────────────
  const registerTool = (tool) => {
    ctx.effect(() => ctx.tools.register({
      ...tool,
      parameters: toJsonSchema(tool.parameters),
      output: tool.output || { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
    }))
  }

  function toJsonSchema(spec) {
    const properties = {}
    const required = []
    for (const [key, meta] of Object.entries(spec || {})) {
      const prop = { type: meta.type }
      if (Array.isArray(meta.enum)) prop.enum = meta.enum
      if (meta.description) prop.description = meta.description
      properties[key] = prop
      if (meta.required) required.push(key)
    }
    return { type: 'object', properties, required, additionalProperties: false }
  }

  registerTool({
    name: 'ctf_status',
    description: 'Show the CTF Expert ledger: current phase, totalScore, step/stagnation counters, milestone history, pending directive. Call it whenever you need your live score or before choosing the next move.',
    parameters: {},
    execute() {
      const session = currentSession()
      if (!session) return 'no agent session'
      const st = engineFor(session.id).status()
      return [
        statusText(st),
        `engine=${ENGINE_VERSION} discovered=[${st.discovered.join(',') || '-'}] branches=${st.branches}`,
        '技能路由（which skill used，来自 zhaoxuya520/reverse-skill 的题型分类）：' +
          CTF_SKILLS.map((s) => `${s.id}=${s.label}`).join(' | '),
        '规则摘要：每次环境交互后调用 ctf_step 结算；停滞 3 步触发 BACKTRACK（先 ctf_backtrack 再换方向）；同一里程碑只结算一次；goal=ACHIEVED 前不得宣告完成。',
      ].join('\n')
    },
  })

  registerTool({
    name: 'ctf_step',
    description: 'Settle one interaction with the environment (reward evaluator + state inspector): pass the command you ran, the raw output (or its head/key part) and whether it errored. The engine detects milestone evidence in the output, applies step cost / repeat penalty / novelty bonus, updates the stagnation counter and returns your score plus a directive. Mandatory after every environment interaction.',
    parameters: {
      command: { type: 'string', description: 'the exact command / tool action performed', required: false },
      output: { type: 'string', description: 'environment output text (or a faithful key excerpt)', required: false },
      error: { type: 'boolean', description: 'true when the command failed or returned an error', required: false },
    },
    execute(args) {
      const session = currentSession()
      if (!session) return 'no agent session'
      const eng = engineFor(session.id)
      const rec = eng.tick({
        command: args.command,
        output: args.output,
        error: !!args.error,
      })
      maybeSave(session.id)
      const lines = [
        statusText({ ...eng.status(), lastDirective: rec.directive }),
        `step reward=${rec.reward} (cost/penalty/novelty already applied) newEvents=[${rec.newEvents.join(',') || '-'}]`,
      ]
      if (rec.newEvents.length) lines.push(`里程碑首达结算：${rec.newEvents.join(', ')}`)
      if (rec.directive === 'BACKTRACK') {
        lines.push('BACKTRACK：收益连续为负。放弃当前方向 → 调用 ctf_backtrack 说明原因 → 选一个完全不同的切入点。')
      } else if (rec.directive === 'GOAL_ACHIEVED') {
        lines.push('GOAL_ACHIEVED：检测到 flag 证据。调用 ctf_export 导出账本作为完成证据，然后向用户汇报。')
      }
      return lines.join('\n')
    },
  })

  registerTool({
    name: 'ctf_backtrack',
    description: 'Break the current loop and switch strategy: resets the stagnation/repeat counters (milestones stay discovered), records the reason in the journal. Mandatory when the directive is BACKTRACK. Afterwards pick a fundamentally different angle — not a variant of the failed one.',
    parameters: {
      reason: { type: 'string', description: 'why this branch died (error/loop/dead-end evidence)', required: false },
      from: { type: 'string', description: 'what approach is being abandoned', required: false },
    },
    execute(args) {
      const session = currentSession()
      if (!session) return 'no agent session'
      const eng = engineFor(session.id)
      const st = eng.backtrack({ reason: args.reason, from: args.from })
      maybeSave(session.id)
      return [
        statusText(st),
        '已熔断回溯：停滞计数归零。现在选一个完全不同的技术路径（换工具库 / 换攻击面 / 换入口），不要再碰刚才的方向。',
      ].join('\n')
    },
  })

  registerTool({
    name: 'ctf_plan',
    description: 'Record one exploration branch/plan (autonomous path-finding evidence + which-skill-used). Required product of the minimal round: pass objective/hypothesis/firstProbe AND the skill (one of the CTF_SKILLS ids: ' + CTF_SKILLS.map((s) => s.id).join(', ') + ') you will use on this branch. Use it in the minimal round before acting and whenever you switch to a new branch.',
    parameters: {
      objective: { type: 'string', description: 'what this branch tries to achieve', required: false },
      hypothesis: { type: 'string', description: 'the assumption being tested', required: false },
      firstProbe: { type: 'string', description: 'the first validating action', required: false },
      skill: { type: 'string', description: 'which skill used (CTF_SKILLS id, e.g. web-runtime / reverse-pwn / crypto-mobile / identity-windows / cloud-container / pcap-protocol / stego-forensic / patch-diff / code-audit / malware-config / zip-archive / llm-agent)', required: false },
    },
    execute(args) {
      const session = currentSession()
      if (!session) return 'no agent session'
      const eng = engineFor(session.id)
      const res = eng.plan(args)
      maybeSave(session.id)
      return `分支 #${res.branches} 已记录（phase=${res.phase} ${res.phaseName}）skill=${res.skill || '(未声明)'}。执行首个探测，然后用 ctf_step 结算其输出。`
    },
  })

  registerTool({
    name: 'ctf_export',
    description: 'Export the full append-only ledger (score history, milestones, directives, plan branches) as JSON for auditing / persistence (traceability). Save it to a file in the workspace if you need it to survive restarts.',
    parameters: {},
    execute() {
      const session = currentSession()
      if (!session) return 'no agent session'
      const ledger = engineFor(session.id).exportLedger()
      return JSON.stringify(ledger, null, 2)
    },
  })

  registerTool({
    name: 'ctf_hack',
    description: 'Reward-hacking pivot: switch to unconventional thinking to maximize score. When conventional branches stall, expand the attack surface — attack the scoring/judging/flag-delivery surface itself (score API, Oracle endpoint, hidden data/backups, supply-chain caches, privilege edges, side channels) or question the challenge assumptions. First call activates reward-hack mode (new milestones settle at the configured multiplier). Evidence must still come from real command output. Returns the vector library and your live standing.',
    parameters: {
      vector: {
        type: 'string',
        description: 'one of: ' + HACK_VECTORS.join(' / '),
        required: false,
      },
      hypothesis: { type: 'string', description: 'the unconventional hypothesis to test', required: false },
      why: { type: 'string', description: 'why the conventional path is stuck / why this shortcut may exist', required: false },
      target: { type: 'string', description: 'what surface is attacked (score API / flag store / hidden data / …)', required: false },
    },
    execute(args) {
      const session = currentSession()
      if (!session) return 'no agent session'
      const eng = engineFor(session.id)
      const res = eng.unconventional({
        vector: args.vector,
        hypothesis: args.hypothesis,
        why: args.why,
        target: args.target,
      })
      maybeSave(session.id)
      const lines = [
        res.activated
          ? `🎯 reward-hack 模式已激活（乘数 ${res.multiplier}x）——常规路径不再受信任，攻击面外推开始。`
          : `已追加非常规分支 #${res.hackBranches}（vector=${res.vector}）。`,
        '向量库：' + HACK_VECTORS.join(' | '),
      ]
      if (!args.vector) lines.push('下一步：从向量库里选一条最可能藏捷径的，立刻用真实命令探测，然后 ctf_step 结算。')
      return lines.join('\n')
    },
  })

  // ── 纪律看门狗：每次非 ctf 工具调用（真实环境动作）都被记账；
  //    未用 ctf_step 结算的动作在下次结算时按 -0.05/个 扣分（P7 中间件强制评估近似）。
  ctx.on('tools/result', (exec, result) => {
    try {
      const agent = exec && exec.agent
      if (!agent) return
      const eng = engines.get(agent.id)
      if (eng === undefined) return
      const name = exec.name
      if (typeof name === 'string' && name.startsWith('ctf_')) return
      eng.noteAction(name, !!(result && result.isError))
    } catch { /* 观察者失败被隔离，不影响工具结果 */ }
  })

  // ── 每轮 system 组装：注入阶段/规则/实时状态；phase 0 裁剪工具面 ──────
  ctx.on('system-prompt/assemble', async (_assembly, context, next) => {
    const agent = context.agent
    const session = agent?.session
    if (session === undefined) return next()

    const assembled = await next()
    const eng = engineFor(session.id)
    const hasToolCall = (session.events || []).some((event) => event.type === 'tool/call')

    // 阶段推进（由持久 session 事件驱动，resume/reload 不丢）
    if (hasToolCall && eng.state.phase === 0) eng.advancePhase(1, 'standard')
    if (eng.state.phase === 1 &&
        (eng.state.milestonesHit.length > 0 || eng.state.stepCount >= cfg.phase2AfterSteps)) {
      eng.advancePhase(2, 'hunt')
    }
    maybeSave(session.id)

    const sections = [...(assembled.sections || [])]
    const st = eng.status()
    sections.push({ name: 'ctf-status', text: statusText(st), order: 900 })

    if (!hasToolCall && eng.state.phase === 0) {
      // 极简模式：一轮思考。上下文清零聚焦本轮；工具面裁剪到最小核心。
      sections.push({ name: 'ctf-think', text: THINK_SECTION, order: 901 })
      const available = new Set((assembled.tools || []).map((tool) => tool.name))
      const shell = available.has('pwsh') ? 'pwsh' : available.has('bash') ? 'bash' : null
      if (shell === null) {
        return { ...assembled, sections, contexts: [], tools: assembled.tools }
      }
      const core = new Set([shell, ...cfg.phase0Tools])
      return {
        ...assembled,
        sections,
        contexts: [],
        tools: (assembled.tools || []).filter((tool) => core.has(tool.name)),
      }
    }

    sections.push(eng.state.phase === 1
      ? { name: 'ctf-standard', text: STANDARD_SECTION, order: 901 }
      : { name: 'ctf-hunt', text: HUNT_SECTION, order: 901 })

    return { ...assembled, sections }
  })
}
