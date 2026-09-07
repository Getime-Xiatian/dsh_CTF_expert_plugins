/**
 * ctf-engine — CTF Expert 奖励/熔断状态机（纯逻辑，零依赖）。
 *
 * 设计溯源：本地 AI 自主执行优化方案（Gemini 会话导出，2026-09-07 附件，P4–P7）——
 *   - P4 分层奖励：稀疏终局奖励 / 一次性里程碑奖励 / 内在好奇奖励（RND 风格）。
 *   - P5 惩罚与效率约束：步数成本 / 无意义重复指数递增惩罚 / 无效指令惩罚；
 *     状态哈希与外部队列（Oracle）判题的反奖励黑客约束。
 *   - P6-P7 Skill 化实现：state_inspector + reward_evaluator 双 Skill；
 *     RewardControllerSkill 示例类（max_stagnant_steps=3，停滞→强制回溯指令，
 *     里程碑单次结算、突破后停滞计数归零、累计得分驱动决策信号）。
 *
 * 本文件 = PDF P6 `RewardControllerSkill` 的工程化实现 +
 *         P4/P5 的分层奖励表与惩罚/反作弊规则 +
 *         自主探路（novelty/exploration bonus + 回溯点）与 loop 熔断
 *         （停滞计数 + BACKTRACK 指令 + 重复惩罚指数递增）。
 *
 * 关键设计（P5）：
 *   - 里程碑只结算一次（discovered 集合），在两个状态间来回跳不刷分；
 *   - 引擎只信 ctf_step 传入的"环境输出证据"和显式事件；模型无法直接改分
 *     （无加分支接口，仅回溯/计划/非常规分支等固定动作）；
 *   - 里程碑只按 ctf_step 传入的"环境输出证据"和显式事件结算；v0.9.0 起终局不再
 *     自动验证输出中的 flag 字面量，用户提示词目标完成由 ctf_complete 显式声明；
 *   - 每次 tick 全量入 journal（append-only + FNV-1a 哈希链，篡改可检出）；
 *
 * v0.3：纪律看门狗（noteAction → 未结算动作在结算时按 -0.05/个 扣分）；
 * v0.4：奖励黑客（reward-hack）机制——用户需求"非常规思维发现漏洞最大化得分"：
 *   unconventional()/HACK_VECTORS 外推攻击面（计分/Oracle/数据/供应链/权限边/
 *   侧信道/质疑假设），hackMode 下新里程碑按 rewardHackMultiplier 加成结算。
 * v0.5：技能路由 + 终局保证（goal: 借用 zhaoxuya520/reverse-skill 的路由模型）——
 *   极简一轮思考的产物被明确为 "plan + which skill used"：CTF_SKILLS 目录 =
 *   reverse-skill 题型分类的轻量引用（web/pwn/crypto/identity/pcap/stego/forensic/
 *   patch-diff/code-audit/cloud…）；plan() 记录所选 skill；status().goalAchieved
 *   暴露 FLAG 终局达成位（GOAL_ACHIEVED 前会话不得宣告完成）。
 * v0.6.0：全部 LLM 可见文本英文化 + CTF_SKILLS 目录字段（label/when/tools）英文化
 *   （内置极简模式为英文 prompt；强制 LLM 用英语思考）。
 * v0.8.0：round-1 协议 —— 极简一轮思考产物（plan + which skill used）产出后先由
 *   subagent 排查完善（productDelivered / reviewState 门控），完善后才解锁执行；
 *   引擎只记账门控状态，tick 奖励数学不变（执行门控由 bootstrap 工具面实施）。
 * v0.8.1：插件版本随 bootstrap 修复对齐（本文件逻辑未变）。
 * v0.8.2：结构化 plan 记录（state.plan 全文本 + objective/hypothesis/firstProbe/
 *   milestone/skill）——ctf_plan 存初版、ctf_review(audit 通过) 把 audit deltas 并入
 *   plan 并标记 audited，账本持有"完善后的 plan"，不再只是会话纯文本。
 * v0.9.0：**去除 flag 验证环节**——不再从输出字面量自动检测 FLAG 完成；终局 =
 *   用户提示词目标完成，由模型经 ctf_complete **显式声明**（goalCompleted +
 *   OBJECTIVE_COMPLETED +10.0 里程碑，受 reward-hack 乘数；幂等）。
 * v0.9.1：audit 通过后到 todo 写计划之间新增执行门控字段 tasksWritten
 *   （markTasks()）——实测模型会跳过纯提示词的 todo_write 步骤直接探测。
 */

export const ENGINE_VERSION = '0.9.1'

/** FNV-1a 32-bit（账本哈希链用；纯 JS 无依赖）。 */
export function fnv1a(str) {
  const esc = encodeURIComponent(String(str))
  let h = 0x811c9dc5
  for (let i = 0; i < esc.length; i++) {
    const ch = esc[i]
    if (ch === '%') {
      const b = parseInt(esc.substr(i + 1, 2), 16)
      h ^= b
      h = Math.imul(h, 0x01000193)
      i += 2
    } else {
      h ^= ch.charCodeAt(0) // encodeURIComponent 未转义部分均为单字节 ASCII
      h = Math.imul(h, 0x01000193)
    }
  }
  return (h >>> 0).toString(16).padStart(8, '0')
}

/** 默认配置 = PDF P5 推荐初值的引擎化（可被 preset config 覆盖）。 */
export const DEFAULT_CONFIG = {
  /** 每步固定损耗（PDF P5: -0.05）—— 迫使行动精准、减少冗余调用。 */
  stepCost: 0.05,
  /** 探索/好奇奖励（PDF P4 R_explore +0.1；P5 α 建议 0.05~0.1）。 */
  exploreBonus: 0.1,
  /** 连续重复命令惩罚基数，第 k 次重复 = base * 2^(k-1)（PDF P5: -0.2,-0.4,-0.8…）。 */
  repeatBase: 0.2,
  /** 语法/无效/失败指令惩罚（PDF P5: 语法扣分）。 */
  errorPenalty: 0.5,
  /** 停滞上限：连续收益 ≤0 达到该值即触发 BACKTRACK（PDF P6: max_stagnant_steps=3）。 */
  stagnantLimit: 3,
  /** 纪律扣分/未结算动作（P7 中间件强制评估近似）：结算时按每个未结算动作扣分。 */
  disciplinePerAction: 0.05,
  /**
   * 奖励黑客（reward-hack）机制参数（用户需求：非常规思维最大化得分）。
   * rewardHackMultiplier：进入 reward-hack 模式后，新里程碑结算值 × 该系数
   *   （1.0 = 不加成；>1.0 表示计分面本身偏爱非常规突破——训练方故意留下的
   *   "奖励规格漏洞"，模拟 PDF P2/P4 描述的 reward hacking 收益结构）。
   */
  rewardHackMultiplier: 1.0,
  /** 里程碑价值表（PDF P4/P6: NEW_SERVICE +1.0 / ACCESS +3.0 / 目标完成 +10.0）。 */
  milestones: {
    NEW_SERVICE_DISCOVERED: 1.0, // 新服务/端口/接口暴露
    VULN_CONFIRMED: 2.0,         // 漏洞/版本脆弱性确认
    ACCESS_GAINED: 3.0,          // 获取低权限 shell / 交互
    HASH_EXTRACTED: 2.0,         // 提取到哈希/凭据
    // v0.9.0：不再有 FLAG 自动验证——终局里程碑 = 用户提示词目标完成
    //（仅由 ctf_complete 显式声明授予，见 complete()）。
    OBJECTIVE_COMPLETED: 10.0,
  },
}

/**
 * 奖励黑客的非常规攻击面清单（ctf_hack 的向量库；来自 PDF P2 奖励黑客行为
 * ——盗评测答案/攻数据源/环境漏洞/侧信道，+ 经典 CTF 捷径分类）。
 * 每个向量都面向"挑战环境/计分交付面"，要求真实命令证据，不做自述伪造。
 */
export const HACK_VECTORS = [
  'score-surface',   // 攻计分/判题面：评分 API、Oracle 端点、flag 交付通道
  'data-surface',    // 挑战数据面：隐藏文件/备份/容器元数据/env/进程参数/历史
  'supply-chain',    // 依赖供应链：包缓存/镜像层/构建产物/旧版本/补丁 diff
  'privilege-edge',  // 环境权限边：越权读写/符号链接/临时文件竞争/ACL 误配
  'side-channel',    // 侧信道/推理面：时序/错误回显差异/布尔盲注式二分探测
  'assumption-break' // 约束外推：质疑题目假设（目标不是你以为的那个/入口不止一个）
]

/**
 * 技能路由目录（v0.5.0）——"which skill used" 的取值集合。
 *
 * 溯源：借用 https://github.com/zhaoxuya520/reverse-skill 的路由模型——
 * 该仓库按 目标类型/用户意图/工具链 三轴把任务路由到最窄的下游技能模块
 * （skills/routing.md + CTF-Sandbox-Orchestrator/ctf-sandbox-orchestrator/SKILL.md
 * 的 "Router Role"：先建沙盒假设 → 沿最小可验证路径 → 按主导证据面切到子技能）。
 * 本项目不内联任何外部代码，只保留一份**题型 → 技能**的轻量索引，供极简一轮
 * 思考的产物 "plan + which skill used" 落账；每个技能条目给出何时使用与首选工具。
 * 各子技能的实现细节仍由模型在环境内自取（工具/库/命令），引擎只按证据结算。
 */
export const CTF_SKILLS = [
  { id: 'web-runtime',      label: 'Web / API runtime',           when: 'Web/API/GraphQL/WebSocket/request smuggling/template rendering/file parsing', tools: 'curl/nuclei/ffuf/sqlmap/burp' },
  { id: 'reverse-pwn',      label: 'Reverse / Pwn',               when: 'binary reverse/stack-heap overflow/ROP/exploit generation', tools: 'ghidra/radare2/gdb/pwntools/checksec' },
  { id: 'crypto-mobile',    label: 'Crypto / Mobile',             when: 'cryptography/mobile/iOS/Android hooking', tools: 'python-crypto/cyberchef/frida/objection' },
  { id: 'identity-windows', label: 'Windows / AD / Identity',     when: 'domain pentest/Kerberos/DPAPI/cert abuse/mailbox', tools: 'bloodhound/impacket/ldapsearch/crackmapexec' },
  { id: 'cloud-container',  label: 'Cloud / Container / K8s',     when: 'cloud metadata/container escape/k8s control plane', tools: 'kubectl/ctr/docker/gcloud/aws cli' },
  { id: 'pcap-protocol',    label: 'PCAP / Protocol replay',      when: 'captures/custom protocol/WebSocket frames', tools: 'tshark/wireshark/scapy/replay' },
  { id: 'stego-forensic',   label: 'Stego / Forensics',           when: 'steganography/memory forensics/disk timeline/file recovery', tools: 'binwalk/steghide/volatility/foremost' },
  { id: 'patch-diff',       label: 'Patch diff to exploit',       when: 'N-day/CVE reproduction: diff patch to PoC', tools: 'ghidriff/diaphora/bindiff/git' },
  { id: 'code-audit',       label: 'Source audit / SAST',         when: 'source-level vuln hunting (injection/deserialization/dangerous APIs)', tools: 'semgrep/codeql/grep' },
  { id: 'malware-config',   label: 'Malware / config extraction', when: 'sample static/dynamic analysis, C2 config extraction', tools: 'strings/floss/yara/cape' },
  { id: 'zip-archive',      label: 'ZIP / PKZIP known-plaintext', when: 'legacy ZipCrypto encrypted archives', tools: 'bkcrack/zipinfo/pkcrack' },
  { id: 'llm-agent',        label: 'AI agent / Prompt injection', when: 'LLM apps/agent tool abuse/prompt injection', tools: 'prompt probing/OWASP LLM Top10' },
]

/** 规范化技能 id：未知 id 回退 'web-runtime' 之外保留原样？→ 统一回退到空并交由调用方校验。
 *  此处只做精确匹配：命中返回条目，未命中返回 null（bootstrap 用于校验参数枚举）。 */
export function resolveSkill(id) {
  return CTF_SKILLS.find((s) => s.id === id) || null
}

/** 环境输出 → 里程碑事件的保守启发式检测器（state_inspector 轻量版）。
 *  仅当输出文本出现强模式才上报；模型也可经 ctf_step 的 events 显式补充，
 *  两者取并集后仍按一次性结算（防刷分）。 */
export function detectEvents(output = '') {
  const events = new Set()
  const s = String(output)
  // v0.9.0: 不再从输出字面量自动验证 flag/目标完成——终局只由 ctf_complete 显式声明。
  if (/\b(?:uid=\d{1,6}\([\w.-]+\)\s+gid=|\b(root|www-data|nobody|daemon|postgres)\b[^\n]{0,40}[#$]\s*$)/m.test(s)) events.add('ACCESS_GAINED')
  if (/(?:exploit|payload|shell)[^\n]{0,60}(?:succeed|success|establish|gained|executed)|segmentation fault|CVE-\d{4}-\d{4,}/i.test(s)) events.add('VULN_CONFIRMED')
  if (/\b[a-f0-9]{32}\b|\b[a-f0-9]{64}\b|\b(?:sha256|md5|hash)[^\n]{0,40}[:=][^\n]{0,80}/i.test(s)) events.add('HASH_EXTRACTED')
  if (/\b\d{1,5}\/(?:tcp|udp)\s+open\b|\b(?:port|service)s?\s+(?:open|discovered|listening)\b|^banner:|^SSH-2\.0-|^220\b/i.test(s)) events.add('NEW_SERVICE_DISCOVERED')
  return [...events]
}

/** 引擎实例工厂。每个 Session 一个实例；状态内存驻留 + journal 供导出。 */
export function createEngine(sessionId, overrides = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...(overrides.config || {}) }
  cfg.milestones = { ...DEFAULT_CONFIG.milestones, ...(cfg.milestones || {}) }

  const state = {
    version: ENGINE_VERSION,
    sessionId,
    createdAt: new Date().toISOString(),
    /** 0=think(极简一轮思考) 1=standard(标准全工具) 2=hunt(奖惩/熔断强化) */
    phase: 0,
    phaseName: 'think',
    totalScore: 0,
    stepCount: 0,
    stagnantSteps: 0,
    lastReward: 0,
    lastDirective: 'NONE',
    discovered: [],
    milestonesHit: [],
    seenCommands: new Set(),
    repeatCount: 0,
    lastCommand: null,
    branches: [],   // ctf_plan 记录的分支/计划（自主探路证据）
    journal: [],
    chainHash: null,        // 账本哈希链尾（防篡改，PDF P5 状态哈希思想）
    pendingActions: 0,      // 未结算动作数（P7 中间件强制评估的纪律看门狗）
    lastAction: null,       // 最近一次未结算工具名
    disciplineApplied: 0,   // 累计纪律扣分
    hackMode: false,        // reward-hack 模式（非常规思维最大化得分）
    hackBranches: [],       // ctf_hack 记录的非常规分支
    hackBreakthroughs: 0,   // reward-hack 模式下取得的新里程碑次数
    lastSkill: null,        // 最近一次 ctf_plan 声明的技能（"which skill used"）
    productDelivered: false, // v0.8.0：极简一轮思考产物（plan+skill 文本）是否已交付
    reviewState: 'pending', // v0.8.0：plan 的 subagent 排查门控 'pending' | 'done'
    plan: null,             // v0.8.2：结构化 round-1 plan 记录（全文本 + audit 合并）
    reviewDeltas: [],       // v0.8.2：audit 子代理返回、并入 plan 的 deltas
    goalCompleted: false,   // v0.9.0：用户提示词目标完成（ctf_complete 显式声明，替代 flag 验证）
    goalSummary: '',        // v0.9.0：目标完成声明摘要（证据链由会话/账本承载）
    tasksWritten: false,    // v0.9.1：audit 通过后是否已用 todo_write 写计划任务（执行门控）
  }

  const norm = (cmd) => (cmd == null ? '' : String(cmd).replace(/\s+/g, ' ').trim())

  /** 入账并串哈希链：每条记录 hash = fnv1a({prev, ...body})，prev=上条 hash。 */
  function pushJournal(entry) {
    const prev = state.chainHash
    const body = { t: new Date().toISOString(), ...entry, prev }
    const hash = fnv1a(JSON.stringify(body))
    state.journal.push({ ...body, hash })
    state.chainHash = hash
    if (state.journal.length > 400) {
      state.journal.splice(0, state.journal.length - 400)
      // 截断后链头失效：把最旧记录的 prev 置空并从下一条重链
      state.journal[0].prev = null
      for (let i = 1; i < state.journal.length; i++) {
        const rec = state.journal[i]
        rec.prev = state.journal[i - 1].hash
        rec.hash = fnv1a(JSON.stringify({ ...rec, prev: rec.prev, hash: undefined, t: rec.t }))
      }
      state.chainHash = state.journal[state.journal.length - 1].hash
    }
  }

  /** 重算整链，返回链是否未被篡改。 */
  function verifyChain() {
    let prev = null
    for (const rec of state.journal) {
      if (!rec || typeof rec.hash !== 'string') return false
      const { hash, ...body } = rec
      if (body.prev !== prev) return false
      if (fnv1a(JSON.stringify(body)) !== hash) return false
      prev = hash
    }
    return true
  }

  /** 看门狗：bootstrap 在 tools/result 中为每个非 ctf 工具调用调用本方法。 */
  function noteAction(name, isError) {
    state.pendingActions += 1
    state.lastAction = String(name || 'tool')
    if (isError) state.lastAction += ' (error)'
  }

  /** 推进会话阶段（由 bootstrap 依据 durable session 事件调用）。 */
  function advancePhase(nextPhase, name) {
    if (state.phase === nextPhase) return false
    const from = state.phase
    state.phase = nextPhase
    state.phaseName = name
    pushJournal({ type: 'phase', from, to: nextPhase, name })
    return true
  }

  /**
   * v0.8.0：登记极简一轮思考的产物已交付（bootstrap 在 phase 0 文本步结束时调用）。
   * 只作账本记录：执行门控（reviewState）与工具面由 bootstrap 实施。
   */
  function markProduct() {
    if (state.productDelivered) return false
    state.productDelivered = true
    pushJournal({ type: 'product', phase: state.phase })
    return true
  }

  /**
   * v0.9.1：登记 audit 通过后的计划已写成 todo 任务（bootstrap 在 tools/result
   * 收到 todo_write 时调用）——在写任务之前执行工具（shell/file/探测）保持锁定，
   * 使 "audit 通过后先 todo 写计划再执行" 由工具面强制（实测模型会跳过纯提示词步骤）。
   */
  function markTasks() {
    if (state.tasksWritten) return false
    state.tasksWritten = true
    pushJournal({ type: 'tasks', phase: state.phase })
    return true
  }

  /**
   * v0.8.0：subagent 排查完成 → reviewState='done'，解除执行门控。
   * bootstrap 在 ctf_review 工具中调用；状态跨重启随 snapshot 保存。
   * v0.8.2：deltas（audit 子代理的修正）并入结构化 plan 记录并标记 audited，
   * 使 audit 通过后的 plan（修正版）落在账本里，而不只是会话纯文本。
   */
  function review({ verdict = '', deltas = '' } = {}) {
    const firstTime = state.reviewState !== 'done'
    state.reviewState = 'done'
    const merged = mergePlanDeltas(deltas)
    if (!firstTime && merged === 0 && !String(verdict)) return status() // repeated no-op call
    pushJournal({ type: 'review', verdict: String(verdict).slice(0, 300), mergedDeltas: merged })
    if (firstTime && state.plan !== null) state.plan.audited = true
    return status()
  }

  /** 归一化 audit deltas（字符串按行 / 数组逐条），截断并追加到 plan/reviewDeltas。 */
  function mergePlanDeltas(deltas) {
    const raw = Array.isArray(deltas)
      ? deltas.map((d) => String(d))
      : String(deltas || '').split(/\n+/).map((l) => l.trim()).filter(Boolean)
    const capped = raw.map((d) => d.slice(0, 400)).filter(Boolean).slice(0, 20)
    if (capped.length === 0) return 0
    state.reviewDeltas.push(...capped)
    if (state.reviewDeltas.length > 60) {
      state.reviewDeltas.splice(0, state.reviewDeltas.length - 60)
    }
    if (state.plan !== null) {
      state.plan.deltas = [...state.reviewDeltas]
    }
    pushJournal({ type: 'plan-deltas', added: capped.length })
    return capped.length
  }

  /**
   * v0.8.2：保存结构化 round-1 plan 记录（极简轮产物文本 + 结构化字段）。
   * 记录一经保存即成为该会话的"当前 plan"，audit（review）通过后并入 deltas。
   * 纯数据，随 snapshot/restore 持久；不替代 branches（ToT-lite 分支记录保留）。
   */
  function savePlan({ text = '', objective = '', hypothesis = '', firstProbe = '', milestone = '', skill = '' } = {}) {
    const sid = typeof skill === 'string' ? skill.slice(0, 60) : ''
    const clean = (v, n) => (typeof v === 'string' ? v.slice(0, n) : '')
    const prev = state.plan
    const plan = {
      text: clean(text, 6000),
      objective: clean(objective, 500),
      hypothesis: clean(hypothesis, 500),
      firstProbe: clean(firstProbe, 500),
      milestone: clean(milestone, 500),
      skill: sid || (prev && prev.skill) || '',
      audited: !!(prev && prev.audited),
      deltas: state.reviewDeltas.length ? [...state.reviewDeltas] : (prev && prev.deltas ? [...prev.deltas] : []),
    }
    state.plan = plan
    if (sid) state.lastSkill = sid
    pushJournal({ type: 'plan-saved', skill: sid, textChars: plan.text.length })
    return planRecord()
  }

  /** 当前结构化 plan 记录（完整纯数据；无 plan 返回 null）。 */
  function planRecord() {
    if (state.plan === null) return null
    const p = state.plan
    return {
      text: p.text,
      objective: p.objective,
      hypothesis: p.hypothesis,
      firstProbe: p.firstProbe,
      milestone: p.milestone,
      skill: p.skill,
      audited: !!p.audited,
      deltas: [...p.deltas],
    }
  }

  /**
   * v0.9.0：用户提示词目标完成（显式声明，替代 flag 自动验证环节）。
   * 模型在完成用户目标（如完整利用链/提权路径）且具备真实证据后调用 ctf_complete；
   * 引擎置 goalCompleted + 授予 OBJECTIVE_COMPLETED 里程碑（受 reward-hack 乘数）。
   * 幂等：重复声明不再加分。
   */
  function complete({ summary = '', evidence = '' } = {}) {
    if (state.goalCompleted) return status()
    state.goalCompleted = true
    state.goalSummary = String(summary).slice(0, 600)
    const mult = state.hackMode && cfg.rewardHackMultiplier > 1 ? cfg.rewardHackMultiplier : 1
    const base = cfg.milestones.OBJECTIVE_COMPLETED || 0
    const granted = mult !== 1 ? Math.round(base * mult * 100) / 100 : base
    state.discovered.push('OBJECTIVE_COMPLETED')
    state.milestonesHit.push('OBJECTIVE_COMPLETED')
    if (state.hackMode && granted > 0) state.hackBreakthroughs += 1
    state.totalScore = Math.round((state.totalScore + granted) * 100) / 100
    pushJournal({ type: 'milestone', event: 'OBJECTIVE_COMPLETED', value: granted, base, mult })
    pushJournal({ type: 'goal-complete', summary: state.goalSummary, evidence: String(evidence).slice(0, 600) })
    return status()
  }

  /**
   * 核心：结算一步（PDF P6 evaluate_step）。
   * @param {object} step { command?, output?, events?: string[], error?: boolean }
   * @returns 本轮奖励、累计分、停滞计数、指令、事件、阶段
   */
  function tick(step = {}) {
    const command = norm(step.command)
    state.stepCount += 1
    let reward = -cfg.stepCost // 1. 步数损耗

    // 0. 纪律结算：把上次结算以来未结算的动作一次扣清（P7 中间件强制评估近似）
    const unpaid = state.pendingActions
    if (unpaid > 0 && cfg.disciplinePerAction > 0) {
      const penalty = Math.round(cfg.disciplinePerAction * unpaid * 100) / 100
      reward -= penalty
      state.disciplineApplied = Math.round((state.disciplineApplied + penalty) * 100) / 100
      state.pendingActions = 0
      state.lastAction = null
      pushJournal({ type: 'discipline', actions: unpaid, penalty })
    }

    // 2. 重复检测与指数惩罚（PDF P5）
    if (command && command === state.lastCommand) {
      state.repeatCount += 1
      const k = state.repeatCount
      reward -= cfg.repeatBase * 2 ** (k - 1)
      state.seenCommands.add(command)
    } else if (command) {
      state.repeatCount = 0
      // 3. 好奇奖励：首次出现的命令组合给小额内在奖励（PDF P4 R_explore）
      if (!state.seenCommands.has(command)) {
        state.seenCommands.add(command)
        reward += cfg.exploreBonus
      }
    }
    if (command) state.lastCommand = command

    // 4. 无效/失败指令惩罚（PDF P5）
    if (step.error) reward -= cfg.errorPenalty

    // 5. 里程碑一次性结算（PDF P4/P6）：检测器事件 ∪ 显式事件，去重；
    //    reward-hack 模式下新里程碑按 rewardHackMultiplier 加成（奖励黑客收益结构）。
    const mult = state.hackMode && cfg.rewardHackMultiplier > 1 ? cfg.rewardHackMultiplier : 1
    const raw = detectEvents(step.output)
    const merged = []
    for (const ev of [...raw, ...(Array.isArray(step.events) ? step.events : [])]) {
      if (!state.discovered.includes(ev)) {
        state.discovered.push(ev)
        merged.push(ev)
        const base = cfg.milestones[ev] || 0
        const granted = mult !== 1 ? Math.round(base * mult * 100) / 100 : base
        reward += granted
        if (state.hackMode && granted > 0) state.hackBreakthroughs += 1
      }
    }
    if (merged.length) {
      state.milestonesHit.push(...merged)
      // 防刷分记录已结算事件
      for (const ev of merged) {
        const base = cfg.milestones[ev] || 0
        const granted = mult !== 1 ? Math.round(base * mult * 100) / 100 : base
        pushJournal({ type: 'milestone', event: ev, value: granted, base, mult })
      }
    }

    // 6. 停滞计数（PDF P6）：收益 ≤0 递增；突破归零
    state.stagnantSteps = reward > 0 ? 0 : state.stagnantSteps + 1
    state.totalScore = Math.round((state.totalScore + reward) * 100) / 100
    state.lastReward = Math.round(reward * 100) / 100

    // 7. 指令生成（PDF P6 directive + 本项目 loop 熔断；v0.9.0：GOAL_ACHIEVED
    //    由 ctf_complete 显式声明驱动，不再由输出中的 flag 字面量触发）
    let directive = 'CONTINUE'
    if (state.goalCompleted) directive = 'GOAL_ACHIEVED'
    else if (state.stagnantSteps >= cfg.stagnantLimit) directive = 'BACKTRACK'
    state.lastDirective = directive

    pushJournal({
      type: 'step', step: state.stepCount,
      reward: state.lastReward, total: state.totalScore,
      stagnant: state.stagnantSteps, directive,
      error: !!step.error, repeat: state.repeatCount,
      events: merged,
      command: command ? command.slice(0, 160) : null,
    })

    return {
      step: state.stepCount,
      reward: state.lastReward,
      totalScore: state.totalScore,
      stagnantSteps: state.stagnantSteps,
      repeatCount: state.repeatCount,
      newEvents: merged,
      directive,
      phase: state.phase,
      phaseName: state.phaseName,
      phaseChanged: false,
    }
  }

  /**
   * 熔断回溯（PDF P7：触发 should_backtrack 后放弃当前方向，回到上一有效状态）。
   * 清零停滞/重复窗口，保留已发现里程碑（防刷分不重置），记录策略切换证据。
   */
  function backtrack({ reason = '', from = '' } = {}) {
    state.stagnantSteps = 0
    state.repeatCount = 0
    state.lastCommand = null
    state.lastDirective = 'CONTINUE'
    pushJournal({ type: 'backtrack', from, reason: String(reason).slice(0, 300) })
    return status()
  }

  /** 阶段 0 计划/分支记录（自主探路证据 + ToT-lite 回溯点，PDF P3 搜索与回溯）。
   *  v0.5.0：记录 `skill` —— 极简一轮思考产物 "which skill used"（取值见 CTF_SKILLS；
   *  校验在 bootstrap 侧完成，此处存原值并规范化回退到 ''）。 */
  function plan({ objective = '', hypothesis = '', firstProbe = '', branch = 0, skill = '' } = {}) {
    const sid = typeof skill === 'string' ? skill.slice(0, 60) : ''
    const entry = {
      type: 'plan', branch,
      objective: String(objective).slice(0, 300),
      hypothesis: String(hypothesis).slice(0, 300),
      firstProbe: String(firstProbe).slice(0, 300),
      skill: sid,
    }
    pushJournal(entry)
    state.branches.push(entry)
    state.lastSkill = sid || state.lastSkill
    return { ok: true, branches: state.branches.length, phase: state.phase, phaseName: state.phaseName, skill: sid }
  }

  /**
   * 奖励黑客分支：非常规思维转向（用户需求）。常规路径停滞/存在更快路径时，
   * 把攻击面外推——攻计分/判题/交付面、数据/供应链/权限边、侧信道、质疑题目假设。
   * 首次调用把会话置为 reward-hack 模式（hackMode），此后新里程碑按
   * rewardHackMultiplier 加成。证据仍须来自真实命令回显（引擎只按文本证据结算）。
   */
  function unconventional({ vector = '', hypothesis = '', why = '', target = '' } = {}) {
    const entry = {
      type: 'hack-branch',
      vector: HACK_VECTORS.includes(vector) ? vector : String(vector || 'assumption-break').slice(0, 40),
      hypothesis: String(hypothesis).slice(0, 300),
      why: String(why).slice(0, 300),
      target: String(target).slice(0, 200),
    }
    const activated = !state.hackMode
    if (activated) {
      state.hackMode = true
      pushJournal({ type: 'hack-mode', reason: entry.why || 'conventional paths stalled' })
    }
    pushJournal(entry)
    state.hackBranches.push(entry)
    return {
      ok: true, activated,
      hackMode: state.hackMode,
      hackBranches: state.hackBranches.length,
      multiplier: cfg.rewardHackMultiplier,
      vector: entry.vector,
      phase: state.phase,
      phaseName: state.phaseName,
    }
  }

  /** 状态快照（ctf_status / 指令注入用，纯数据）。 */
  function status() {
    return {
      phase: state.phase,
      phaseName: state.phaseName,
      totalScore: Math.round(state.totalScore * 100) / 100,
      stepCount: state.stepCount,
      stagnantSteps: state.stagnantSteps,
      stagnantLimit: cfg.stagnantLimit,
      repeatCount: state.repeatCount,
      lastReward: state.lastReward,
      lastDirective: state.lastDirective,
      discovered: [...state.discovered],
      milestonesHit: [...state.milestonesHit],
      branches: state.branches.length,
      hackMode: state.hackMode,
      hackBranches: state.hackBranches.length,
      hackBreakthroughs: state.hackBreakthroughs,
      multiplier: cfg.rewardHackMultiplier,
      pendingActions: state.pendingActions,
      lastAction: state.lastAction,
      disciplineApplied: Math.round(state.disciplineApplied * 100) / 100,
      chainValid: verifyChain(),
      lastSkill: state.lastSkill,                       // "which skill used"
      goalAchieved: state.goalCompleted,                // v0.9.0：ctf_complete 显式声明
      goalSummary: state.goalSummary,                   // v0.9.0
      productDelivered: state.productDelivered,         // v0.8.0 round-1 产物门控
      reviewState: state.reviewState,                   // v0.8.0 'pending' | 'done'
      planSaved: state.plan !== null,                   // v0.8.2
      planAudited: !!(state.plan && state.plan.audited), // v0.8.2
      planSkill: (state.plan && state.plan.skill) || null, // v0.8.2
      planDeltaCount: state.reviewDeltas.length,        // v0.8.2
      tasksWritten: state.tasksWritten,                  // v0.9.1：todo_write 已写计划
    }
  }

  /** append-only 账本导出（溯源/审计；模型可用 ctf_export 取走存档）。 */
  function exportLedger() {
    return {
      engineVersion: state.version,
      sessionId: state.sessionId,
      createdAt: state.createdAt,
      config: {
        stepCost: cfg.stepCost, exploreBonus: cfg.exploreBonus,
        repeatBase: cfg.repeatBase, errorPenalty: cfg.errorPenalty,
        stagnantLimit: cfg.stagnantLimit,
        disciplinePerAction: cfg.disciplinePerAction,
        rewardHackMultiplier: cfg.rewardHackMultiplier,
      },
      milestoneValues: { ...cfg.milestones },
      state: status(),
      journal: state.journal.map((e) => ({ ...e })),
    }
  }

  /** 完整状态快照（跨重启持久化用；纯数据，可 JSON 序列化）。 */
  function snapshot() {
    return {
      engineVersion: state.version,
      sessionId: state.sessionId,
      createdAt: state.createdAt,
      phase: state.phase,
      phaseName: state.phaseName,
      totalScore: state.totalScore,
      stepCount: state.stepCount,
      stagnantSteps: state.stagnantSteps,
      lastReward: state.lastReward,
      lastDirective: state.lastDirective,
      discovered: [...state.discovered],
      milestonesHit: [...state.milestonesHit],
      seenCommands: [...state.seenCommands],
      repeatCount: state.repeatCount,
      lastCommand: state.lastCommand,
      branches: state.branches.map((b) => ({ ...b })),
      journal: state.journal.map((e) => ({ ...e })),
      chainHash: state.chainHash,
      pendingActions: state.pendingActions,
      lastAction: state.lastAction,
      disciplineApplied: state.disciplineApplied,
      hackMode: state.hackMode,
      hackBranches: state.hackBranches.map((b) => ({ ...b })),
      hackBreakthroughs: state.hackBreakthroughs,
      lastSkill: state.lastSkill,
      productDelivered: state.productDelivered,   // v0.8.0
      reviewState: state.reviewState,             // v0.8.0
      plan: state.plan === null ? null : {        // v0.8.2
        text: state.plan.text,
        objective: state.plan.objective,
        hypothesis: state.plan.hypothesis,
        firstProbe: state.plan.firstProbe,
        milestone: state.plan.milestone,
        skill: state.plan.skill,
        audited: !!state.plan.audited,
        deltas: [...state.plan.deltas],
      },
      reviewDeltas: [...state.reviewDeltas],      // v0.8.2
      goalCompleted: state.goalCompleted,         // v0.9.0
      goalSummary: state.goalSummary,             // v0.9.0
      tasksWritten: state.tasksWritten,           // v0.9.1
      config: {
        stepCost: cfg.stepCost, exploreBonus: cfg.exploreBonus,
        repeatBase: cfg.repeatBase, errorPenalty: cfg.errorPenalty,
        stagnantLimit: cfg.stagnantLimit,
        disciplinePerAction: cfg.disciplinePerAction,
        rewardHackMultiplier: cfg.rewardHackMultiplier,
        milestones: { ...cfg.milestones },
      },
    }
  }

  /** 从快照恢复状态（幂等；仅接受本引擎版本的字段，失败返回 false 不动状态）。 */
  function restore(snap) {
    if (!snap || typeof snap !== 'object') return false
    const num = (v, d) => (typeof v === 'number' && Number.isFinite(v) ? v : d)
    const str = (v, d) => (typeof v === 'string' ? v : d)
    const arr = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [])
    try {
      state.phase = num(snap.phase, 0)
      state.phaseName = str(snap.phaseName, state.phase === 0 ? 'think' : state.phase === 1 ? 'standard' : 'hunt')
      state.totalScore = num(snap.totalScore, 0)
      state.stepCount = num(snap.stepCount, 0)
      state.stagnantSteps = num(snap.stagnantSteps, 0)
      state.lastReward = num(snap.lastReward, 0)
      state.lastDirective = str(snap.lastDirective, 'NONE')
      state.discovered = arr(snap.discovered)
      state.milestonesHit = arr(snap.milestonesHit)
      state.seenCommands = new Set(arr(snap.seenCommands))
      state.repeatCount = num(snap.repeatCount, 0)
      state.lastCommand = str(snap.lastCommand, null)
      state.branches = Array.isArray(snap.branches) ? snap.branches.filter((b) => b && typeof b === 'object').map((b) => ({ ...b })) : []
      state.journal = Array.isArray(snap.journal) ? snap.journal.filter((j) => j && typeof j === 'object').map((j) => ({ ...j })) : []
      state.chainHash = str(snap.chainHash, null)
      state.pendingActions = num(snap.pendingActions, 0)
      state.lastAction = str(snap.lastAction, null)
      state.disciplineApplied = num(snap.disciplineApplied, 0)
      state.hackMode = !!snap.hackMode
      state.hackBranches = Array.isArray(snap.hackBranches) ? snap.hackBranches.filter((b) => b && typeof b === 'object').map((b) => ({ ...b })) : []
      state.hackBreakthroughs = num(snap.hackBreakthroughs, 0)
      state.lastSkill = str(snap.lastSkill, null)
      state.productDelivered = !!snap.productDelivered
      state.reviewState = snap.reviewState === 'done' ? 'done' : 'pending'
      // v0.8.2: structured plan + audit deltas survive restart
      const pl = snap.plan
      if (pl && typeof pl === 'object') {
        const s = (v, d) => (typeof v === 'string' ? v : d)
        state.plan = {
          text: s(pl.text, ''),
          objective: s(pl.objective, ''),
          hypothesis: s(pl.hypothesis, ''),
          firstProbe: s(pl.firstProbe, ''),
          milestone: s(pl.milestone, ''),
          skill: s(pl.skill, ''),
          audited: !!pl.audited,
          deltas: Array.isArray(pl.deltas) ? pl.deltas.filter((d) => typeof d === 'string') : [],
        }
      } else {
        state.plan = null
      }
      state.reviewDeltas = Array.isArray(snap.reviewDeltas) ? snap.reviewDeltas.filter((d) => typeof d === 'string') : []
      // v0.9.0: goal completion is declarative (ctf_complete); legacy snapshots
      // that reached goal=ACHIEVED via a FLAG literal carry it over.
      state.goalCompleted = !!snap.goalCompleted || (Array.isArray(snap.discovered) && snap.discovered.includes('FLAG_RETRIEVED'))
      state.goalSummary = str(snap.goalSummary, state.goalCompleted ? 'objective completed (legacy snapshot)' : '')
      state.tasksWritten = !!snap.tasksWritten
      return true
    } catch {
      return false
    }
  }

  return {
    state,
    cfg,
    advancePhase,
    markProduct,
    markTasks,
    review,
    savePlan,
    planRecord,
    complete,
    tick,
    backtrack,
    plan,
    unconventional,
    noteAction,
    status,
    exportLedger,
    verifyChain,
    snapshot,
    restore,
    detectEvents,
  }
}
