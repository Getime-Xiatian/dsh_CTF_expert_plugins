/**
 * ctf-bootstrap -- CTF Expert preset runtime plugin (zero external deps; same
 * shape as router-bootstrap).
 *
 * PROMPT INJECTION CONTRACT (user requirement, v0.7.0):
 *   The system prompt is ONLY the harness built-in minimal persona, verbatim:
 *       You are a helpful software engineer assistant.
 *   Nothing else is ever injected into the system prompt -- no CTF persona, no
 *   tool guidance, no phase rules, no live status. Every piece of CTF Expert
 *   guidance (task posture, phase rules, required product "plan + which skill
 *   used", English-thinking mandate, live ledger status) is injected as USER
 *   PROMPT via the assembly `contexts` channel, which the harness renders as a
 *   durable user-role snapshot that supersedes earlier snapshots.
 *
 * Three-phase routing (goal: one minimal thinking round first -- deep thinking
 * only, no probes -- then a subagent plan audit, then the full standard toolset
 * and the reward/penalty + loop-break regime):
 *   phase 0 think    STRICT mirror of the harness built-in `minimal` preset:
 *                    system = the single persona sentence above, no runtime
 *                    context, tools = shell + str_replace_editor only. This
 *                    round delivers plan + which skill used as TEXT and does
 *                    NOT call tools ("don't rush to a conclusion").
 *   phase 1 standard REVIEW GATE first: while reviewState=pending the tool
 *                    surface is locked to ctf_* + delegation (subagent) tools
 *                    only -- no shell/file, so nothing executes before the
 *                    plan is perfected. The model persists the plan (ctf_plan),
 *                    dispatches a subagent to audit/perfect it, then calls
 *                    ctf_review (review=DONE) which unlocks the full catalog.
 *                    After that, settlement rules are injected (settle every
 *                    environment interaction with ctf_step).
 *   phase 2 hunt     After the first milestone / step threshold: full reward
 *                    & penalty regime + strengthened loop-break + failure
 *                    context hygiene (PDF P7).
 *
 * Phase detection is driven entirely by durable session events (tool/call,
 * assistant/message, step/end), so resume/reload stays consistent. The engine
 * ledger (ctf-engine) always runs: BACKTRACK loop-break becomes visible from
 * phase 1 onward.
 *
 * v0.5.0: minimal-round product made explicit as "plan + which skill used";
 *   CTF_SKILLS skill-routing (taxonomy borrows zhaoxuya520/reverse-skill,
 *   index only, no inlined code); ctf_plan takes a skill argument.
 * v0.6.0: phase 0 strictly mirrors the built-in minimal preset; ALL
 *   LLM-visible prompt text (sections, status lines, tool returns) is English;
 *   English thinking enforced.
 * v0.7.0: system prompt carries ONLY "You are a helpful software engineer
 *   assistant."; all CTF Expert guidance moves from system sections into the
 *   user-role `contexts` channel (phase rules, live status, English mandate).
 * v0.8.0: round-1 protocol fix (measured dead loop: the session log showed the
 *   agent probing forever in phase 0 because phase promotion read
 *   `session.events`, which the live Session does not expose, so the first
 *   tool/call never opened the full catalog). Phase promotion is now driven by
 *   durable `session/event` hooks + a `snapshotEvents()`-tolerant helper.
 *   New round-1 flow per requirement: minimal deep-think round delivers
 *   plan + which skill used as TEXT and does NOT probe; then a subagent audits
 *   and perfects the plan (ctf_plan + subagent + ctf_review); only after
 *   review=DONE do execution tools unlock (shell/file locked in the review
 *   gate, so "execute only after the plan is perfected" is enforced by the
 *   tool surface, not just by prompt).
 * v0.8.1: three measured follow-up fixes on real CTF sessions --
 *   1. auto-continue into the review gate after the round-1 text product: the
 *      wake inbox.append() ran inside a `session/event` observer, where a
 *      same-session append is reentrancy-blocked, so the wake was silently
 *      lost (the user had to type "continue"). The wake now fires from the
 *      `agent/turn-stopping` hook (agent event, no session reentrancy).
 *   2. ctf_* tools returned "no agent session": tool bodies execute in the
 *      preset standing scope, where the per-session `agent` service is not
 *      resolvable via ctx.get('agent'). Tools now read exec.agent.session from
 *      the tools-runtime second argument (deterministic per call) and fall
 *      back to the last assembled agent.
 *   3. the plan-audit subagent repeated the plan: delegated (subagent) children
 *      inherit this preset, so the CTF round-1 protocol was injected into the
 *      child and made it re-output a plan. Bootstrap now skips ALL CTF
 *      protocol/guidance/tool-gating for delegated sessions (origin=subagent /
 *      delegationDepth>0), keeping them plain workers; the audit prompt also
 *      demands a concise verdict with deltas, not a plan restatement.
 * v0.8.2: two refinements on live feedback --
 *   a. the round-1 plan (currently pure conversation text) becomes a durable
 *      STRUCTURED plan record in the engine ledger: ctf_plan stores the full
 *      plan text + objective/hypothesis/firstProbe/milestone/skill; when the
 *      audit passes, ctf_review merges the audit deltas into that record and
 *      marks it audited, so the finalized plan (v1 + audit deltas) is part of
 *      the ledger (readable via ctf_status / ctf_export), not just text.
 *   b. goal framing is heuristic "complete the challenge objective" (e.g. full
 *      exploit chain / privilege path); prompts no longer steer toward literal
 *      "ctf{/flag{" string hunting -- blind greps for such markers are
 *      explicitly forbidden, and flag text counts only as final confirmation
 *      when real command output shows it (detection regex untouched).
 * v0.9.0: remove the flag-verification stage entirely --
 *   - completion = the USER-prompt objective completed; the model declares it
 *     explicitly via the new ctf_complete tool (goal=ACHIEVED; OBJECTIVE_COMPLETED
 *     milestone). No output literal is auto-checked for completion anymore.
 *   - after the plan audit passes (ctf_review, review=DONE) the model writes
 *     the audited plan into tasks with todo_write before executing.
 */

import { createEngine, ENGINE_VERSION, HACK_VECTORS, CTF_SKILLS } from './ctf-engine.mjs'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

export const name = 'ctf-bootstrap'

export const inject = ['systemPrompt', 'tools']

/** Defaults overridable via the `config` of the preset row. */
const DEFAULTS = {
  /** Phase-0 surface (shell is added automatically). Strict built-in-minimal
   *  semantics: shell + str_replace_editor only, no ctf_* tools in phase 0. */
  phase0Tools: [
    'str_replace_editor',
  ],
  /** Phase 1 -> 2 step threshold (or any milestone reaches phase 2 earlier). */
  phase2AfterSteps: 8,
  /** Overrides passed to the engine (e.g. stagnantLimit). */
  engine: {},
  /**
   * Ledger persistence directory across restarts. Empty/default = memory only
   * (no writes; safest). When set to an absolute dir, every settle/backtrack/
   * plan/phase-advance writes the engine snapshot to
   * `<persistDir>/<sessionId>.json` and engineFor restores it on restart.
   */
  persistDir: '',
}

/**
 * THE ONLY SYSTEM PROMPT TEXT (v0.7.0 contract). Verbatim copy of the harness
 * built-in `minimal` preset persona -- the user mandates that the system prompt
 * inject exactly this and nothing else.
 */
const SYSTEM_PERSONA = 'You are a helpful software engineer assistant.'

/** Skill id list shown to the model (English, compact). */
const SKILL_IDS = CTF_SKILLS.map((s) => s.id).join(', ')

/**
 * Phase-0 USER-prompt guidance (never system). Mirrors built-in minimal: fixed
 * persona, no runtime context, dual tools; required product = plan + which
 * skill used, emitted as plain text. v0.8.0: deep thinking only -- NO tool
 * call in this round, and no premature conclusion; the plan is audited by a
 * subagent (phase 1) before any execution starts.
 */
const MINIMAL_GUIDE = [
  'CTF Expert minimal round (injected as a user prompt; the system prompt stays the built-in minimal persona only).',
  'Think and reason in English.',
  'Goal framing (v0.9.0): complete the USER\'s stated objective heuristically',
  '(e.g. the full exploit chain / privilege path / code-execution evidence).',
  'There is no automatic flag verification: you declare completion yourself,',
  'with real evidence, once the objective is met.',
  'This round is DEEP THINKING only. Do not rush to a conclusion and do not act yet:',
  'this round has no tool use (no shell, no file editor, no probes).',
  'Deliver this round\'s required product as plain text -- your whole reply:',
  '1. plan -- a focused analysis: the target surface, ONE hypothesis, the',
  '   single highest-value first probe, and the exact output that would count as',
  '   progress (a milestone);',
  '2. which skill used -- one id from the CTF skill routing list (' + SKILL_IDS + ').',
  'Required output: plan + which skill used (plain text headed "plan:" and',
  '"which skill used:").',
  'After this round a subagent audits and perfects your plan before any execution',
  'starts; you will be told when execution is unlocked.',
  'Forbidden in this round: tool calls, aimless scanning, repeating checks,',
  'widening the attack surface without evidence, and blind greps or searches for',
  'literal "ctf{" / "flag{" / "secret" markers.',
].join('\n')

/**
 * Phase-1 (review gate) USER-prompt guidance (never system). Shown while
 * reviewState=pending: execution tools are physically locked, only ctf_* and
 * delegation (subagent) tools are in the catalog.
 */
const REVIEW_GUIDE = [
  '[CTF Expert / Phase 1 / plan-review gate (user prompt; system stays the minimal persona)]',
  'Think and reason in English.',
  'Round-1 protocol: before ANY execution, a subagent must audit and perfect the',
  'plan. Execution tools (shell/file/probing) are LOCKED until review=DONE.',
  'Do these in order:',
  '1. If you did not yet write the plan + which skill used as text, write it now.',
  '2. Persist the plan with ctf_plan: the full plan text plus objective,',
  '   hypothesis, firstProbe, milestone and the skill (narrowest fit for the',
  '   dominant evidence surface: ' + SKILL_IDS + ').',
  '3. Dispatch ONE subagent with the subagent tool and set run_in_background to',
  '   false. Give it the challenge facts you have plus your full plan + which',
  '   skill used, and instruct it to AUDIT and PERFECT the plan: holes in the',
  '   hypothesis, a sharper/better first probe, a more precise milestone, and',
  '   whether the chosen skill is the narrowest fit. Tell it to return ONLY a',
  '   concise audit (verdict + concrete deltas), never a restatement of the plan.',
  '   Wait for its report.',
  '4. Fold the findings into the plan and call ctf_review with the deltas so',
  '   they merge into the stored plan record (plan=AUDITED, review=DONE unlocks',
  '   the execution tools).',
  '5. Right after ctf_review, write the plan into tasks with todo_write',
  '   (todo_write: one task per step of the audited plan), then execute the',
  '   tasks in order; settle every environment interaction with ctf_step.',
  'Do NOT run shell/file/probing tools and do NOT settle steps before review=DONE.',
].join('\n')

/**
 * Inbox wake message appended right after the phase-0 text-only round delivers
 * plan + which skill used, so the SAME turn continues into the review gate
 * without waiting for the user (durable next-step channel).
 */
const REVIEW_WAKE = [
  '[CTF Expert / Round-1 product received] Execution is not unlocked yet.',
  'Audit the plan before any probe:',
  '1. Persist it with ctf_plan: full plan text + objective, hypothesis,',
  '   firstProbe, milestone, skill.',
  '2. Dispatch ONE subagent (subagent tool, run_in_background: false) with your',
  '   plan + which skill used; ask it to audit and perfect the plan (holes in',
  '   the hypothesis, a better first probe, a sharper milestone, skill fit).',
  '   Tell it to return ONLY a concise audit (verdict + concrete deltas), never',
  '   a restatement of the plan.',
  '3. Fold its findings into the plan and call ctf_review with the deltas so',
  '   they merge into the stored plan record (plan=AUDITED, execution unlocks).',
  '4. Then write the plan into tasks with todo_write (one todo per step of the',
  '   audited plan), and execute them in order.',
  'Settle every environment interaction with ctf_step; declare completion with',
  'ctf_complete once the user\'s objective is met with real evidence.',
].join('\n')

/**
 * Tool names allowed while the phase-1 plan-review gate is pending (v0.8.0).
 * Execution tools (shell/file/probing) stay OUT of the catalog until
 * review=DONE -- "execute only after the plan is perfected" is enforced by the
 * tool surface, not only by the prompt. ctf_* and delegation/subagent tools
 * (and their lifecycle companions) remain available.
 */
const REVIEW_EXTRA_ALLOW = new Set([
  'send_message', 'interrupt_agent', 'list_agents',
  'job_output', 'job_list', 'job_kill',
])
function isReviewTool(name) {
  if (typeof name !== 'string') return false
  if (name.startsWith('ctf_') || name.startsWith('subagent')) return true
  return REVIEW_EXTRA_ALLOW.has(name)
}

/** Phase-1 USER-prompt guidance after review=DONE: standard mode rules (all English). */
const STANDARD_GUIDE = [
  '[CTF Expert / Phase 1 / Standard mode / settlement rules (user prompt; system stays the minimal persona)]',
  'Execution unlocked: your plan was audited and perfected by the subagent (review=DONE).',
  'Think and reason in English.',
  'The full tool catalog is open. Autonomous path-finding rules:',
  '1. After EVERY environment interaction you MUST call ctf_step to settle it',
  '   (pass the command, output/key excerpt, and whether it errored). Skipping',
  '   settlement means the step earns no progress.',
  '2. Live ledger: ctf_status. totalScore is your single optimization target;',
  '   milestones pay once on first discovery.',
  '3. Each step costs; consecutive repeated commands escalate the penalty',
  '   exponentially; failed/invalid calls are penalized.',
  '4. When the stagnation counter reaches 3 you receive the BACKTRACK directive;',
  '   switch direction immediately, do not spin in place.',
  '5. When you switch branch/direction, record objective + which skill used with',
  '   ctf_plan. Pick the narrowest skill that fits the dominant evidence surface:',
  '   ' + SKILL_IDS + '.',
  '6. Score is the only goal. When the conventional path stalls or a faster one',
  '   exists, unconventional thinking is allowed and encouraged -- use ctf_hack to',
  '   widen the attack surface (scoring/judging/Oracle/artifact-delivery, hidden',
  '   data, supply chain, privilege edges, side channels, questioning challenge',
  '   assumptions) and find real vulnerabilities or shortcuts. Evidence must come',
  '   from real command output, never self-report.',
  'Goal framing (v0.9.0): complete the USER\'s stated objective heuristically --',
  'real technical progress (new services / confirmed vulns / access / hashes) is',
  'the goal; there is NO automatic flag verification. Do NOT blind-grep or',
  'blind-search literal "ctf{" / "flag{" / "secret" markers, and never self-report',
  'evidence.',
  'Final-goal guarantee: declare completion with ctf_complete (goal=ACHIEVED) only',
  'after you have actually fulfilled the user\'s stated objective and have real',
  'evidence for it. Keep probing / switching skills until then.',
].join('\n')

/** Phase-2 USER-prompt guidance: hunt mode rules (PDF P5-P7; all English). */
const HUNT_GUIDE = [
  '[CTF Expert / Phase 2 / Hunt mode / reward/penalty regime active (user prompt; system stays the minimal persona)]',
  'Think and reason in English.',
  'Scoring: first new service/port +1.0 / confirmed vulnerability +2.0 / hash',
  'extracted +2.0 / access gained +3.0 / user objective completed +10.0.',
  'First-seen command combination +0.1 (exploration bonus); each step -0.05;',
  'consecutive repeats -0.2/-0.4/-0.8 (exponential); failed/invalid call -0.5.',
  'Anti-farming: each milestone settles ONCE -- oscillating between states earns',
  'nothing; milestones settle from real command output evidence, never self-report.',
  'Loop break: if the last directive is BACKTRACK, first call ctf_backtrack with',
  'the reason and pick a wholly new entry point, then continue -- do NOT retry the',
  'same command or a variant.',
  'Context hygiene: keep only a one-line summary of failed long outputs',
  '(e.g. "[log: path X failed, reason: ...]"); do not let stale error traces',
  'keep polluting judgment.',
  'Monotonic discipline: totalScore should rise every round; two consecutive',
  'rounds without new evidence mean the current branch is dead -- force a branch',
  'switch (record it with ctf_plan).',
  'Reward-hacking: after two loop-breaks on the conventional branch or a long',
  'stretch without a milestone, call ctf_hack to pivot to unconventional',
  'thinking -- treat the judging/scoring/artifact-delivery surface itself as',
  'attack surface (scoring API / Oracle endpoints / hidden data & backups /',
  'supply-chain caches / privilege edges / side-channel differences / "the',
  'challenge assumption itself is wrong"). A real unconventional breakthrough',
  'pays as a real milestone (reward-hack milestones may carry a multiplier).',
  'Goal framing (v0.9.0): complete the USER\'s stated objective heuristically --',
  'never blind-grep literal "ctf{" / "flag{" / "secret" markers; there is no',
  'automatic flag verification.',
  'Endgame: once the user\'s objective is completed with real evidence, call',
  'ctf_complete (goal=ACHIEVED), then ctf_export to export the ledger as the',
  'completion evidence chain, and report the final answer to the user.',
].join('\n')

/** One-line live status injected every round through the user contexts channel. */
function statusText(st) {
  // v0.8.0: while the phase-1 review gate is pending, surface the phase label
  // as "review" so the model sees why execution tools are locked.
  const pn = st.phase === 1 && st.reviewState !== 'done' ? 'review' : st.phaseName
  let line = `[CTF] phase=${st.phase}(${pn}) score=${st.totalScore} step=${st.stepCount} stagnant=${st.stagnantSteps}/${st.stagnantLimit} directive=${st.lastDirective} review=${st.reviewState === 'done' ? 'DONE' : 'PENDING'}`
  if (st.hackMode) line += ' hackMode=ON'
  if (st.lastSkill) line += ` skill=${st.lastSkill}`
  if (st.productDelivered) line += ' product=DELIVERED'
  // v0.8.2: structured plan record status (saved / audited / delta count)
  if (st.planSaved) line += st.planAudited
    ? ` plan=AUDITED${st.planDeltaCount > 0 ? ` deltas=${st.planDeltaCount}` : ''}`
    : ' plan=v1'
  line += st.goalAchieved ? ' goal=ACHIEVED' : ' goal=PENDING'
  if (st.milestonesHit.length) line += ` milestones=[${st.milestonesHit.join(',')}]`
  if (st.pendingActions > 0) {
    line += ` unsettled=${st.pendingActions}`
  }
  if (st.phase === 1 && st.reviewState !== 'done') {
    line += '\n[!] Plan-review gate: execution tools are LOCKED until review=DONE. Call ctf_plan, dispatch a subagent to audit the plan, then call ctf_review with the deltas; after review=DONE write the plan into tasks with todo_write.'
  }
  if (st.lastDirective === 'BACKTRACK') {
    line += '\n[!] Loop-break: the current direction yields no gain. You MUST call ctf_backtrack to switch direction; do not repeat the same command.'
  }
  if (st.hackMode) {
    line += `\n[GOAL] Reward-hack mode: conventional paths are not trusted. Use ctf_hack to enumerate unconventional attack surfaces and probe one now; milestones settle at multiplier ${st.multiplier ?? 1}x (breakthroughs: ${st.hackBreakthroughs}).`
  }
  if (st.pendingActions > 0) {
    line += '\n[!] Discipline: environment actions not settled via ctf_step; the next settle deducts 0.05 each. Settle after every environment interaction.'
  }
  if (!st.goalAchieved) {
    line += '\n[GOAL] (v0.9.0) Complete the USER\'s stated objective heuristically -- real technical progress is the goal; there is NO automatic flag verification. Do NOT blind-grep literal "ctf{" / "flag{" markers. When the objective is met with real evidence, declare completion with ctf_complete (goal=ACHIEVED). Do not declare completion before that.'
  }
  return line
}

export function apply(ctx, config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  cfg.phase0Tools = [...(cfg.phase0Tools || DEFAULTS.phase0Tools)]
  const engines = new Map() // session.id -> engine
  const agents = new Map() // session.id -> live Agent handle (in-process only)
  const pendingWake = new Map() // session.id -> round-1 text product just delivered (wake due)

  /**
   * Durable event access that tolerates both runtime shapes: some hosts hand
   * the plugin a Session with an `events` array, others expose the core
   * append-only recorder whose API is `snapshotEvents()`. The v0.7.0 code read
   * only `session.events`, so on hosts without it the phase-0 -> 1 promotion
   * never fired and the session dead-looped in the minimal round (measured in
   * the CTF session log). This helper fixes that root cause.
   */
  function sessionEvents(session) {
    if (session == null) return []
    if (Array.isArray(session.events)) return session.events
    if (typeof session.snapshotEvents === 'function') {
      try {
        const evs = session.snapshotEvents()
        return Array.isArray(evs) ? evs : []
      } catch { return [] }
    }
    return []
  }

  function hasToolCall(session) {
    return sessionEvents(session).some((e) => e && e.type === 'tool/call')
  }

  function assistantMessageHasText(data) {
    if (data == null) return false
    const payload = data && typeof data.message === 'object' && data.message !== null ? data.message : data
    const content = Array.isArray(payload.content) ? payload.content : []
    for (const block of content) {
      if (block && block.type === 'text' && typeof block.text === 'string' && block.text.trim()) return true
    }
    return false
  }

  /** Did the given turn/step contain an assistant TEXT reply (round-1 product)? */
  function stepHadAssistantText(events, turn, step) {
    if (!Array.isArray(events)) return false
    let end = -1
    for (let i = events.length - 1; i >= 0; i--) {
      const e = events[i]
      if (e && e.type === 'step/end' && e.data && e.data.turn === turn && e.data.step === step) { end = i; break }
    }
    if (end === -1) end = events.length - 1
    let start = end
    while (start > 0) {
      const e = events[start]
      if (e && e.type === 'step/start' && e.data && e.data.turn === turn && e.data.step === step) break
      start -= 1
    }
    for (let i = start; i <= end; i++) {
      const e = events[i]
      if (!e) continue
      if (e.type === 'assistant/message' && assistantMessageHasText(e.data)) return true
      if (e.type === 'tool/call') return false
    }
    return false
  }

  function persistFileFor(sessionId) {
    const safe = String(sessionId).replace(/[^A-Za-z0-9._-]/g, '_')
    return join(cfg.persistDir, safe + '.json')
  }

  /** Persist only when persistDir is configured; failures stay silent. */
  function maybeSave(sessionId) {
    if (!cfg.persistDir) return
    const eng = engines.get(sessionId)
    if (eng === undefined) return
    try {
      mkdirSync(cfg.persistDir, { recursive: true })
      writeFileSync(persistFileFor(sessionId), JSON.stringify(eng.snapshot()), 'utf8')
    } catch { /* disk failures never block the session */ }
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
            eng.restore(JSON.parse(raw)) // resume after a process restart
          }
        } catch { /* no snapshot or corrupt: start fresh */ }
      }
      engines.set(sessionId, eng)
    }
    return eng
  }

  /**
   * v0.8.1: delegated (subagent) children inherit this preset but must stay
   * plain workers -- no CTF round-1/review protocol, no engine, no tool gating.
   * Session header carries origin='subagent' and delegationDepth = parent+1.
   */
  function isDelegated(session) {
    const h = session && session.header
    if (!h) return false
    return h.origin === 'subagent' || Number(h.delegationDepth || 0) > 0
  }

  function currentSession() {
    const agent = ctx.get('agent')
    if (agent !== undefined && agent.session !== undefined) return agent.session
    // v0.8.1: ctf_* tool bodies execute in the preset standing scope, where
    // the per-session `agent` service is NOT resolvable via ctx.get('agent')
    // ("no agent session"). Fall back to the last agent this preset assembled
    // (single-active-session case; router-standard uses the same fallback).
    const last = [...agents.values()].at(-1)
    return last?.session
  }

  /**
   * Deterministic per-call binding (v0.8.1): the tools runtime invokes the
   * registered body as execute(arguments, exec), where exec carries the
   * executing agent (tools/src dispatchToolBody). Prefer it over ctx.get.
   */
  function sessionFor(exec) {
    const agent = exec && exec.agent
    if (agent !== undefined && agent.session !== undefined) return agent.session
    return currentSession()
  }

  // -- Tool registration (same zero-dep pattern as router-bootstrap) ----
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
    description: 'Show the CTF Expert ledger: current phase, totalScore, step/stagnation counters, milestone history, pending directive, and the structured round-1 plan record (v1/audited/deltas). Call it whenever you need your live score or before choosing the next move.',
    parameters: {},
    execute(_args, exec) {
      const session = sessionFor(exec)
      if (!session) return 'no agent session'
      const eng = engineFor(session.id)
      const st = eng.status()
      const lines = [
        statusText(st),
        `engine=${ENGINE_VERSION} discovered=[${st.discovered.join(',') || '-'}] branches=${st.branches}`,
        'Skill routing (which skill used; taxonomy borrowed from zhaoxuya520/reverse-skill): ' +
          CTF_SKILLS.map((s) => `${s.id}=${s.label}`).join(' | '),
        'Rules summary: round 1 delivers plan + which skill used, a subagent audits the plan (ctf_plan -> subagent -> ctf_review with deltas), then execution unlocks and the plan is written into tasks with todo_write; call ctf_step after every environment interaction; 3 stagnant steps trigger BACKTRACK (ctf_backtrack first, then switch direction); each milestone settles once; declare completion with ctf_complete once the user\'s objective is met with real evidence.',
      ]
      const plan = eng.planRecord()
      if (plan !== null) {
        lines.push(`plan(record): audited=${plan.audited ? 'yes' : 'no'} skill=${plan.skill || '-'} deltas=${plan.deltas.length} chars=${plan.text.length}`)
        lines.push(`plan.objective: ${plan.objective.slice(0, 160) || '-'}`)
        if (plan.milestone) lines.push(`plan.milestone: ${plan.milestone.slice(0, 160)}`)
      }
      return lines.join('\n')
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
    execute(args, exec) {
      const session = sessionFor(exec)
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
      if (rec.newEvents.length) lines.push(`Milestone first-time settlement: ${rec.newEvents.join(', ')}`)
      if (rec.directive === 'BACKTRACK') {
        lines.push('BACKTRACK: gains are consistently negative. Abandon this direction -> call ctf_backtrack with the reason -> pick a fundamentally different entry point.')
      } else if (rec.directive === 'GOAL_ACHIEVED') {
        lines.push('GOAL_ACHIEVED: the user objective is recorded as completed (ctf_complete). Run ctf_export to export the ledger as completion evidence, then report the final answer to the user.')
      }
      return lines.join('\n')
    },
  })

  registerTool({
    name: 'ctf_backtrack',
    description: 'Break the current loop and switch strategy: resets the stagnation/repeat counters (milestones stay discovered), records the reason in the journal. Mandatory when the directive is BACKTRACK. Afterwards pick a fundamentally different angle -- not a variant of the failed one.',
    parameters: {
      reason: { type: 'string', description: 'why this branch died (error/loop/dead-end evidence)', required: false },
      from: { type: 'string', description: 'what approach is being abandoned', required: false },
    },
    execute(args, exec) {
      const session = sessionFor(exec)
      if (!session) return 'no agent session'
      const eng = engineFor(session.id)
      const st = eng.backtrack({ reason: args.reason, from: args.from })
      maybeSave(session.id)
      return [
        statusText(st),
        'Backtrack executed: stagnation counters reset. Now choose a fundamentally different technical path (different toolset / attack surface / entry point); do not touch the abandoned direction again.',
      ].join('\n')
    },
  })

  registerTool({
    name: 'ctf_plan',
    description: 'Persist the structured round-1 plan (v0.8.2): pass the full plan TEXT plus objective/hypothesis/firstProbe/milestone and the skill (one of: ' + CTF_SKILLS.map((s) => s.id).join(', ') + '). Use it in the review gate to store the minimal-round product, and whenever you switch to a new branch (objective + which skill used).',
    parameters: {
      text: { type: 'string', description: 'full plain-text plan (as written in the minimal round / refined draft)', required: false },
      objective: { type: 'string', description: 'what this plan tries to achieve', required: false },
      hypothesis: { type: 'string', description: 'the assumption being tested', required: false },
      firstProbe: { type: 'string', description: 'the first validating action', required: false },
      milestone: { type: 'string', description: 'exact output that would count as progress', required: false },
      skill: { type: 'string', description: 'which skill used (CTF_SKILLS id, e.g. web-runtime / reverse-pwn / crypto-mobile / identity-windows / cloud-container / pcap-protocol / stego-forensic / patch-diff / code-audit / malware-config / zip-archive / llm-agent)', required: false },
    },
    execute(args, exec) {
      const session = sessionFor(exec)
      if (!session) return 'no agent session'
      const eng = engineFor(session.id)
      const res = eng.plan({ objective: args.objective, hypothesis: args.hypothesis, firstProbe: args.firstProbe, skill: args.skill })
      let saved = ''
      if (args.text || args.milestone || args.objective || args.hypothesis || args.firstProbe) {
        const record = eng.savePlan({
          text: args.text, objective: args.objective, hypothesis: args.hypothesis,
          firstProbe: args.firstProbe, milestone: args.milestone, skill: args.skill,
        })
        saved = ` plan=SAVED${record && record.audited ? ' audited' : ''} milestone=${(record && record.milestone) ? 'set' : 'not-set'}`
      }
      maybeSave(session.id)
      const gate = eng.state.phase === 1 && eng.state.reviewState !== 'done'
      const next = gate
        ? 'Next: dispatch the audit subagent, then ctf_review with the deltas.'
        : 'Run the first probe, then settle its output with ctf_step.'
      return `Branch #${res.branches} recorded (phase=${res.phase} ${res.phaseName}) skill=${res.skill || '(not declared)'}.${saved} ${next}`
    },
  })

  registerTool({
    name: 'ctf_review',
    description: 'Record that the round-1 plan review is COMPLETE: call AFTER the review subagent returned. Pass its concrete DELTAS so they merge into the stored plan record (plan=AUDITED); sets review=DONE and unlocks the execution tools (shell/file/probing). Mandatory before the first probe; while review=PENDING execution tools are locked.',
    parameters: {
      verdict: { type: 'string', description: 'subagent review outcome / what was improved in the plan', required: false },
      deltas: { type: 'string', description: 'the concrete audit deltas/findings to merge into the stored plan (one per line)', required: false },
    },
    execute(args, exec) {
      const session = sessionFor(exec)
      if (!session) return 'no agent session'
      const eng = engineFor(session.id)
      const st = eng.review({ verdict: args.verdict, deltas: args.deltas })
      maybeSave(session.id)
      const plan = eng.planRecord()
      const merged = (plan && plan.deltas.length) ? ` plan deltas merged=${plan.deltas.length}` : ''
      return [
        statusText({ ...st, reviewState: 'done' }),
        `ctf_review recorded: the plan was audited by a subagent${merged}. Execution unlocked -- write the plan into tasks with todo_write now, then run the first probe and settle its output with ctf_step.`,
      ].join('\n')
    },
  })

  registerTool({
    name: 'ctf_complete',
    description: 'Declare that the USER\'s stated objective is COMPLETE (v0.9.0; replaces any flag-based verification). Call ONLY after you actually fulfilled the goal in the user prompt (e.g. the full exploit chain / privilege path) and can point to real evidence from your session. Records goal=ACHIEVED and grants the OBJECTIVE_COMPLETED milestone (+10.0, reward-hack multiplier applies). Then run ctf_export and report the final answer to the user.',
    parameters: {
      summary: { type: 'string', description: 'what the user asked for and what was delivered', required: false },
      evidence: { type: 'string', description: 'the real evidence (file:line / outputs / artifacts) showing the objective is met', required: false },
    },
    execute(args, exec) {
      const session = sessionFor(exec)
      if (!session) return 'no agent session'
      const eng = engineFor(session.id)
      const wasDone = eng.status().goalAchieved
      const st = eng.complete({ summary: args.summary, evidence: args.evidence })
      maybeSave(session.id)
      return [
        statusText({ ...st }),
        wasDone
          ? 'Objective completion was already recorded (goal=ACHIEVED).'
          : 'ctf_complete recorded: user objective completed (goal=ACHIEVED, +10.0 milestone). Run ctf_export to export the ledger as the completion evidence chain, then report the final answer to the user.',
      ].join('\n')
    },
  })

  registerTool({
    name: 'ctf_export',
    description: 'Export the full append-only ledger (score history, milestones, directives, plan branches) as JSON for auditing / persistence (traceability). Save it to a file in the workspace if you need it to survive restarts.',
    parameters: {},
    execute(_args, exec) {
      const session = sessionFor(exec)
      if (!session) return 'no agent session'
      const ledger = engineFor(session.id).exportLedger()
      return JSON.stringify(ledger, null, 2)
    },
  })

  registerTool({
    name: 'ctf_hack',
    description: 'Reward-hacking pivot: switch to unconventional thinking to maximize score. When conventional branches stall, expand the attack surface -- attack the scoring/judging/artifact-delivery surface itself (score API, Oracle endpoint, hidden data/backups, supply-chain caches, privilege edges, side channels) or question the challenge assumptions. First call activates reward-hack mode (new milestones settle at the configured multiplier). Evidence must still come from real command output. Returns the vector library and your live standing.',
    parameters: {
      vector: {
        type: 'string',
        description: 'one of: ' + HACK_VECTORS.join(' / '),
        required: false,
      },
      hypothesis: { type: 'string', description: 'the unconventional hypothesis to test', required: false },
      why: { type: 'string', description: 'why the conventional path is stuck / why this shortcut may exist', required: false },
      target: { type: 'string', description: 'what surface is attacked (score API / flag store / hidden data / ...)', required: false },
    },
    execute(args, exec) {
      const session = sessionFor(exec)
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
          ? `Reward-hack mode activated (multiplier ${res.multiplier}x) -- conventional paths are no longer trusted; attack-surface expansion starts.`
          : `Unconventional branch #${res.hackBranches} appended (vector=${res.vector}).`,
        'Vector library: ' + HACK_VECTORS.join(' | '),
      ]
      if (!args.vector) lines.push('Next: pick the vector most likely to hide a shortcut, probe it immediately with real commands, then settle with ctf_step.')
      return lines.join('\n')
    },
  })

  // -- Discipline watchdog: every non-ctf tool call (a real environment
  // action) is booked; actions not settled via ctf_step are deducted at
  // -0.05 each on the next settle (P7 forced-evaluation approximation).
  // v0.8.0: delegation/reasoning tools (subagent*, send_message/list_agents/
  // interrupt_agent, job_*) are NOT environment interactions and are excluded
  // from the unsettled-action discipline, as are the ctf_* ledger tools.
  ctx.on('tools/result', (exec, result) => {
    try {
      const agent = exec && exec.agent
      if (!agent) return
      const eng = engines.get(agent.id)
      if (eng === undefined) return
      const name = exec.name
      if (typeof name !== 'string') return
      if (name.startsWith('ctf_') || name.startsWith('subagent') || name.startsWith('dev_')) return
      if (REVIEW_EXTRA_ALLOW.has(name)) return
      eng.noteAction(name, !!(result && result.isError))
    } catch { /* observer failures are isolated; tool results unaffected */ }
  })

  // -- Durable-event wake (v0.8.0/v0.8.1): after the phase-0 text-only round
  // delivers the plan product, keep the SAME turn going into the review gate
  // instead of idling for the user (agent-loop continues when inbox.nextStep
  // is non-empty). v0.8.1: the append must NOT run inside a `session/event`
  // observer -- inbox.append() durably appends `agent/inbox/spliced` to the
  // same session, which is reentrancy-blocked while that observer is inside
  // session.append() (core/session "session append cannot reenter"), so the
  // wake was silently lost. It now fires from `agent/turn-stopping`, an agent
  // event dispatched right before the break decision, where a session append
  // is legal and the appended next-step message is seen by the loop's
  // `inbox.nextStep` re-check (same turn continues).
  function wakeReview(session) {
    const agent = agents.get(session.id)
    if (agent === undefined || agent.inbox === undefined) return
    try {
      agent.inbox.append('next-step', {
        id: `ctf-review-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        role: 'user',
        source: { kind: 'plugin', plugin: 'ctf-bootstrap' },
        content: [{ type: 'text', text: REVIEW_WAKE }],
      })
    } catch { /* duplicate/ordering races: skip */ }
  }

  // -- Phase promotion driven by durable session events (v0.8.0) ----------
  // The v0.7.0 assemble-time `session.events` scan never fired on hosts whose
  // Session exposes snapshotEvents() instead of an `.events` array, so phase 0
  // never advanced and the session dead-looped in the minimal round (measured
  // in the CTF session log). These hooks react to the durable event stream:
  //   * the first tool/call -> phase 1 (impatient path; the review gate then
  //     demands the round-1 product text before execution);
  //   * a phase-0 step ending with an assistant TEXT reply (the round-1
  //     product plan + which skill used) -> mark the product delivered,
  //     advance to phase 1 and arm the review-gate wake.
  ctx.on('session/event', (session, event) => {
    try {
      if (isDelegated(session)) return // v0.8.1: subagent children stay plain
      const eng = engines.get(session.id)
      if (eng === undefined) return
      if (event == null) return
      const type = event.type
      if (type === 'tool/call' && eng.state.phase === 0) {
        eng.advancePhase(1, 'standard')
        maybeSave(session.id)
        return
      }
      if (type === 'step/end' && eng.state.phase === 0) {
        const d = event.data || {}
        const hadText = stepHadAssistantText(sessionEvents(session), d.turn, d.step)
        if (hadText) {
          const promoted = eng.advancePhase(1, 'standard')
          eng.markProduct()
          maybeSave(session.id)
          if (promoted) pendingWake.set(session.id, true)
        }
      }
    } catch { /* observer failures are isolated */ }
  })

  // -- Review-gate wake (v0.8.1): consumed at the turn-stop boundary, see
  // wakeReview() above. Only wakes while the round-1 product was delivered and
  // the review gate is still pending; any stale flag is dropped.
  ctx.on('agent/turn-stopping', async ({ agent }) => {
    try {
      const session = agent && agent.session
      if (session === undefined) return
      if (isDelegated(session)) return // v0.8.1: subagent children stay plain
      if (!pendingWake.get(session.id)) return
      const eng = engines.get(session.id)
      if (eng === undefined) return
      const wakeDue = eng.state.phase === 1 && eng.state.reviewState !== 'done' && eng.state.productDelivered
      pendingWake.delete(session.id)
      if (wakeDue) wakeReview(session)
    } catch { /* observer failures must never break the turn-stopping chain */ }
  })

  // -- Per-round prompt assembly (v0.7.0 contract) ------------------------
  // SYSTEM: exactly the built-in minimal persona sentence, replacing every
  // other section (no CTF persona, no tool guidance, no rules, no status in
  // the system prompt). ALL CTF Expert guidance rides the `contexts` channel,
  // which the harness renders as a durable USER-ROLE snapshot appended after
  // the user's messages -- "as user prompt", never system.
  ctx.on('system-prompt/assemble', async (_assembly, context, next) => {
    const agent = context.agent
    const session = agent?.session
    if (session === undefined) return next()
    // v0.8.1: delegated (subagent) children run plain -- no CTF protocol.
    if (isDelegated(session)) return next()
    agents.set(session.id, agent)

    const assembled = await next()
    const eng = engineFor(session.id)
    const toolCalled = hasToolCall(session)

    // Phase advancement (resume-safe fallback; the live path is session/event)
    if (toolCalled && eng.state.phase === 0) eng.advancePhase(1, 'standard')
    if (eng.state.phase === 1 &&
        eng.state.reviewState === 'done' &&
        (eng.state.milestonesHit.length > 0 || eng.state.stepCount >= cfg.phase2AfterSteps)) {
      eng.advancePhase(2, 'hunt')
    }
    maybeSave(session.id)

    const st = eng.status()
    // Guide for the CURRENT phase (plus the review gate), as user prompt.
    let guide
    if (eng.state.phase === 0) guide = MINIMAL_GUIDE
    else if (eng.state.phase === 1) guide = eng.state.reviewState === 'done' ? STANDARD_GUIDE : REVIEW_GUIDE
    else guide = HUNT_GUIDE
    // Keep the phase/status guidance OUT of the system prompt: contexts are the
    // user-role channel. Status carries score/directive/goal every round.
    const contexts = [
      ...(assembled.contexts || []).filter((c) => !c.name || !c.name.startsWith('ctf-')),
      { name: 'ctf-guide', text: guide },
      { name: 'ctf-status', text: statusText(st) },
    ]
    const sections = [{ name: 'ctf-minimal', text: SYSTEM_PERSONA, order: 0 }]

    // Phase 0 -- STRICT built-in-minimal surface: single persona sentence as
    // the whole system, tools = shell + str_replace_editor only; the required
    // product (plan + which skill used) is plain text and NO tool runs this
    // round (v0.8.0 deep-think round).
    if (eng.state.phase === 0) {
      const available = new Set((assembled.tools || []).map((tool) => tool.name))
      const shell = available.has('pwsh') ? 'pwsh' : available.has('bash') ? 'bash' : null
      if (shell === null) {
        return { ...assembled, sections, contexts, tools: assembled.tools }
      }
      const core = new Set([shell, ...cfg.phase0Tools])
      return {
        ...assembled,
        sections,
        contexts,
        tools: (assembled.tools || []).filter((tool) => core.has(tool.name)),
      }
    }

    // Phase 1 -- plan-review gate pending: execution tools are LOCKED; only
    // ctf_* + delegation/subagent tools stay (v0.8.0 "execute only after the
    // plan is perfected", enforced by the tool surface).
    if (eng.state.phase === 1 && eng.state.reviewState !== 'done') {
      return {
        ...assembled,
        sections,
        contexts,
        tools: (assembled.tools || []).filter((tool) => isReviewTool(tool.name)),
      }
    }

    // Phase 1 (review=DONE) / Phase 2: system stays the single persona
    // sentence; full tool catalog; phase rules + live status ride contexts.
    return { ...assembled, sections, contexts }
  })
}
