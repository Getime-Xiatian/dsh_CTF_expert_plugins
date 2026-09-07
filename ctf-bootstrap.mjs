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
 * Three-phase routing (goal: one minimal thinking round first, then the full
 * standard toolset, then the reward/penalty + loop-break regime):
 *   phase 0 think    STRICT mirror of the harness built-in `minimal` preset:
 *                    system = the single persona sentence above, no runtime
 *                    context, tools = shell + str_replace_editor only. The
 *                    required product of this round (plan + which skill used)
 *                    is emitted as plain text.
 *   phase 1 standard First durable tool/call after phase 0: the full Standard
 *                    catalog opens; settlement rules are injected (settle every
 *                    environment interaction with ctf_step).
 *   phase 2 hunt     After the first milestone / step threshold: full reward
 *                    & penalty regime + strengthened loop-break + failure
 *                    context hygiene (PDF P7).
 *
 * Phase detection is driven entirely by durable session events (tool/call), so
 * resume/reload stays consistent. The engine ledger (ctf-engine) always runs:
 * BACKTRACK loop-break becomes visible from phase 1 onward.
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
 * skill used, emitted as plain text.
 */
const MINIMAL_GUIDE = [
  'CTF Expert minimal round (injected as a user prompt; the system prompt stays the built-in minimal persona only).',
  'Think and reason in English.',
  'Available tools this round: a shell and a file editor only (no ctf_* tools yet).',
  'Produce this round\'s required product as plain text before acting:',
  '1. plan -- a focused one-round analysis: the target surface, ONE hypothesis, the',
  '   single highest-value first probe, and the exact output that would count as',
  '   progress (a milestone);',
  '2. which skill used -- one id from the CTF skill routing list (' + SKILL_IDS + ').',
  'Required output: plan + which skill used.',
  'Forbidden: aimless scanning, repeating checks already done, or widening the attack',
  'surface without evidence.',
  'When you are ready to act, running the first shell probe opens the full toolset.',
].join('\n')

/** Phase-1 USER-prompt guidance: standard mode rules (all English). */
const STANDARD_GUIDE = [
  '[CTF Expert / Phase 1 / Standard mode / settlement rules (user prompt; system stays the minimal persona)]',
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
  '   widen the attack surface (scoring/judging/Oracle/flag delivery, hidden data,',
  '   supply chain, privilege edges, side channels, questioning challenge',
  '   assumptions) and find real vulnerabilities or shortcuts. Evidence must come',
  '   from real command output, never self-report.',
  'Final-goal guarantee: you MUST NOT declare the task complete before flag',
  'evidence is settled (goal=ACHIEVED). Keep probing, switching skills or branches.',
  'Goal: keep totalScore rising until you retrieve the flag.',
].join('\n')

/** Phase-2 USER-prompt guidance: hunt mode rules (PDF P5-P7; all English). */
const HUNT_GUIDE = [
  '[CTF Expert / Phase 2 / Hunt mode / reward/penalty regime active (user prompt; system stays the minimal persona)]',
  'Think and reason in English.',
  'Scoring: first new service/port +1.0 / confirmed vulnerability +2.0 / hash',
  'extracted +2.0 / access gained +3.0 / flag retrieved +10.0.',
  'First-seen command combination +0.1 (exploration bonus); each step -0.05;',
  'consecutive repeats -0.2/-0.4/-0.8 (exponential); failed/invalid call -0.5.',
  'Anti-farming: each milestone settles ONCE -- oscillating between states earns',
  'nothing; a flag settles only from real output evidence, never self-report.',
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
  'thinking -- treat the judging/scoring/flag-delivery surface itself as attack',
  'surface (scoring API / Oracle endpoints / hidden data & backups / supply-chain',
  'caches / privilege edges / side-channel differences / "the challenge assumption',
  'itself is wrong"). A real unconventional breakthrough pays as a real milestone',
  '(reward-hack milestones may carry a multiplier).',
  'Endgame: after retrieving the flag call ctf_export to export the ledger as the',
  'completion evidence chain; do NOT declare completion before goal=ACHIEVED.',
].join('\n')

/** One-line live status injected every round through the user contexts channel. */
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
    line += '\n[!] Loop-break: the current direction yields no gain. You MUST call ctf_backtrack to switch direction; do not repeat the same command.'
  }
  if (st.hackMode) {
    line += `\n[GOAL] Reward-hack mode: conventional paths are not trusted. Use ctf_hack to enumerate unconventional attack surfaces and probe one now; milestones settle at multiplier ${st.multiplier ?? 1}x (breakthroughs: ${st.hackBreakthroughs}).`
  }
  if (st.pendingActions > 0) {
    line += '\n[!] Discipline: environment actions not settled via ctf_step; the next settle deducts 0.05 each. Settle after every environment interaction.'
  }
  if (!st.goalAchieved) {
    line += '\n[GOAL] Final-goal guarantee: no flag evidence yet. Do not declare completion before GOAL_ACHIEVED -- keep probing or switch skills until ctf_status shows goal=ACHIEVED.'
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

  function currentSession() {
    const agent = ctx.get('agent')
    return agent?.session
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
    description: 'Show the CTF Expert ledger: current phase, totalScore, step/stagnation counters, milestone history, pending directive. Call it whenever you need your live score or before choosing the next move.',
    parameters: {},
    execute() {
      const session = currentSession()
      if (!session) return 'no agent session'
      const st = engineFor(session.id).status()
      return [
        statusText(st),
        `engine=${ENGINE_VERSION} discovered=[${st.discovered.join(',') || '-'}] branches=${st.branches}`,
        'Skill routing (which skill used; taxonomy borrowed from zhaoxuya520/reverse-skill): ' +
          CTF_SKILLS.map((s) => `${s.id}=${s.label}`).join(' | '),
        'Rules summary: call ctf_step after every environment interaction; 3 stagnant steps trigger BACKTRACK (ctf_backtrack first, then switch direction); each milestone settles once; do not declare completion before goal=ACHIEVED.',
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
      if (rec.newEvents.length) lines.push(`Milestone first-time settlement: ${rec.newEvents.join(', ')}`)
      if (rec.directive === 'BACKTRACK') {
        lines.push('BACKTRACK: gains are consistently negative. Abandon this direction -> call ctf_backtrack with the reason -> pick a fundamentally different entry point.')
      } else if (rec.directive === 'GOAL_ACHIEVED') {
        lines.push('GOAL_ACHIEVED: flag evidence detected. Call ctf_export to export the ledger as completion evidence, then report to the user.')
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
    execute(args) {
      const session = currentSession()
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
    description: 'Record one exploration branch/plan (autonomous path-finding evidence + which-skill-used). Pass objective/hypothesis/firstProbe AND the skill (one of the CTF_SKILLS ids: ' + CTF_SKILLS.map((s) => s.id).join(', ') + ') you will use on this branch. Use it whenever you switch to a new branch (and to persist the plan from the minimal round).',
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
      return `Branch #${res.branches} recorded (phase=${res.phase} ${res.phaseName}) skill=${res.skill || '(not declared)'}. Run the first probe, then settle its output with ctf_step.`
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
    description: 'Reward-hacking pivot: switch to unconventional thinking to maximize score. When conventional branches stall, expand the attack surface -- attack the scoring/judging/flag-delivery surface itself (score API, Oracle endpoint, hidden data/backups, supply-chain caches, privilege edges, side channels) or question the challenge assumptions. First call activates reward-hack mode (new milestones settle at the configured multiplier). Evidence must still come from real command output. Returns the vector library and your live standing.',
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
  ctx.on('tools/result', (exec, result) => {
    try {
      const agent = exec && exec.agent
      if (!agent) return
      const eng = engines.get(agent.id)
      if (eng === undefined) return
      const name = exec.name
      if (typeof name === 'string' && name.startsWith('ctf_')) return
      eng.noteAction(name, !!(result && result.isError))
    } catch { /* observer failures are isolated; tool results unaffected */ }
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

    const assembled = await next()
    const eng = engineFor(session.id)
    const hasToolCall = (session.events || []).some((event) => event.type === 'tool/call')

    // Phase advancement (driven by durable session events; resume-safe)
    if (hasToolCall && eng.state.phase === 0) eng.advancePhase(1, 'standard')
    if (eng.state.phase === 1 &&
        (eng.state.milestonesHit.length > 0 || eng.state.stepCount >= cfg.phase2AfterSteps)) {
      eng.advancePhase(2, 'hunt')
    }
    maybeSave(session.id)

    const st = eng.status()
    // Guide for the CURRENT phase, as user prompt.
    const guide = eng.state.phase === 0
      ? MINIMAL_GUIDE
      : (eng.state.phase === 1 ? STANDARD_GUIDE : HUNT_GUIDE)
    // Keep the phase/status guidance OUT of the system prompt: contexts are the
    // user-role channel. Status carries score/directive/goal every round.
    const contexts = [
      ...(assembled.contexts || []).filter((c) => !c.name || !c.name.startsWith('ctf-')),
      { name: 'ctf-guide', text: guide },
      { name: 'ctf-status', text: statusText(st) },
    ]

    // Phase 0 -- STRICT built-in-minimal surface: single persona sentence as
    // the whole system, no runtime context beyond our user-role guide, tools =
    // shell + str_replace_editor. The required product (plan + which skill
    // used) is plain text; the first shell probe opens the full toolset.
    if (!hasToolCall && eng.state.phase === 0) {
      const available = new Set((assembled.tools || []).map((tool) => tool.name))
      const shell = available.has('pwsh') ? 'pwsh' : available.has('bash') ? 'bash' : null
      const sections = [{ name: 'ctf-minimal', text: SYSTEM_PERSONA, order: 0 }]
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

    // Phases 1-2: system stays the single persona sentence; full tool catalog;
    // phase rules + live status ride the user contexts channel.
    const sections = [{ name: 'ctf-minimal', text: SYSTEM_PERSONA, order: 0 }]
    return { ...assembled, sections, contexts }
  })
}
