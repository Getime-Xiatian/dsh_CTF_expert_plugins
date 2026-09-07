/**
 * ctf-bootstrap -- CTF Expert preset runtime plugin (zero external deps; same
 * shape as router-bootstrap).
 *
 * Three-phase routing (goal: one minimal thinking round first, then the full
 * standard toolset, then the reward/penalty + loop-break regime):
 * phase 0 think STRICT mirror of the harness built-in `minimal` preset:
 * the system prompt is ONE fixed English complete persona
 * (no runtime context, no extra sections), the tool surface
 * is shell + str_replace_editor only, and contexts are
 * cleared. The required product of this round is emitted as
 * plain text: plan + which skill used.
 * phase 1 standard First durable tool/call after phase 0: full Standard
 * catalog opens and the settlement rules are injected
 * (settle every environment interaction with ctf_step).
 * phase 2 hunt After the first milestone / step threshold: full reward
 * & penalty regime + strengthened loop-break + failure
 * context hygiene (PDF P7) injected every round.
 *
 * Phase detection is driven entirely by durable session events (tool/call),
 * so resume/reload stays consistent. The engine ledger (ctf-engine) always
 * runs: BACKTRACK loop-break becomes visible from phase 1 onward.
 *
 * v0.5.0: minimal-round product made explicit as "plan + which skill used" -- 
 * CTF_SKILLS skill-routing (taxonomy borrows zhaoxuya520/reverse-skill,
 * index only, no inlined code); ctf_plan takes a skill argument; status line
 * carries goal=ACHIEVED/PENDING final-goal guarantee bit.
 * v0.6.0: phase 0 strictly mirrors the built-in minimal preset (single fixed
 * English persona = whole system prompt, shell + str_replace_editor only,
 * product = plan + which skill used as plain text); ALL LLM-visible prompt
 * text (sections, status lines, tool returns) is English; English thinking
 * is enforced in every phase.
 */

import { createEngine, ENGINE_VERSION, HACK_VECTORS, CTF_SKILLS } from './ctf-engine.mjs'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

export const name = 'ctf-bootstrap'

export const inject = ['systemPrompt', 'tools']

/** Defaults overridable via the `config` of the preset row. */
const DEFAULTS = {
 /** Phase-0 surface (shell is added automatically). Strict built-in-minimal
 * semantics: shell + str_replace_editor only, no ctf_* tools in phase 0. */
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
 * Phase 0 -- strict mirror of the harness built-in `minimal` preset: one fixed
 * English complete persona is the whole system prompt (no runtime context, no
 * extra sections), tools are shell + str_replace_editor, and the required
 * product of the round is plain text: plan + which skill used.
 */
const MINIMAL_PERSONA = [
 'You are a helpful software engineer assistant working in CTF minimal mode.',
 'This round mirrors the harness built-in minimal preset: a fixed system prompt,',
 'no runtime context, and only a shell plus a file editor are available.',
 'Think and reason in English. Produce this round\'s required product before acting:',
 '1. plan -- a focused one-round analysis: the target surface, ONE hypothesis, the',
 ' single highest-value first probe, and the exact output that would count as',
 ' progress (a milestone);',
 '2. which skill used -- one id from the CTF skill routing list (web-runtime,',
 ' reverse-pwn, crypto-mobile, identity-windows, cloud-container, pcap-protocol,',
 ' stego-forensic, patch-diff, code-audit, malware-config, zip-archive, llm-agent).',
 'Required output: plan + which skill used.',
 'Forbidden: aimless scanning, repeating checks already done, or widening the',
 'attack surface without evidence. When you are ready to act, running the first',
 'shell probe opens the full toolset.',
].join('\n')

/** Phase 1 -- standard mode: full tools + settlement rules (all English). */
const STANDARD_SECTION = [
 '[CTF Expert / Phase 1 / Standard mode / settlement rules]',
 'The full tool catalog is open. Think and reason in English.',
 'Autonomous path-finding rules:',
 '1. After EVERY environment interaction you MUST call ctf_step to settle it',
 ' (pass the command, output/key excerpt, and whether it errored). Skipping',
 ' settlement means the step earns no progress.',
 '2. Live ledger: ctf_status. totalScore is your single optimization target;',
 ' milestones pay once on first discovery.',
 '3. Each step costs; consecutive repeated commands escalate the penalty',
 ' exponentially; failed/invalid calls are penalized.',
 '4. When the stagnation counter reaches 3 you receive the BACKTRACK directive -- ',
 ' switch direction immediately, do not spin in place.',
 '5. When you switch branch/direction, record objective + which skill used with',
 ' ctf_plan (skill routing list in ctf_status). Pick the narrowest skill that',
 ' fits the dominant evidence surface: Web-> web-runtime, binary/pwn-> reverse-pwn,',
 ' crypto/mobile-> crypto-mobile, identity/AD-> identity-windows,',
 ' cloud/container-> cloud-container, capture/protocol-> pcap-protocol,',
 ' stego/forensics-> stego-forensic, N-day/CVE-> patch-diff, source-> code-audit,',
 ' sample-> malware-config, ZIP-> zip-archive, AI app-> llm-agent.',
 '6. Score is the only goal. When the conventional path stalls or a faster one',
 ' exists, unconventional thinking is allowed and encouraged -- use ctf_hack to',
 ' widen the attack surface (scoring/judging/Oracle/flag delivery, hidden data,',
 ' supply chain, privilege edges, side channels, questioning challenge',
 ' assumptions) and find real vulnerabilities or shortcuts. Evidence must come',
 ' from real command output, never self-report.',
 'Final-goal guarantee: you MUST NOT declare the task complete before flag',
 'evidence is settled (goal=ACHIEVED). Keep probing, switching skills or branches.',
 'Goal: keep totalScore rising until you retrieve the flag.',
].join('\n')

/** Phase 2 -- hunt mode: full reward/penalty regime (PDF P5- P7; all English). */
const HUNT_SECTION = [
 '[CTF Expert / Phase 2 / Hunt mode / reward/penalty regime active]',
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

/** One-line live status injected every round (core directive visibility). */
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

 // -- Per-round system assembly: inject phase/rules/live status; phase 0
 // mirrors the built-in minimal preset (single persona, dual tools).
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

 // Phase 0 -- STRICT built-in-minimal mirror: single fixed English persona
 // replaces every other section, runtime context cleared, tools limited to
 // shell + str_replace_editor (the required product plan + which skill used
 // is plain text; the first shell probe opens the full toolset).
 if (!hasToolCall && eng.state.phase === 0) {
 const available = new Set((assembled.tools || []).map((tool) => tool.name))
 const shell = available.has('pwsh') ? 'pwsh' : available.has('bash') ? 'bash' : null
 const minimalSections = [{ name: 'ctf-minimal', text: MINIMAL_PERSONA, order: 0 }]
 if (shell === null) {
 return { ...assembled, sections: minimalSections, contexts: [], tools: assembled.tools }
 }
 const core = new Set([shell, ...cfg.phase0Tools])
 return {
 ...assembled,
 sections: minimalSections,
 contexts: [],
 tools: (assembled.tools || []).filter((tool) => core.has(tool.name)),
 }
 }

 const sections = [...(assembled.sections || [])]
 const st = eng.status()
 sections.push({ name: 'ctf-status', text: statusText(st), order: 900 })
 sections.push(eng.state.phase === 1
 ? { name: 'ctf-standard', text: STANDARD_SECTION, order: 901 }
 : { name: 'ctf-hunt', text: HUNT_SECTION, order: 901 })

 return { ...assembled, sections }
 })
}
