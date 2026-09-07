# CTF Expert - dsh CTF 能力插件 / Agent 预设 (v0.8.2)

> **English** | [简体中文](README.zh-CN.md)

Reward-driven autonomous CTF agent for dsh: CVE repro / PoC validation / exploit
generation. Provides the Agent preset `CTF Expert` with a reward/penalty
mechanism (maximize score), autonomous path-finding, loop-break, skill routing
(which skill used) and a final-goal guarantee (no completion before
goal=ACHIEVED). Round-1 protocol: the minimal deep-think round emits
plan + which skill used as text, a subagent audits and perfects the plan, and
only then do execution tools unlock. All LLM-facing prompts are English;
English thinking enforced.

## Prompt injection contract (v0.7.0)

The system prompt is EXACTLY and ONLY the harness built-in minimal persona,
verbatim:

> You are a helpful software engineer assistant.

Nothing else is injected into the system prompt - no CTF persona, no tool
guidance, no phase rules, no live status. Every piece of CTF Expert guidance
(phase rules, the required product "plan + which skill used", the English
thinking mandate, live ledger status) is injected as a USER prompt through the
assembly `contexts` channel, which the harness renders as a durable user-role
snapshot that supersedes earlier snapshots.

## Install

Put this directory at `~/.dsh/.agent-presets/ctf-expert/` (or your preset
root), then start a new session on **CTF Expert** in the dsh Web Agent Preset
picker.

## Files

| File | Role |
|---|---|
| `agent.cordis.yml` | Preset composition (31 rows, no duplicate ids) |
| `preset.yml` | Display metadata (name/description) |
| `ctf-engine.mjs` | Pure-logic zero-dep engine: layered rewards/penalties, stagnation BACKTRACK, one-shot milestones, FNV-1a hash-chain ledger, discipline watchdog, reward-hack, CTF_SKILLS routing, goalAchieved final state, round-1 gate (productDelivered / reviewState) |
| `ctf-bootstrap.mjs` | Runtime plugin: 7 ctf_* tools (incl. ctf_review) + phase gating + review-gate tool lock + durable session/event promotion + tools/result watchdog + optional ledger persistence + v0.7 prompt-injection contract |

## Round-1 protocol + phase design (v0.8.0)

- **phase 0 (minimal deep-think round)** - STRICT mirror of the harness
  built-in `minimal` preset: system = the single persona sentence above (and
  nothing else), tools = shell + str_replace_editor only. This round does NOT
  call tools: deep thinking only, do not rush to a conclusion. Required
  product, as plain text: **plan + which skill used**. The text-only round
  immediately wakes the review gate (no idle wait).
- **phase 1 (standard) - plan-review gate first**: while review=PENDING the
  tool catalog is physically LOCKED to ctf_* + delegation (subagent) tools -
  no shell/file/probing. Sequence: write the plan text if missing -> ctf_plan
  -> dispatch ONE subagent (subagent tool, run_in_background: false) to audit
  and perfect the plan -> ctf_review (review=DONE unlocks execution). After
  review=DONE: full catalog + settlement rules (settle every environment
  interaction with ctf_step). Phase 1 -> 2 only after review=DONE.
- **phase 2 (hunt)** - full reward/penalty regime + loop-break + context
  hygiene (PDF P7).

Status lines carry `review=PENDING|DONE` and `product=DELIVERED`; while the
review gate is pending the phase label reads `1(review)`.

v0.8.1 fixes (measured on real CTF sessions): (1) the review-gate wake now
fires from the `agent/turn-stopping` hook -- the old wake ran inside a
`session/event` observer where a same-session inbox append is reentrancy-
blocked, so the agent idled after the plan text until the user typed
"continue"; (2) ctf_* tools bind the session via the tools-runtime
`exec.agent.session` argument (previously "no agent session" because the
per-session `agent` service is not resolvable from the preset standing
scope); (3) delegated (subagent) children now skip ALL CTF protocol/guidance
(`isDelegated()`: origin=subagent / delegationDepth>0), so the plan-audit
subagent returns a concise verdict with deltas instead of re-outputting the
plan, and the audit prompt demands deltas only.

v0.8.2 refinements: (a) the round-1 plan is now a durable STRUCTURED plan
record in the engine ledger -- `ctf_plan` stores the full plan text +
objective/hypothesis/firstProbe/milestone/skill (v1), and `ctf_review` merges
the audit deltas into that record and marks it audited (plan=AUDITED), so the
finalized plan lives in the ledger (readable via ctf_status / ctf_export /
ledger persistence), not just in conversation text; (b) goal framing is
heuristic "complete the challenge objective" (e.g. the full exploit chain) --
prompts/status no longer steer toward literal `ctf{`/`flag{` string hunting
(blind greps for such markers are explicitly forbidden; the flag only counts
as final confirmation when real command output shows it; detection regex
untouched).

Why v0.8.0 exists: a measured CTF session dead-looped in phase 0 (the agent
probed forever, never emitting the plan) because phase promotion read
`session.events`, which the live Session does not expose. Promotion is now
driven by durable `ctx.on('session/event')` hooks (first tool/call, or a
phase-0 text reply) plus a snapshotEvents()-tolerant helper.

All LLM-visible text (system persona, user-role guidance, status lines, tool
descriptions and returns, skill catalog fields) is English-only; every phase
instructs the model to think and reason in English.

## Design provenance

- Rewards/loop-break: local "AI autonomous execution optimization" PDF P4-P7
  (layered milestones, one-shot settlement, step cost, exponential repeat
  penalty, stagnation loop-break, dual-skill, middleware-forced evaluation).
- Skill routing (v0.5.0): borrows the routing model of
  https://github.com/zhaoxuya520/reverse-skill (challenge type -> narrowest
  downstream skill); lightweight index only, no inlined external code.
- Minimal-mode alignment (v0.6.0/v0.7.0): mirrors the harness built-in
  `minimal` preset per user requirement; product = plan + which skill used.
  v0.7.0 moves every CTF guidance string out of the system prompt into the
  user-role contexts channel (system = only the built-in minimal persona).
- Round-1 protocol (v0.8.0): user requirement - round 1 thinks deeply in
  minimal mode, emits plan + which skill used, then a subagent audits and
  perfects the plan, and only then execution starts (tool-surface enforced).
- Tests/docs/change ledger live at /home/xiatian/default/ctf-expert/
  (TRACE.md records every change, T-<n>).
