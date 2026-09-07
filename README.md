# CTF Expert - dsh CTF 能力插件 / Agent 预设 (v0.7.0)

> **English** | [简体中文](README.zh-CN.md)

Reward-driven autonomous CTF agent for dsh: CVE repro / PoC validation / exploit
generation. Provides the Agent preset `CTF Expert` with a reward/penalty
mechanism (maximize score), autonomous path-finding, loop-break, skill routing
(which skill used) and a final-goal guarantee (no completion before
goal=ACHIEVED). All LLM-facing prompts are English; English thinking enforced.

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
| `ctf-engine.mjs` | Pure-logic zero-dep engine: layered rewards/penalties, stagnation BACKTRACK, one-shot milestones, FNV-1a hash-chain ledger, discipline watchdog, reward-hack, CTF_SKILLS routing, goalAchieved final state |
| `ctf-bootstrap.mjs` | Runtime plugin: 6 ctf_* tools + 3-phase gating + tools/result watchdog + optional ledger persistence + v0.7 prompt-injection contract |

## Phase design (v0.7.0)

- **phase 0 (minimal)** - STRICT mirror of the harness built-in `minimal`
  preset: system = the single persona sentence above (and nothing else), tools
  = shell + str_replace_editor only. Required product of the round, as plain
  text: **plan + which skill used**. The first shell probe opens phase 1.
- **phase 1 (standard)** - full tool catalog + settlement rules (settle every
  environment interaction with ctf_step).
- **phase 2 (hunt)** - full reward/penalty regime + loop-break + context
  hygiene (PDF P7).

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
- Tests/docs/change ledger live at /home/xiatian/default/ctf-expert/
  (TRACE.md records every change, T-<n>).
