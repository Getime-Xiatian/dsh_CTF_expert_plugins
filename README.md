# CTF Expert - dsh CTF 能力插件 / Agent 预设 (v0.6.0)

Reward-driven autonomous CTF agent for dsh: CVE repro / PoC validation / exploit
generation. Provides the Agent preset `CTF Expert` with a reward/penalty
mechanism (maximize score), autonomous path-finding, loop-break, skill routing
(which skill used) and a final-goal guarantee (no completion before
goal=ACHIEVED). All LLM-facing prompts are English; English thinking enforced.

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
| `ctf-bootstrap.mjs` | Runtime plugin: 6 ctf_* tools + 3-phase assemble gating + tools/result watchdog + optional ledger persistence |

## Phase design (v0.6.0)

- **phase 0 (minimal)** - STRICT mirror of the harness built-in `minimal`
  preset: ONE fixed English complete persona replaces all sections, no runtime
  context, tools = shell + str_replace_editor only. Required product of the
  round, as plain text: **plan + which skill used**. The first shell probe
  opens phase 1.
- **phase 1 (standard)** - full tool catalog + settlement rules (settle every
  environment interaction with ctf_step).
- **phase 2 (hunt)** - full reward/penalty regime + loop-break + context
  hygiene (PDF P7).

All LLM-visible text (persona, phase sections, status lines, tool descriptions
and returns, skill catalog fields) is English-only; every phase instructs the
model to think and reason in English.

## Design provenance

- Rewards/loop-break: local "AI autonomous execution optimization" PDF P4-P7
  (layered milestones, one-shot settlement, step cost, exponential repeat
  penalty, stagnation loop-break, dual-skill, middleware-forced evaluation).
- Skill routing (v0.5.0): borrows the routing model of
  https://github.com/zhaoxuya520/reverse-skill (challenge type -> narrowest
  downstream skill); lightweight index only, no inlined external code.
- Minimal-mode alignment (v0.6.0): mirrors the harness built-in `minimal`
  preset (single fixed English complete persona, shell + editor, no runtime
  context) per user requirement; product = plan + which skill used.
- Tests/docs/change ledger live at /home/xiatian/default/ctf-expert/
  (TRACE.md records every change, T-<n>).
