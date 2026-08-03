/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, it, expect } from 'vitest';
import { parseAndLintSource } from './test-utils.js';

// Exercises the wiring in AgentFabricSemanticPass.finalize() (via the public
// agentfabric dialect -> defaultRules -> agentFabricSemanticPass), proving the
// new checkEvidenceGateRules runs alongside the existing graph-aware passes.
describe('evidence-gate rules', () => {
  it('flags completion reached only through unguarded edges while failure is gated', () => {
    // Router "r" gates its FAILED outcome with a "when" predicate but reaches
    // COMPLETED unconditionally via `otherwise` — the success claim is the one
    // lifecycle transition not bound to verifiable evidence.
    const source = `
config:
  agent_name: "evidence-gate-asymmetry"

trigger t:
  kind: "a2a"
  target: "brokers://evidence-gate-asymmetry/a2a"
  on_message: -> transition to @router.r

router r:
  routes:
    - target: @echo.failed
      when: True
  otherwise:
    target: @echo.done

echo failed:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_FAILED"
  message: "failed"

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "done"
`;
    const result = parseAndLintSource(source);
    const warnings = result.diagnostics.filter(
      d => d.code === 'terminal-completion-requires-evidence-gate'
    );
    expect(warnings).toHaveLength(1);
    expect(typeof warnings[0].message).toBe('string');
    expect(warnings[0].message).toContain('completed');
  });

  it('does not flag when the completion transition is also gated', () => {
    // Both outcomes are gated by a "when" route; completion is evidenced.
    const source = `
config:
  agent_name: "evidence-gate-balanced"

trigger t:
  kind: "a2a"
  target: "brokers://evidence-gate-balanced/a2a"
  on_message: -> transition to @router.r

router r:
  routes:
    - target: @echo.done
      when: True
    - target: @echo.failed
      when: True
  otherwise:
    target: @echo.failed

echo failed:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_FAILED"
  message: "failed"

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "done"
`;
    const result = parseAndLintSource(source);
    expect(
      result.diagnostics.some(
        d => d.code === 'terminal-completion-requires-evidence-gate'
      )
    ).toBe(false);
  });

  it('does not flag a direct trigger-to-completed entry transition', () => {
    // A trigger's entry response may declare completion directly; it is the
    // agent's response, not a false-DONE claim from a work node.
    const source = `
config:
  agent_name: "evidence-gate-simple"

trigger t:
  kind: "a2a"
  target: "brokers://evidence-gate-simple/a2a"
  on_message: -> transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "done"
`;
    const result = parseAndLintSource(source);
    expect(
      result.diagnostics.some(
        d => d.code === 'terminal-completion-requires-evidence-gate'
      )
    ).toBe(false);
  });
});
