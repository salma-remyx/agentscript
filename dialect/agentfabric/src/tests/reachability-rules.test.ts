/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, it, expect } from 'vitest';
import type { Diagnostic } from '@agentscript/language';
import { parseAndLintSource } from './test-utils.js';

// Exercises the reachability / liveness lint rules through the real
// `agentfabricDialect` pipeline (parseAndLint -> AgentFabricSemanticPass
// -> checkReachabilityRules), not by calling the rule in isolation.

function withCode(diagnostics: Diagnostic[], code: string): Diagnostic[] {
  return diagnostics.filter(d => d.code === code);
}

describe('reachability / liveness rules', () => {
  it('flags an orphan subgraph no trigger can reach (unreachable-from-trigger)', () => {
    // Trigger reaches only @echo.done. The orchestrator A <-> B cycle is
    // referenced internally (A<-B, B<-A) so unused-node skips it, but it is
    // unreachable from any trigger — a dead state.
    const source = `
config:
  agent_name: "orphan-subgraph"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

trigger t:
  kind: "a2a"
  target: "brokers://orphan-subgraph/a2a"
  on_message: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"

orchestrator A:
  description: "orphan A"
  llm: @llm.g
  reasoning:
    instructions: ->
      | work
  on_exit: ->
    transition to @orchestrator.B

orchestrator B:
  description: "orphan B"
  llm: @llm.g
  reasoning:
    instructions: ->
      | work
  on_exit: ->
    transition to @orchestrator.A
`;
    const { diagnostics } = parseAndLintSource(source);
    const found = withCode(diagnostics, 'unreachable-from-trigger');
    expect(found.length).toBeGreaterThanOrEqual(2);
    const messages = found.map(d => d.message);
    expect(messages.some(m => m.includes('@orchestrator.A'))).toBe(true);
    expect(messages.some(m => m.includes('@orchestrator.B'))).toBe(true);
  });

  it('does not flag nodes that are reachable from a trigger', () => {
    const source = `
config:
  agent_name: "reachable-chain"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

trigger t:
  kind: "a2a"
  target: "brokers://reachable-chain/a2a"
  on_message: ->
    transition to @subagent.work

subagent work:
  llm: @llm.g
  description: "worker"
  reasoning:
    instructions: ->
      | work
  on_exit: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const { diagnostics } = parseAndLintSource(source);
    expect(withCode(diagnostics, 'unreachable-from-trigger')).toEqual([]);
  });

  it('flags a router whose routes share the same gating condition (overlapping-route-predicates)', () => {
    // Two routes gated by \`True\` both fire on every input — a nondeterministic
    // transition conflict.
    const source = `
config:
  agent_name: "overlap-routes"

trigger t:
  kind: "a2a"
  target: "brokers://overlap-routes/a2a"
  on_message: ->
    transition to @router.r

router r:
  routes:
    - target: @echo.high
      when: True
    - target: @echo.low
      when: True
  otherwise:
    target: @echo.done

echo high:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "high"

echo low:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "low"

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const { diagnostics } = parseAndLintSource(source);
    const found = withCode(diagnostics, 'overlapping-route-predicates');
    expect(found).toHaveLength(1);
    expect(found[0].message).toContain('same condition');
  });

  it('does not flag a router with distinct route predicates', () => {
    const source = `
config:
  agent_name: "distinct-routes"

trigger t:
  kind: "a2a"
  target: "brokers://distinct-routes/a2a"
  on_message: ->
    transition to @router.r

router r:
  routes:
    - target: @echo.high
      when: True
    - target: @echo.low
      when: False
  otherwise:
    target: @echo.done

echo high:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "high"

echo low:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "low"

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const { diagnostics } = parseAndLintSource(source);
    expect(withCode(diagnostics, 'overlapping-route-predicates')).toEqual([]);
  });

  it('flags a node reachable from two independent triggers (shared-state-convergence)', () => {
    const source = `
config:
  agent_name: "convergence"

trigger a:
  kind: "a2a"
  target: "brokers://convergence/a"
  on_message: ->
    transition to @echo.join

trigger b:
  kind: "a2a"
  target: "brokers://convergence/b"
  on_message: ->
    transition to @echo.join

echo join:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "joined"
`;
    const { diagnostics } = parseAndLintSource(source);
    const found = withCode(diagnostics, 'shared-state-convergence');
    expect(found).toHaveLength(1);
    expect(found[0].message).toContain('@echo.join');
    expect(found[0].message).toContain('2 independent');
  });
});
