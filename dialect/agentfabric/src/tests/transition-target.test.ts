/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, it, expect } from 'vitest';
import { parseAndLintSource, parseDocument } from './test-utils.js';
import { extractGraph } from '../graph/extractor.js';
import { AgentFabricSchemaInfo } from '../schema.js';
import { verifyTypedNeighborhood } from '../lint/passes/rules/transition-target-rules.js';

describe('invalid-transition-target lint rule', () => {
  it('reports no invalid-transition-target for a valid DAG', () => {
    const source = `
config:
  agent_name: "tt-valid"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

trigger t:
  kind: "a2a"
  target: "brokers://tt-valid/a2a"
  on_message: ->
    transition to @generator.g

generator g:
  llm: @llm.g
  prompt: -> summarize
  on_exit: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(
      result.diagnostics.filter(d => d.code === 'invalid-transition-target')
    ).toEqual([]);
  });

  it('flags a transition that targets a trigger node', () => {
    // The target trigger is a defined symbol, so undefined-reference stays
    // quiet — this is purely a typed-neighborhood error that scoped
    // verification (GRACE-inspired) is what catches it.
    const source = `
config:
  agent_name: "tt-into-trigger"

trigger t:
  kind: "a2a"
  target: "brokers://tt-into-trigger/a2a"
  on_message: ->
    transition to @echo.mid

echo mid:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_WORKING"
  message: "routing back"
  on_exit: ->
    transition to @trigger.t
`;
    const result = parseAndLintSource(source);
    const hits = result.diagnostics.filter(
      d => d.code === 'invalid-transition-target'
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].source).toBe('agentfabric-lint');
    expect(hits[0].message).toContain('@trigger.t');
    expect(hits[0].message).toContain('trigger');
  });
});

describe('verifyTypedNeighborhood (GRACE scoped verifier)', () => {
  it('full-graph mode flags the edge into a trigger and derives legal kinds from the schema', () => {
    const source = `
config:
  agent_name: "tt-core"

trigger t:
  kind: "a2a"
  target: "brokers://tt-core/a2a"
  on_message: ->
    transition to @echo.mid

echo mid:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_WORKING"
  message: "x"
  on_exit: ->
    transition to @trigger.t
`;
    const parsed = parseDocument(source);
    const extracted = extractGraph(parsed, AgentFabricSchemaInfo);
    const violations = verifyTypedNeighborhood(
      extracted,
      AgentFabricSchemaInfo
    );
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({
      fromId: 'echo.mid',
      toId: 'trigger.t',
      toKind: 'trigger',
    });
    // Legal kinds are derived from the schema's transitionTarget capability,
    // sorted for deterministic messages — trigger is absent on purpose.
    expect(violations[0].legalKinds).toEqual([
      'echo',
      'executor',
      'generator',
      'orchestrator',
      'router',
      'subagent',
    ]);
  });

  it('scoped mode only inspects neighborhoods of modified nodes', () => {
    // Two identical bad edges (gen1 -> trigger, gen2 -> trigger). Limiting the
    // scope to gen1 surfaces only gen1's violation — gen2's neighborhood is
    // left unverified, exactly GRACE's local re-verification of a change.
    const source = `
config:
  agent_name: "tt-scoped"

trigger t:
  kind: "a2a"
  target: "brokers://tt-scoped/a2a"
  on_message: ->
    transition to @generator.gen1

generator gen1:
  prompt: -> one
  on_exit: ->
    transition to @trigger.t

generator gen2:
  prompt: -> two
  on_exit: ->
    transition to @trigger.t
`;
    const parsed = parseDocument(source);
    const extracted = extractGraph(parsed, AgentFabricSchemaInfo);

    const scoped = verifyTypedNeighborhood(extracted, AgentFabricSchemaInfo, {
      modifiedNodeIds: ['generator.gen1'],
    });
    expect(scoped).toHaveLength(1);
    expect(scoped[0].fromId).toBe('generator.gen1');

    // Full-graph mode catches both bad edges.
    const full = verifyTypedNeighborhood(extracted, AgentFabricSchemaInfo);
    expect(full).toHaveLength(2);
  });

  it('skips dangling targets (existence is undefined-referencePass job)', () => {
    const source = `
config:
  agent_name: "tt-dangling"

trigger t:
  kind: "a2a"
  target: "brokers://tt-dangling/a2a"
  on_message: ->
    transition to @subagent.missing
`;
    const parsed = parseDocument(source);
    const extracted = extractGraph(parsed, AgentFabricSchemaInfo);
    // The missing target is not a typed error — verifyTypedNeighborhood ignores
    // it so the dangling-reference diagnostic stays the single source of truth.
    expect(verifyTypedNeighborhood(extracted, AgentFabricSchemaInfo)).toEqual(
      []
    );
  });
});
