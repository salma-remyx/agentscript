/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, it, expect } from 'vitest';
import { parseAndLintSource, parseDocument, toRecord } from './test-utils.js';
import {
  certifyLoopContract,
  computeStateDigest,
} from '../lint/passes/rules/loop-contract-receipt.js';

const CLEAN_SOURCE = `
config:
  agent_name: "loop-contract-clean"

trigger t:
  kind: "a2a"
  target: "brokers://loop-contract-clean/a2a"
  on_message: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;

const CYCLIC_SOURCE = `
config:
  agent_name: "loop-contract-cycle"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

trigger t:
  kind: "a2a"
  target: "brokers://loop-contract-cycle/a2a"
  on_message: ->
    transition to @orchestrator.A

orchestrator A:
  description: "node A"
  llm: @llm.g
  reasoning:
    instructions: ->
      | work
  on_exit: ->
    transition to @orchestrator.B

orchestrator B:
  description: "node B"
  llm: @llm.g
  reasoning:
    instructions: ->
      | work
  on_exit: ->
    transition to @orchestrator.C

orchestrator C:
  description: "node C"
  llm: @llm.g
  reasoning:
    instructions: ->
      | work
  on_exit: ->
    transition to @orchestrator.A
`;

describe('loop-contract-receipt (integration via AgentFabricSemanticPass)', () => {
  it('emits a state-bound receipt diagnostic when a cycle is present', () => {
    const result = parseAndLintSource(CYCLIC_SOURCE);
    const receipt = result.diagnostics.find(
      d => d.code === 'loop-contract-violation'
    );
    expect(receipt).toBeDefined();
    expect(receipt?.severity).toBe(3); // DiagnosticSeverity.Information
    expect(receipt?.source).toBe('agentfabric-lint');
    // The verifier evidence is bound to an exact graph-state digest.
    const digest = receipt?.data?.stateDigest;
    expect(typeof digest).toBe('string');
    expect(digest as string).toMatch(/^[0-9a-f]{12}$/);
    expect(receipt?.data?.clause).toBe('certification.acyclic');
  });

  it('binds the receipt digest to the same state the certifier sees', () => {
    const result = parseAndLintSource(CYCLIC_SOURCE);
    const receipt = result.diagnostics.find(
      d => d.code === 'loop-contract-violation'
    );
    const certified = certifyLoopContract(
      toRecord(parseDocument(CYCLIC_SOURCE))
    );
    expect(receipt?.data?.stateDigest).toBe(certified.stateDigest);
  });

  it('emits no receipt diagnostic for an acyclic graph', () => {
    const result = parseAndLintSource(CLEAN_SOURCE);
    expect(
      result.diagnostics.some(d => d.code === 'loop-contract-violation')
    ).toBe(false);
  });
});

describe('certifyLoopContract (capability)', () => {
  it('certifies a clean trigger -> terminal-echo graph', () => {
    const receipt = certifyLoopContract(toRecord(parseDocument(CLEAN_SOURCE)));
    expect(receipt.certification.acyclic).toBe(true);
    expect(receipt.certification.terminalReachable).toBe(true);
    expect(receipt.liveness).toBe(true);
    expect(receipt.conforms).toBe(true);
    expect(receipt.certification.firstCycle).toBeUndefined();
    expect(receipt.admission.triggerCount).toBe(1);
  });

  it('flags the cycle and drops conformance for a cyclic graph', () => {
    const receipt = certifyLoopContract(toRecord(parseDocument(CYCLIC_SOURCE)));
    expect(receipt.certification.acyclic).toBe(false);
    expect(receipt.conforms).toBe(false);
    expect(receipt.certification.firstCycle).toBeDefined();
    expect(receipt.certification.firstCycle!.length).toBeGreaterThan(0);
  });

  it('produces a stable digest for an identical graph state', () => {
    const a = certifyLoopContract(toRecord(parseDocument(CLEAN_SOURCE)));
    const b = certifyLoopContract(toRecord(parseDocument(CLEAN_SOURCE)));
    expect(a.stateDigest).toBe(b.stateDigest);
  });

  it('produces a different digest when the topology changes', () => {
    const clean = certifyLoopContract(toRecord(parseDocument(CLEAN_SOURCE)));
    const cyclic = certifyLoopContract(toRecord(parseDocument(CYCLIC_SOURCE)));
    expect(clean.stateDigest).not.toBe(cyclic.stateDigest);
  });
});

describe('computeStateDigest (order invariance)', () => {
  it('is invariant under node/edge reordering', () => {
    const nodes = [{ id: 'a.a' }, { id: 'a.b' }];
    const edges = [
      { from: 'a.a', to: 'a.b' },
      { from: 'a.b', to: 'a.a' },
    ];
    const reversed = {
      nodes: [{ id: 'a.b' }, { id: 'a.a' }],
      edges: [
        { from: 'a.b', to: 'a.a' },
        { from: 'a.a', to: 'a.b' },
      ],
    };
    expect(computeStateDigest(reversed.nodes, reversed.edges)).toBe(
      computeStateDigest(nodes, edges)
    );
  });
});
