/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, it, expect } from 'vitest';
import { parseAndLintSource } from './test-utils.js';

describe('action-spec-gap rule', () => {
  it('warns when a shared action with no input contract is bound by two agents', () => {
    const source = `
config:
  agent_name: "spec-gap-multi"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  notify:
    target: "a2a://notify_conn"
    kind: "a2a:send_message"

trigger t:
  target: "brokers://spec-gap-multi/a2a"
  on_message: -> transition to @orchestrator.o

orchestrator o:
  description: "first consumer"
  llm: @llm.g
  reasoning:
    instructions: -> route the notification
    actions:
      n: @actions.notify
  on_exit: -> transition to @subagent.s

subagent s:
  description: "second consumer"
  llm: @llm.g
  reasoning:
    instructions: -> also notify
    actions:
      n: @actions.notify
  on_exit: -> transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    const gaps = result.diagnostics.filter(d => d.code === 'action-spec-gap');
    expect(gaps).toHaveLength(1);
    expect(gaps[0].severity).toBe(2);
    expect(gaps[0].message).toContain('actions.notify');
    expect(gaps[0].message).toContain('2 agents');
    expect(gaps[0].message).toContain('orchestrator.o');
    expect(gaps[0].message).toContain('subagent.s');
  });

  it('does not warn when the shared action declares an input contract', () => {
    const source = `
config:
  agent_name: "spec-gap-specified"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  notify:
    target: "a2a://notify_conn"
    kind: "a2a:send_message"
    inputs:
      message: {}

trigger t:
  target: "brokers://spec-gap-specified/a2a"
  on_message: -> transition to @orchestrator.o

orchestrator o:
  description: "first consumer"
  llm: @llm.g
  reasoning:
    instructions: -> route the notification
    actions:
      n: @actions.notify
  on_exit: -> transition to @subagent.s

subagent s:
  description: "second consumer"
  llm: @llm.g
  reasoning:
    instructions: -> also notify
    actions:
      n: @actions.notify
  on_exit: -> transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(result.diagnostics.some(d => d.code === 'action-spec-gap')).toBe(
      false
    );
  });

  it('does not warn when only one agent binds the under-specified action', () => {
    const source = `
config:
  agent_name: "spec-gap-single"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  notify:
    target: "a2a://notify_conn"
    kind: "a2a:send_message"

trigger t:
  target: "brokers://spec-gap-single/a2a"
  on_message: -> transition to @orchestrator.o

orchestrator o:
  description: "sole consumer"
  llm: @llm.g
  reasoning:
    instructions: -> route the notification
    actions:
      n: @actions.notify
  on_exit: -> transition to @subagent.s

subagent s:
  description: "does not bind notify"
  llm: @llm.g
  reasoning:
    instructions: -> handle without the shared action
  on_exit: -> transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(result.diagnostics.some(d => d.code === 'action-spec-gap')).toBe(
      false
    );
  });
});
