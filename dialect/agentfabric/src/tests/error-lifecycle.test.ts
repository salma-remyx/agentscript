/*
 * Copyright (c) 2026, Salesforce, Inc.
 * All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * For full license text, see the LICENSE file in the repo root or https://www.apache.org/licenses/LICENSE-2.0
 */

import { describe, it, expect } from 'vitest';
import type { Diagnostic } from '@agentscript/language';
import { parseAndLintSource } from './test-utils.js';

describe('error-lifecycle rules', () => {
  function errorLifecycle(diagnostics: Diagnostic[]): Diagnostic[] {
    return diagnostics.filter(
      d => typeof d.code === 'string' && d.code.startsWith('error-lifecycle')
    );
  }

  it('flags a failure status overwritten by a downstream non-failure terminal', () => {
    const source = `
config:
  agent_name: "masked-failure"

trigger t:
  kind: "a2a"
  target: "brokers://masked-failure/a2a"
  on_message: -> transition to @echo.failed

echo failed:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_FAILED"
  message: "boom"
  on_exit: ->
    transition to @echo.done

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    const found = errorLifecycle(result.diagnostics);
    expect(found).toHaveLength(1);
    expect(found[0].code).toBe('error-lifecycle-masked-failure');
    expect(found[0].message).toContain("'failed'");
  });

  it('flags a fallible node with no path to any failure terminal', () => {
    const source = `
config:
  agent_name: "unobservable-error"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  ping:
    target: "mcp://conn"
    kind: "mcp:tool"
    tool_name: "ping"

trigger t:
  kind: "a2a"
  target: "brokers://unobservable-error/a2a"
  on_message: -> transition to @router.r

router r:
  routes:
    - target: @executor.work
      when: True
  otherwise:
    target: @echo.fail

executor work:
  do: ->
    run @actions.ping
  on_exit: -> transition to @echo.done

echo fail:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_FAILED"
  message: "err"

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    const found = errorLifecycle(result.diagnostics);
    expect(found).toHaveLength(1);
    expect(found[0].code).toBe('error-lifecycle-unobservable-error');
    expect(found[0].message).toContain("'work'");
  });

  it('does not flag when a fallible node can reach a failure terminal', () => {
    const source = `
config:
  agent_name: "handled-failure"

llm:
  g:
    target: "llm://openai"
    kind: "OpenAI"
    model: "gpt-4o-mini"

actions:
  ping:
    target: "mcp://conn"
    kind: "mcp:tool"
    tool_name: "ping"

trigger t:
  kind: "a2a"
  target: "brokers://handled-failure/a2a"
  on_message: -> transition to @executor.work

executor work:
  do: ->
    run @actions.ping
  on_exit: -> transition to @router.r

router r:
  routes:
    - target: @echo.done
      when: True
  otherwise:
    target: @echo.fail

echo fail:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_FAILED"
  message: "err"

echo done:
  kind: "a2a:status_update_event"
  state: "TASK_STATE_COMPLETED"
  message: "ok"
`;
    const result = parseAndLintSource(source);
    expect(errorLifecycle(result.diagnostics)).toHaveLength(0);
  });
});
