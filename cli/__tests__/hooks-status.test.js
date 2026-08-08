import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getHookStatus, HOOK_COMMANDS } from '../commands/hooks.js';

const registered = (command) => [{ hooks: [{ command }] }];

describe('hooks status contract', () => {
  it('reports active when both hooks and scripts are ready', () => {
    const status = getHookStatus({
      hooks: {
        PreToolUse: registered(HOOK_COMMANDS.preToolUse),
        PostToolUse: registered(HOOK_COMMANDS.postToolUse),
      },
    }, { preToolUse: true, postToolUse: true });

    assert.equal(status.schemaVersion, 1);
    assert.equal(status.state, 'active');
    assert.equal(status.protected, true);
  });

  it('reports partial when only one hook is ready', () => {
    const status = getHookStatus({
      hooks: { PreToolUse: registered(HOOK_COMMANDS.preToolUse) },
    }, { preToolUse: true, postToolUse: false });

    assert.equal(status.state, 'partial');
    assert.equal(status.protected, false);
  });

  it('reports inactive when nothing is installed', () => {
    const status = getHookStatus({}, { preToolUse: false, postToolUse: false });

    assert.equal(status.state, 'inactive');
    assert.equal(status.protected, false);
  });

  it('reports invalid settings as unprotected', () => {
    const status = getHookStatus({}, { preToolUse: true, postToolUse: true }, false);

    assert.equal(status.state, 'partial');
    assert.equal(status.protected, false);
    assert.equal(status.settings.valid, false);
  });
});
