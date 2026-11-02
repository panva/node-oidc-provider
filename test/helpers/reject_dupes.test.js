import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import rejectDupes from '../../lib/shared/reject_dupes.js';

function rejection(options, ctx) {
  try {
    rejectDupes(options, ctx, () => {});
  } catch (err) {
    return err;
  }

  throw new Error('expected duplicate parameters to be rejected');
}

describe('rejectDupes helper', () => {
  it('rejects and clears duplicate parameters in their original order', { timeout: 3000 }, () => {
    const ctx = {
      oidc: {
        params: {
          state: ['one', 'two'],
          scope: 'openid',
          nonce: ['one', 'two'],
        },
      },
    };

    ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, "'state' and 'nonce' parameters must not be provided twice"); })(rejection({}, ctx));
    assert.deepEqual(ctx.oidc.params, {
      state: undefined,
      scope: 'openid',
      nonce: undefined,
    });
  });

  it('gives except precedence over only', { timeout: 3000 }, () => {
    const ctx = {
      oidc: {
        params: {
          resource: ['one', 'two'],
          scope: ['one', 'two'],
        },
      },
    };

    ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, "'scope' parameter must not be provided twice"); })(rejection({
      except: new Set(['resource']),
      only: new Set(['resource']),
    }, ctx));
    assert.deepEqual(ctx.oidc.params, {
      resource: ['one', 'two'],
      scope: undefined,
    });
  });

  it('checks only selected parameters', { timeout: 3000 }, () => {
    const ctx = {
      oidc: {
        params: {
          resource: ['one', 'two'],
          scope: ['one', 'two'],
        },
      },
    };

    ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, "'scope' parameter must not be provided twice"); })(rejection({ only: new Set(['scope']) }, ctx));
    assert.deepEqual(ctx.oidc.params, {
      resource: ['one', 'two'],
      scope: undefined,
    });
  });
});
