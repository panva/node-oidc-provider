import { expect } from 'chai';

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
  it('rejects and clears duplicate parameters in their original order', () => {
    const ctx = {
      oidc: {
        params: {
          state: ['one', 'two'],
          scope: 'openid',
          nonce: ['one', 'two'],
        },
      },
    };

    expect(rejection({}, ctx)).to.have.property(
      'error_description',
      "'state' and 'nonce' parameters must not be provided twice",
    );
    expect(ctx.oidc.params).to.deep.equal({
      state: undefined,
      scope: 'openid',
      nonce: undefined,
    });
  });

  it('gives except precedence over only', () => {
    const ctx = {
      oidc: {
        params: {
          resource: ['one', 'two'],
          scope: ['one', 'two'],
        },
      },
    };

    expect(rejection({
      except: new Set(['resource']),
      only: new Set(['resource']),
    }, ctx)).to.have.property(
      'error_description',
      "'scope' parameter must not be provided twice",
    );
    expect(ctx.oidc.params).to.deep.equal({
      resource: ['one', 'two'],
      scope: undefined,
    });
  });

  it('checks only selected parameters', () => {
    const ctx = {
      oidc: {
        params: {
          resource: ['one', 'two'],
          scope: ['one', 'two'],
        },
      },
    };

    expect(rejection({ only: new Set(['scope']) }, ctx)).to.have.property(
      'error_description',
      "'scope' parameter must not be provided twice",
    );
    expect(ctx.oidc.params).to.deep.equal({
      resource: ['one', 'two'],
      scope: undefined,
    });
  });
});
