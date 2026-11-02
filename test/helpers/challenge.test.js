import { describe, beforeEach, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import sinon from 'sinon';

import ServerChallenge, { CHALLENGE_OK_WINDOW } from '../../lib/helpers/challenge.js';

const STEP = 60;

describe('ServerChallenge', () => {
  const secret = randomBytes(32);
  let clock;

  function at(seconds) {
    clock.returns(seconds * 1000);
  }

  beforeEach(() => {
    clock = sinon.stub(Date, 'now');
    at(1_000_000);
  }, { timeout: 3000 });

  afterEach(() => {
    clock.restore();
  }, { timeout: 3000 });

  it('validates its constructor arguments', { timeout: 3000 }, () => {
    assert.throws(() => new ServerChallenge('not a buffer', 'info'), (error) => { assert.ok(error instanceof TypeError); assert.match(error.message, /32-byte Buffer/); return true; });
    assert.throws(() => new ServerChallenge(randomBytes(31), 'info'), (error) => { assert.ok(error instanceof TypeError); assert.match(error.message, /32-byte Buffer/); return true; });
    assert.throws(() => new ServerChallenge(secret, ''), (error) => { assert.ok(error instanceof TypeError); assert.match(error.message, /non-empty string/); return true; });
    assert.throws(() => new ServerChallenge(secret, 0), (error) => { assert.ok(error instanceof TypeError); assert.match(error.message, /non-empty string/); return true; });
  });

  it('accepts the challenge it just issued', { timeout: 3000 }, () => {
    const server = new ServerChallenge(secret, 'info');
    assert.equal(server.checkChallenge(server.nextChallenge()), true);
  });

  it('derives challenges from the clock, not from process uptime', { timeout: 3000 }, () => {
    // Instances constructed hours apart must agree. A host that suspends the process between
    // requests (e.g. AWS Lambda) must not desynchronize an instance from its peers.
    const a = new ServerChallenge(secret, 'info');

    at(1_000_000 + 6 * 60 * 60);
    const b = new ServerChallenge(secret, 'info');

    assert.equal(a.nextChallenge(), b.nextChallenge());
    assert.equal(a.checkChallenge(b.nextChallenge()), true);
    assert.equal(b.checkChallenge(a.nextChallenge()), true);
  });

  it('accepts an issued challenge for the remainder of its window', { timeout: 3000 }, () => {
    const server = new ServerChallenge(secret, 'info');
    const issued = server.nextChallenge();

    for (const steps of [0, 1, 2, 3]) {
      at(1_000_000 + steps * STEP);
      assert.equal(server.checkChallenge(issued), true, `step +${steps}`);
    }

    at(1_000_000 + 4 * STEP);
    assert.equal(server.checkChallenge(issued), false);
  });

  it('rejects challenges from a different secret or a different info', { timeout: 3000 }, () => {
    const server = new ServerChallenge(secret, 'DPoP');
    const otherInfo = new ServerChallenge(secret, 'OpenID4VCI c_nonce');
    const otherSecret = new ServerChallenge(randomBytes(32), 'DPoP');

    assert.equal(server.checkChallenge(otherInfo.nextChallenge()), false);
    assert.equal(server.checkChallenge(otherSecret.nextChallenge()), false);
  });

  it('rejects malformed values', { timeout: 3000 }, () => {
    const server = new ServerChallenge(secret, 'info');

    assert.equal(server.checkChallenge(''), false);
    assert.equal(server.checkChallenge('foo'), false);
    assert.equal(server.checkChallenge(`${server.nextChallenge()}x`), false);
  });

  it('exposes the accepted window', { timeout: 3000 }, () => {
    assert.equal(CHALLENGE_OK_WINDOW, STEP * 5);
  });
});
