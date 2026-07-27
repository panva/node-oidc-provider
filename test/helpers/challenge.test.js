import { randomBytes } from 'node:crypto';

import { expect } from 'chai';
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
  });

  afterEach(() => {
    clock.restore();
  });

  it('validates its constructor arguments', () => {
    expect(() => new ServerChallenge('not a buffer', 'info')).to.throw(TypeError, /32-byte Buffer/);
    expect(() => new ServerChallenge(randomBytes(31), 'info')).to.throw(TypeError, /32-byte Buffer/);
    expect(() => new ServerChallenge(secret, '')).to.throw(TypeError, /non-empty string/);
    expect(() => new ServerChallenge(secret, 0)).to.throw(TypeError, /non-empty string/);
  });

  it('accepts the challenge it just issued', () => {
    const server = new ServerChallenge(secret, 'info');
    expect(server.checkChallenge(server.nextChallenge())).to.be.true;
  });

  it('derives challenges from the clock, not from process uptime', () => {
    // Instances constructed hours apart must agree. A host that suspends the process between
    // requests (e.g. AWS Lambda) must not desynchronize an instance from its peers.
    const a = new ServerChallenge(secret, 'info');

    at(1_000_000 + 6 * 60 * 60);
    const b = new ServerChallenge(secret, 'info');

    expect(a.nextChallenge()).to.equal(b.nextChallenge());
    expect(a.checkChallenge(b.nextChallenge())).to.be.true;
    expect(b.checkChallenge(a.nextChallenge())).to.be.true;
  });

  it('accepts an issued challenge for the remainder of its window', () => {
    const server = new ServerChallenge(secret, 'info');
    const issued = server.nextChallenge();

    for (const steps of [0, 1, 2, 3]) {
      at(1_000_000 + steps * STEP);
      expect(server.checkChallenge(issued), `step +${steps}`).to.be.true;
    }

    at(1_000_000 + 4 * STEP);
    expect(server.checkChallenge(issued)).to.be.false;
  });

  it('rejects challenges from a different secret or a different info', () => {
    const server = new ServerChallenge(secret, 'DPoP');
    const otherInfo = new ServerChallenge(secret, 'OpenID4VCI c_nonce');
    const otherSecret = new ServerChallenge(randomBytes(32), 'DPoP');

    expect(server.checkChallenge(otherInfo.nextChallenge())).to.be.false;
    expect(server.checkChallenge(otherSecret.nextChallenge())).to.be.false;
  });

  it('rejects malformed values', () => {
    const server = new ServerChallenge(secret, 'info');

    expect(server.checkChallenge('')).to.be.false;
    expect(server.checkChallenge('foo')).to.be.false;
    expect(server.checkChallenge(`${server.nextChallenge()}x`)).to.be.false;
  });

  it('exposes the accepted window', () => {
    expect(CHALLENGE_OK_WINDOW).to.equal(STEP * 5);
  });
});
