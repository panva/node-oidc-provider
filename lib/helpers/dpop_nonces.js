import ServerChallenge, { CHALLENGE_OK_WINDOW } from './challenge.js';

export { CHALLENGE_OK_WINDOW as DPOP_OK_WINDOW };

export default class DPoPNonces extends ServerChallenge {
  constructor(secret) {
    if (!Buffer.isBuffer(secret) || secret.byteLength !== 32) {
      throw new TypeError('features.dPoP.nonceSecret must be a 32-byte Buffer instance');
    }

    super(secret, 'DPoP');
  }

  nextNonce() {
    return super.nextChallenge();
  }

  checkNonce(nonce) {
    return super.checkChallenge(nonce);
  }
}
