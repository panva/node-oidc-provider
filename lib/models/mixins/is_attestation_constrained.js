import * as jose from 'jose';

export default (superclass) => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'attestationJkt',
    ];
  }

  async setAttestBinding(ctx) {
    const { cnf: { jwk } } = jose.decodeJwt(ctx.get('oauth-client-attestation'));
    this.attestationJkt = await jose.calculateJwkThumbprint(jwk);
  }
};
