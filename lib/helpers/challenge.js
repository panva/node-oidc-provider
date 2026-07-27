import { hkdfSync } from 'node:crypto';

import * as base64url from './base64url.js';
import epochTime from './epoch_time.js';

function sixfourbeify(value) {
  const buf = Buffer.alloc(8);
  for (let i = buf.length - 1; i >= 0; i--) {
    buf[i] = value & 0xff;
    value >>= 8;
  }

  return buf;
}

function compute(secret, info, step) {
  return base64url.encodeBuffer(
    Buffer.from(
      hkdfSync('sha256', secret, sixfourbeify(step), info, 32),
    ),
  );
}

function compare(server, client) {
  let result = 0;

  if (server.length !== client.length) {
    result = 1;
    client = server;
  }

  for (let i = 0; i < server.length; i++) {
    result |= server.charCodeAt(i) ^ client.charCodeAt(i);
  }

  return result;
}

const STEP = 60;
export const CHALLENGE_OK_WINDOW = STEP * 5;

export default class ServerChallenge {
  #info;

  #secret;

  #step;

  #values;

  constructor(secret, info) {
    if (!Buffer.isBuffer(secret) || secret.byteLength !== 32) {
      throw new TypeError('Challenge secret must be a 32-byte Buffer instance');
    }

    if (typeof info !== 'string' || !info.length) {
      throw new TypeError('Challenge info must be a non-empty string');
    }

    this.#info = info;
    this.#secret = Uint8Array.prototype.slice.call(secret);
  }

  // The step is derived from the clock on every read rather than advanced by a timer so that all
  // instances sharing a secret agree regardless of process age, event loop stalls, or hosts that
  // suspend the process between requests (e.g. AWS Lambda).
  #window() {
    const step = Math.floor(epochTime() / STEP);

    if (step !== this.#step) {
      this.#step = step;
      this.#values = [
        step - 2,
        step - 1,
        step,
        step + 1,
        step + 2,
      ].map(compute.bind(undefined, this.#secret, this.#info));
    }

    return this.#values;
  }

  nextChallenge() {
    return this.#window()[3];
  }

  checkChallenge(challenge) {
    let matched = 0;

    for (const server of this.#window()) {
      const result = compare(server, challenge);
      matched |= ((result | -result) >>> 31) ^ 1;
    }

    return matched === 1;
  }
}
