/* eslint-disable no-plusplus, no-bitwise, no-param-reassign */

import { hkdfSync } from 'node:crypto';

import * as base64url from './base64url.js';

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
  #counter;

  #info;

  #secret;

  #prevprev;

  #prev;

  #now;

  #next;

  #nextnext;

  constructor(secret, info) {
    if (!Buffer.isBuffer(secret) || secret.byteLength !== 32) {
      throw new TypeError('Challenge secret must be a 32-byte Buffer instance');
    }

    if (typeof info !== 'string' || !info.length) {
      throw new TypeError('Challenge info must be a non-empty string');
    }

    this.#info = info;
    this.#secret = Uint8Array.prototype.slice.call(secret);
    this.#counter = Math.floor(Date.now() / 1000 / STEP);

    [this.#prevprev, this.#prev, this.#now, this.#next, this.#nextnext] = [
      this.#counter - 2,
      this.#counter - 1,
      this.#counter,
      this.#counter + 1,
      this.#counter++ + 2,
    ].map(compute.bind(undefined, this.#secret, this.#info));

    setInterval(() => {
      [
        this.#prevprev,
        this.#prev,
        this.#now,
        this.#next,
        this.#nextnext,
      ] = [
        this.#prev,
        this.#now,
        this.#next,
        this.#nextnext,
        compute(this.#secret, this.#info, this.#counter++ + 2),
      ];
    }, STEP * 1000).unref();
  }

  nextChallenge() {
    return this.#next;
  }

  checkChallenge(challenge) {
    let result = 0;

    for (const server of [this.#prevprev, this.#prev, this.#now, this.#next, this.#nextnext]) {
      result ^= compare(server, challenge);
    }

    return result === 0;
  }
}
