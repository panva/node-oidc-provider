import { strict as assert } from 'node:assert';
import { createWriteStream, writeFileSync } from 'node:fs';
import * as stream from 'node:stream';
import { promisify } from 'node:util';

import ms from 'ms';

import debug from './debug.js';

const pipeline = promisify(stream.pipeline);

const FINISHED = new Set(['FINISHED']);
const RESULTS = new Set(['REVIEW', 'PASSED', 'WARNING', 'SKIPPED']);

class API {
  #headers = new Headers({ accept: 'application/json' });

  #baseUrl;

  constructor({ baseUrl, bearerToken } = {}) {
    assert(baseUrl, 'argument property "baseUrl" missing');
    this.#baseUrl = baseUrl;
    if (bearerToken) {
      this.#headers.set('authorization', `bearer ${bearerToken}`);
    }
  }

  async getAllTestModules() {
    const response = await fetch(new URL('api/runner/available', this.#baseUrl), { headers: this.#headers });

    try {
      assert.equal(response.status, 200);
    } catch (err) {
      throw new Error('unexpected response code', { cause: [response.status, await response.text()] });
    }

    return response.json();
  }

  async createTestPlan({ planName, configuration, variant } = {}) {
    assert(planName, 'argument property "planName" missing');
    assert(configuration, 'argument property "configuration" missing');

    const headers = new Headers(this.#headers);
    headers.set('content-type', 'application/json');

    const url = new URL('api/plan', this.#baseUrl);
    url.searchParams.set('planName', planName);
    if (variant) {
      url.searchParams.set('variant', variant);
    }

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(configuration),
    });

    try {
      assert.equal(response.status, 201);
    } catch (err) {
      throw new Error('unexpected response code', { cause: [response.status, await response.text()] });
    }

    return response.json();
  }

  async createTestFromPlan({ plan, test, variant } = {}) {
    assert(plan, 'argument property "plan" missing');
    assert(test, 'argument property "test" missing');

    const url = new URL('api/runner', this.#baseUrl);
    url.searchParams.set('test', test);
    url.searchParams.set('plan', plan);
    url.searchParams.set('variant', JSON.stringify(variant));

    const response = await fetch(url, {
      method: 'POST',
      headers: this.#headers,
    });

    try {
      assert.equal(response.status, 201);
    } catch (err) {
      throw new Error('unexpected response code', { cause: [response.status, await response.text()] });
    }

    return response.json();
  }

  async getModuleInfo({ moduleId } = {}) {
    assert(moduleId, 'argument property "moduleId" missing');

    const response = await fetch(new URL(`api/info/${moduleId}`, this.#baseUrl), { headers: this.#headers });

    try {
      assert.equal(response.status, 200);
    } catch (err) {
      throw new Error('unexpected response code', { cause: [response.status, await response.text()] });
    }

    return response.json();
  }

  async getTestLog({ moduleId } = {}) {
    assert(moduleId, 'argument property "moduleId" missing');

    const response = await fetch(new URL(`api/log/${moduleId}`, this.#baseUrl), { headers: this.#headers });

    try {
      assert.equal(response.status, 200);
    } catch (err) {
      throw new Error('unexpected response code', { cause: [response.status, await response.text()] });
    }

    return response.json();
  }

  async downloadArtifact({ planId } = {}) {
    assert(planId, 'argument property "planId" missing');
    const filename = `export-${planId}.zip`;
    if (process.env.GITHUB_ENV) {
      writeFileSync(process.env.GITHUB_ENV, `EXPORT_FILE=${filename}`, { flag: 'a' });
    }
    if (process.env.GITHUB_STEP_SUMMARY) {
      writeFileSync(process.env.GITHUB_STEP_SUMMARY, `\n\nArtifact: \`${filename}\``, { flag: 'a' });
    }
    const headers = new Headers(this.#headers);
    headers.set('accept', 'application/zip');
    const response = await fetch(new URL(`api/plan/exporthtml/${planId}`, this.#baseUrl), { headers });

    try {
      assert.equal(response.status, 200);
    } catch (err) {
      throw new Error('unexpected response code', { cause: [response.status, await response.text()] });
    }

    return pipeline(
      response.body,
      createWriteStream(filename),
    );
  }

  async waitForState({ moduleId, timeout = ms('4m') } = {}) {
    assert(moduleId, 'argument property "moduleId" missing');
    assert(moduleId, 'argument property "states" missing');
    assert(moduleId, 'argument property "timeout" missing');

    const timeoutAt = Date.now() + timeout;

    while (Date.now() < timeoutAt) {
      const { status, result } = await this.getModuleInfo({ moduleId });
      if (!['WAITING', 'FINISHED', 'RUNNING', 'CREATED'].includes(status)) {
        debug('module id %s status is %s', moduleId, status);
      }
      if (FINISHED.has(status)) {
        if (!status || !result) continue; // eslint-disable-line no-continue
        if (!RESULTS.has(result)) {
          throw new Error(`module id ${moduleId} is ${status} but ${result}`);
        }
        return [status, result];
      }

      if (status === 'INTERRUPTED') {
        debug(await this.getTestLog({ moduleId }));
        throw new Error(`module id ${moduleId} is ${status}`);
      }

      await new Promise((resolve) => { setTimeout(resolve, ms('2s')); });
    }

    debug(`module id ${moduleId} expected state timeout`);
    throw new Error(`Timed out waiting for test module ${moduleId} to be in one of states: ${[...FINISHED].join(', ')}`);
  }
}

export default API;
