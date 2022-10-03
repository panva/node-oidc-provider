/* eslint-disable no-await-in-loop */
const { strict: assert } = require('assert');
const { createWriteStream } = require('fs');
const stream = require('stream');
const { promisify } = require('util');

const Got = require('got');
const ms = require('ms');

const pipeline = promisify(stream.pipeline);

const debug = require('./debug');

const FINISHED = new Set(['FINISHED']);
const RESULTS = new Set(['REVIEW', 'PASSED', 'SKIPPED']);

class API {
  constructor({ baseUrl, bearerToken } = {}) {
    assert(baseUrl, 'argument property "baseUrl" missing');

    const { get, post } = Got.extend({
      prefixUrl: baseUrl,
      throwHttpErrors: false,
      followRedirect: false,
      headers: {
        ...(bearerToken ? { authorization: `bearer ${bearerToken}` } : undefined),
        'content-type': 'application/json',
      },
      responseType: 'json',
      retry: 0,
      timeout: 10000,
    });

    this.get = get;
    this.post = post;

    this.stream = Got.extend({
      prefixUrl: baseUrl,
      throwHttpErrors: false,
      followRedirect: false,
      headers: {
        ...(bearerToken ? { authorization: `bearer ${bearerToken}` } : undefined),
        'content-type': 'application/json',
      },
      retry: 0,
    }).stream;
  }

  async getAllTestModules() {
    const { statusCode, body: response } = await this.get('api/runner/available');

    assert.equal(statusCode, 200);

    return response;
  }

  async createTestPlan({ planName, configuration, variant } = {}) {
    assert(planName, 'argument property "planName" missing');
    assert(configuration, 'argument property "configuration" missing');

    const { statusCode, body: response } = await this.post('api/plan', {
      searchParams: {
        planName,
        ...(variant ? { variant } : undefined),
      },
      json: configuration,
    });

    assert.equal(statusCode, 201);

    return response;
  }

  async createTestFromPlan({ plan, test, variant } = {}) {
    assert(plan, 'argument property "plan" missing');
    assert(test, 'argument property "test" missing');

    const searchParams = { test, plan };

    if (variant) {
      Object.assign(searchParams, { variant: JSON.stringify(variant) });
    }

    const { statusCode, body: response } = await this.post('api/runner', {
      searchParams,
    });

    assert.equal(statusCode, 201);

    return response;
  }

  async getModuleInfo({ moduleId } = {}) {
    assert(moduleId, 'argument property "moduleId" missing');

    const { statusCode, body: response } = await this.get(`api/info/${moduleId}`);

    assert.equal(statusCode, 200);

    return response;
  }

  async getTestLog({ moduleId } = {}) {
    assert(moduleId, 'argument property "moduleId" missing');

    const { statusCode, body: response } = await this.get(`api/log/${moduleId}`);

    assert.equal(statusCode, 200);

    return response;
  }

  async downloadArtifact({ planId } = {}) {
    assert(planId, 'argument property "planId" missing');
    const filename = `export-${planId}.zip`;
    return pipeline(
      this.stream(`api/plan/exporthtml/${planId}`, {
        headers: { accept: 'application/zip' },
        responseType: 'buffer',
      }),
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

      await new Promise((resolve) => setTimeout(resolve, ms('2s')));
    }

    debug(`module id ${moduleId} expected state timeout`);
    throw new Error(`Timed out waiting for test module ${moduleId} to be in one of states: ${[...FINISHED].join(', ')}`);
  }
}

module.exports = API;
