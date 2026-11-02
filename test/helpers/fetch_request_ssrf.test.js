import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { once } from 'node:events';
import { promisify } from 'node:util';

import { Agent, Dispatcher1Wrapper } from 'undici';

import {
  applySSRFProtection,
  destroySpecialUseSocket,
} from '../../lib/helpers/fetch_request.js';

const execFileAsync = promisify(execFile);
const node = process.execPath;

// Runs a script in a fresh node process with no prior undici import.
// The script must write a single JSON line to stdout.
async function freshNode(script) {
  const { stdout } = await execFileAsync(node, ['--input-type=module', '-e', script]);
  return JSON.parse(stdout);
}

// Wraps a v2 undici Agent so the runtime's v1 fetch() dispatcher contract is
// satisfied on Node 24 (built-in undici 7). On Node 26+ (built-in undici 8)
// the Agent is used as-is.
function createCompatibleAgent() {
  const agent = new Agent();
  const dispatcher = parseInt(process.versions.undici, 10) < 8
    ? new Dispatcher1Wrapper(agent)
    : agent;
  return { agent, dispatcher };
}

function socketTarget(remoteAddress, destroy) {
  const target = {};
  target[Symbol('socket')] = { remoteAddress, destroy };
  return target;
}

function isDestroyed(remoteAddress) {
  let destroyed = false;
  destroySpecialUseSocket(socketTarget(remoteAddress, () => { destroyed = true; }));
  return destroyed;
}

describe('SSRF-protected dispatcher', () => {

  // These guard tests run in fresh subprocesses so no prior undici import
  // contaminates the global state. They verify the exact internals the
  // production code in fetch_request.js relies on.
  describe('undici internals guard (fresh process)', () => {

    it('referencing Response triggers global dispatcher symbol initialization', { timeout: 3000 }, async () => {
      const result = await freshNode(`
        const s1 = Symbol.for('undici.globalDispatcher.1');
        const s2 = Symbol.for('undici.globalDispatcher.2');
        const before = globalThis[s1] ?? globalThis[s2] ?? null;
        Response;
        const after = globalThis[s1] ?? globalThis[s2] ?? null;
        console.log(JSON.stringify({
          beforeNull: before === null,
          afterExists: after !== null,
          hasConstructor: after?.constructor != null,
        }));
      `);
      assert.equal(result.beforeNull, true);
      assert.equal(result.afterExists, true);
      assert.equal(result.hasConstructor, true);
    });

    it('.1 symbol is always set after initialization', { timeout: 3000 }, async () => {
      const result = await freshNode(`
        Response;
        const val = globalThis[Symbol.for('undici.globalDispatcher.1')];
        console.log(JSON.stringify({ exists: val != null }));
      `);
      assert.equal(result.exists, true);
    });

    it('.2 symbol exists on undici >= 8', { timeout: 3000 }, async (t) => {
      if (parseInt(process.versions.undici, 10) < 8) {
        return t.skip();
      }
      const result = await freshNode(`
        Response;
        const val = globalThis[Symbol.for('undici.globalDispatcher.2')];
        console.log(JSON.stringify({ exists: val != null }));
      `);
      assert.equal(result.exists, true);
    });

    it('global dispatcher .constructor produces a usable Agent', { timeout: 3000 }, async () => {
      const result = await freshNode(`
        Response;
        const s2 = Symbol.for('undici.globalDispatcher.2');
        const s1 = Symbol.for('undici.globalDispatcher.1');
        const Agent = (globalThis[s2] ?? globalThis[s1]).constructor;
        const agent = new Agent();
        console.log(JSON.stringify({
          hasOn: typeof agent.on === 'function',
          hasClose: typeof agent.close === 'function',
        }));
        agent.close();
      `);
      assert.equal(result.hasOn, true);
      assert.equal(result.hasClose, true);
    });

    it('targets has at least 3 elements and the last target has Symbol(socket) with remoteAddress', { timeout: 3000 }, async () => {
      const result = await freshNode(`
        import { createServer } from 'node:http';
        import { once } from 'node:events';
        Response;
        const s2 = Symbol.for('undici.globalDispatcher.2');
        const s1 = Symbol.for('undici.globalDispatcher.1');
        const Agent = (globalThis[s2] ?? globalThis[s1]).constructor;
        const agent = new Agent();
        const server = createServer((req, res) => { res.writeHead(200); res.end('ok'); });
        server.listen(0, '127.0.0.1');
        await once(server, 'listening');
        const port = server.address().port;
        const result = {};
        agent.on('connect', (_origin, targets) => {
          result.targetsLength = targets.length;
          const client = targets[targets.length - 1];
          const socketSym = Object.getOwnPropertySymbols(client)
            .find((s) => s.description === 'socket');
          result.hasSocketSym = socketSym != null;
          if (socketSym) {
            result.remoteAddress = client[socketSym]?.remoteAddress;
          }
        });
        const res = await fetch('http://127.0.0.1:' + port + '/', { dispatcher: agent });
        await res.text();
        console.log(JSON.stringify(result));
        agent.close();
        server.close();
      `);
      assert.equal(typeof result.targetsLength, 'number');
      assert.ok(result.targetsLength >= 3);
      assert.equal(result.hasSocketSym, true);
      assert.equal(result.remoteAddress, '127.0.0.1');
    });
  });

  describe('blocks special-use IPs', () => {

    let server;
    let port;

    before(async () => {
      server = createServer((_req, res) => {
        res.writeHead(200);
        res.end('should not reach here');
      });
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      port = server.address().port;
    }, { timeout: 3000 });

    after(() => server.close(), { timeout: 3000 });

    it('rejects fetch to 127.0.0.1 (loopback)', { timeout: 3000 }, async () => {
      const { agent, dispatcher } = createCompatibleAgent();
      applySSRFProtection(agent);
      try {
        await fetch(`http://127.0.0.1:${port}/`, { dispatcher });
        expect.fail('should have thrown');
      } catch (e) {
        assert.ok(e instanceof TypeError);
        assert.equal(e.cause?.message, 'hostname resolves to a special-use IP address');
      }
      agent.close();
    });

    it('rejects fetch to [::1] (IPv6 loopback)', { timeout: 3000 }, async (t) => {
      const v6server = createServer((_req, res) => {
        res.writeHead(200);
        res.end('should not reach here');
      });
      try {
        v6server.listen(0, '::1');
        await once(v6server, 'listening');
      } catch {
        v6server.close();
        return t.skip();
      }

      const v6port = v6server.address().port;
      const { agent, dispatcher } = createCompatibleAgent();
      applySSRFProtection(agent);
      try {
        await fetch(`http://[::1]:${v6port}/`, { dispatcher });
        expect.fail('should have thrown');
      } catch (e) {
        assert.ok(e instanceof TypeError);
        assert.equal(e.cause?.message, 'hostname resolves to a special-use IP address');
      }
      agent.close();
      v6server.close();
    });

    it('blocks repeatedly (persistent on listener, not once)', { timeout: 3000 }, async () => {
      const { agent, dispatcher } = createCompatibleAgent();
      applySSRFProtection(agent);
      const errors = [];

      for (let i = 0; i < 3; i += 1) {
        try {
          await fetch(`http://127.0.0.1:${port}/`, { dispatcher });
          expect.fail('should have thrown');
        } catch (e) {
          errors.push(e);
        }
      }

      assert.equal(errors.length, 3);
      for (const e of errors) {
        assert.equal(e.cause?.message, 'hostname resolves to a special-use IP address');
      }
      agent.close();
    });
  });

  describe('handler logic (simulated targets)', () => {
    it('does not destroy socket for public IPv4', { timeout: 3000 }, () => {
      assert.equal(isDestroyed('93.184.216.34'), false);
    });

    it('destroys socket for private IPv4 (10.x)', { timeout: 3000 }, () => {
      let destroyMsg;
      destroySpecialUseSocket(socketTarget('10.0.0.1', (err) => { destroyMsg = err.message; }));
      assert.equal(destroyMsg, 'hostname resolves to a special-use IP address');
    });

    it('destroys socket for link-local 169.254.169.254 (cloud metadata)', { timeout: 3000 }, () => {
      assert.equal(isDestroyed('169.254.169.254'), true);
    });

    it('destroys socket for IPv4-mapped IPv6 private address', { timeout: 3000 }, () => {
      assert.equal(isDestroyed('::ffff:192.168.1.1'), true);
    });

    it('does not destroy socket for IPv4-mapped IPv6 public address', { timeout: 3000 }, () => {
      assert.equal(isDestroyed('::ffff:8.8.8.8'), false);
    });

    it('skips targets without symbol properties', { timeout: 3000 }, () => {
      const targets = [{}, { foo: 'bar' }, Object.create(null)];
      assert.doesNotThrow(() => {
        for (const target of targets) destroySpecialUseSocket(target);
      });
    });

    it('skips symbol properties that are not sockets', { timeout: 3000 }, () => {
      const target = {};
      target[Symbol('notSocket')] = { foo: 'bar' };
      target[Symbol('number')] = 42;
      target[Symbol('null')] = null;

      assert.equal(destroySpecialUseSocket(target), false);
    });
  });
});
