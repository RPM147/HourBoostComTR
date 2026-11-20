'use strict';

/**
 * SSH-R1 real-library regression for malformed stored refresh tokens.
 *
 * This intentionally loads the pinned steam-user dependency (no fake client)
 * while a preloaded network tripwire proves that invalid inputs are rejected
 * before any connection attempt:
 *
 *   node tests/diagnostics/steam_worker_invalid_token_probe.js
 */

const assert = require('assert').strict;
const childProcess = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const readline = require('readline');

const PRELOAD_FLAG = 'HOURBOOST_R1_INVALID_TOKEN_PRELOAD';
const TRIPWIRE_PATH_KEY = 'HOURBOOST_R1_NETWORK_TRIPWIRE_PATH';
const WORKER_DATA_KEY = 'STEAM_WORKER_DATA_DIR';
const RESPONSE_TIMEOUT_MS = 3000;
const COLD_START_TIMEOUT_MS = 10000;

function installNetworkTripwire() {
  const tripwirePath = process.env[TRIPWIRE_PATH_KEY];
  const recordAttempt = () => {
    fs.appendFileSync(tripwirePath, 'network-attempt\n', {mode: 0o600});
    throw new Error('SSH-R1 probe blocked an unexpected network attempt.');
  };

  net.connect = recordAttempt;
  net.createConnection = recordAttempt;
  net.Socket.prototype.connect = recordAttempt;
}

if (process.env[PRELOAD_FLAG] === '1') {
  installNetworkTripwire();
} else {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hourboost-r1-token-'));
  const tripwirePath = path.join(tempDir, 'network-attempts.log');
  const workerPath = path.resolve(__dirname, '..', '..', 'steam_worker.js');
  const workerDataDir = path.join(tempDir, 'worker-data');

  function jwt(payload) {
    const encode = (value) => Buffer.from(JSON.stringify(value), 'utf8')
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    return `${encode({alg: 'none', typ: 'JWT'})}.${encode(payload)}.signature`;
  }

  const invalidTokens = [
    'definitely-not-a-jwt',
    jwt({iss: 'not-steam', sub: '76561198000000001', aud: ['client']}),
    jwt({iss: 'steam', sub: '76561198000000001', aud: ['web']}),
    jwt({iss: 'steam', sub: 'not-a-steamid', aud: ['client']})
  ];

  const child = childProcess.spawn(
    process.execPath,
    ['--require', __filename, workerPath],
    {
      env: {
        ...process.env,
        [PRELOAD_FLAG]: '1',
        [TRIPWIRE_PATH_KEY]: tripwirePath,
        [WORKER_DATA_KEY]: workerDataDir
      },
      stdio: ['pipe', 'pipe', 'pipe']
    }
  );

  const messages = [];
  const parseErrors = [];
  let stderr = '';
  let closed = false;
  let spawnError = null;

  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });
  readline.createInterface({input: child.stdout}).on('line', (line) => {
    if (!line.trim()) {
      return;
    }
    try {
      messages.push(JSON.parse(line));
    } catch (error) {
      parseErrors.push(error.message);
    }
  });
  child.on('error', (error) => {
    spawnError = error;
  });

  const closePromise = new Promise((resolve) => {
    child.on('close', (code, signal) => {
      closed = true;
      resolve({code, signal});
    });
  });

  function send(command) {
    child.stdin.write(`${JSON.stringify(command)}\n`);
  }

  async function waitFor(predicate, label, timeoutMs = RESPONSE_TIMEOUT_MS) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const found = messages.find(predicate);
      if (found) {
        return found;
      }
      if (closed) {
        throw new Error(`Worker exited while waiting for ${label}.`);
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    throw new Error(`Timed out waiting for ${label}.`);
  }

  async function main() {
    try {
      for (let index = 0; index < invalidTokens.length; index += 1) {
        const id = `invalid-token-${index}`;
        send({id, action: 'login', username: 'probe-user', refresh_token: invalidTokens[index]});
        const response = await waitFor(
          (message) => message.id === id,
          id,
          index === 0 ? COLD_START_TIMEOUT_MS : RESPONSE_TIMEOUT_MS
        );
        assert.equal(response.ok, false);
        assert.equal(response.eresult, 5);
        assert.equal(response.terminal, true);
      }

      send({id: 'post-invalid-status', action: 'status'});
      const status = await waitFor(
        (message) => message.id === 'post-invalid-status',
        'post-invalid status'
      );
      assert.equal(status.ok, true);
      assert.equal(status.logged_in, false);
      assert.equal(status.login_state, 'idle');
      assert.equal(fs.existsSync(tripwirePath), false, 'Invalid tokens reached the network layer.');

      child.stdin.end();
      const killTimer = setTimeout(() => child.kill('SIGKILL'), RESPONSE_TIMEOUT_MS);
      const exit = await closePromise;
      clearTimeout(killTimer);

      assert.equal(spawnError, null);
      assert.deepEqual(parseErrors, []);
      assert.equal(exit.code, 0, stderr);
      assert.equal(exit.signal, null);
      assert.ok(!stderr.includes('Invalid JWT'), stderr);
      assert.ok(!stderr.includes('refresh token'), stderr);
      for (const token of invalidTokens) {
        assert.ok(!stderr.includes(token), 'A refresh token leaked to stderr.');
      }
      assert.equal(
        messages.filter((message) => message.id && message.id.startsWith('invalid-token-')).length,
        invalidTokens.length,
        'Each invalid request must receive exactly one response.'
      );

      process.stdout.write('PASS steam-worker invalid refresh-token preflight (4/4)\n');
    } finally {
      if (!closed) {
        child.kill('SIGKILL');
        await closePromise;
      }
      fs.rmSync(tempDir, {recursive: true, force: true});
    }
  }

  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}
