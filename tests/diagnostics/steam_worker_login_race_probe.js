'use strict';

/**
 * SSH-R1 deterministic acceptance harness for Steam worker login ownership.
 *
 * The worker is executed as a real child process, but this file is preloaded
 * into that child to replace `steam-user` with a controlled EventEmitter fake.
 * No scenario opens a network connection or records credential values.
 *
 *   node tests/diagnostics/steam_worker_login_race_probe.js --expect-fixed
 *
 * The harness intentionally uses only Node.js 14-compatible built-ins.
 */

const assert = require('assert').strict;
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');

const PRELOAD_FLAG = 'HOURBOOST_R1_STEAM_PROBE_PRELOAD';
const STATE_PATH_KEY = 'HOURBOOST_R1_STEAM_PROBE_STATE';
const SCENARIO_KEY = 'HOURBOOST_R1_STEAM_PROBE_SCENARIO';
const WORKER_DATA_KEY = 'STEAM_WORKER_DATA_DIR';
const TEST_TIMEOUT_MS = 2500;
const DUPLICATE_LOGIN_MESSAGE =
  'Already attempting to log on, cannot log on again';

const PASSWORD_SENTINEL = 'R1_PASSWORD_SECRET_7f11';
const SECOND_PASSWORD_SENTINEL = 'R1_PASSWORD_SECRET_82ce';
const EMAIL_CODE_SENTINEL = 'R1_EMAIL_CODE_SECRET_6a42';
const WRONG_2FA_CODE_SENTINEL = 'R1_WRONG_2FA_SECRET_c510';
const CORRECT_2FA_CODE_SENTINEL = 'R1_CORRECT_2FA_SECRET_38bf';
const SECRET_SENTINELS = [
  PASSWORD_SENTINEL,
  SECOND_PASSWORD_SENTINEL,
  EMAIL_CODE_SENTINEL,
  WRONG_2FA_CODE_SENTINEL,
  CORRECT_2FA_CODE_SENTINEL
];

function appendState(event) {
  fs.appendFileSync(
    process.env[STATE_PATH_KEY],
    `${JSON.stringify(event)}\n`,
    {encoding: 'utf8', mode: 0o600}
  );
}

function classifyGuardCode(code) {
  if (code === EMAIL_CODE_SENTINEL) {
    return 'email-correct';
  }
  if (code === WRONG_2FA_CODE_SENTINEL) {
    return '2fa-wrong';
  }
  if (code === CORRECT_2FA_CODE_SENTINEL) {
    return '2fa-correct';
  }
  return 'unknown';
}

function installFakeSteamUser() {
  const EventEmitter = require('events');
  const Module = require('module');
  const originalLoad = Module._load;
  const scenario = process.env[SCENARIO_KEY];

  class FakeSteamUser extends EventEmitter {
    constructor(options) {
      super();
      this.options = options;
      this.steamID = null;
      this.loginPending = false;
      this.loginAttempts = 0;
      appendState({
        event: 'constructor',
        scenario,
        auto_relogin: Boolean(options && options.autoRelogin)
      });
    }

    _emitLoggedOn(delay = 12) {
      setTimeout(() => {
        this.loginPending = false;
        this.steamID = {
          getSteamID64() {
            return '76561198000000001';
          }
        };
        appendState({event: 'emit_logged_on'});
        this.emit('loggedOn');
      }, delay);
    }

    _emitError(code, delay = 12) {
      setTimeout(() => {
        this.loginPending = false;
        const error = new Error('Synthetic Steam login failure.');
        error.eresult = code;
        appendState({event: 'emit_error', eresult: code});
        this.emit('error', error);
      }, delay);
    }

    _emitDisconnected(delay = 12) {
      setTimeout(() => {
        this.loginPending = false;
        appendState({event: 'emit_disconnected', eresult: 3});
        this.emit('disconnected', 3, 'Synthetic disconnect.');
      }, delay);
    }

    _guardCallback(slot) {
      let callCount = 0;
      return (code) => {
        callCount += 1;
        const codeClass = classifyGuardCode(code);
        appendState({
          event: 'guard_callback',
          slot,
          call_count: callCount,
          code_class: codeClass
        });

        if (scenario === 'guard_email' && slot === 'email-initial') {
          if (codeClass === 'email-correct') {
            this._emitLoggedOn();
          }
          return;
        }

        if (scenario === 'guard_2fa' && slot === '2fa-initial') {
          if (codeClass === '2fa-wrong') {
            process.nextTick(() => {
              appendState({event: 'emit_guard', type: '2fa', last_code_wrong: true});
              this.emit(
                'steamGuard',
                null,
                this._guardCallback('2fa-retry'),
                true
              );
            });
          }
          return;
        }

        if (
          scenario === 'guard_2fa' &&
          slot === '2fa-retry' &&
          codeClass === '2fa-correct'
        ) {
          this._emitLoggedOn();
        }
      };
    }

    _emitInitialGuard(type) {
      setTimeout(() => {
        const isEmail = type === 'email';
        appendState({event: 'emit_guard', type, last_code_wrong: false});
        this.emit(
          'steamGuard',
          isEmail ? 'example.invalid' : null,
          this._guardCallback(`${type}-initial`),
          false
        );
      }, 12);
    }

    logOn(details) {
      this.loginAttempts += 1;
      appendState({
        event: 'log_on',
        attempt: this.loginAttempts,
        auth_kind: details && details.refreshToken ? 'refresh_token' : 'password'
      });

      // Match steam-user's important failure shape: a duplicate logOn is not
      // safely catchable by the caller because the failure is raised on the
      // next turn. The fixed worker must never reach this branch.
      if (this.loginPending) {
        appendState({event: 'duplicate_log_on_detected'});
        process.nextTick(() => {
          const error = new Error(DUPLICATE_LOGIN_MESSAGE);
          error.eresult = 2;
          throw error;
        });
        return;
      }

      this.loginPending = true;
      switch (scenario) {
        case 'race_success':
          this._emitLoggedOn(35);
          break;
        case 'error_cleanup':
          if (this.loginAttempts === 1) {
            this._emitError(20);
          } else {
            this._emitLoggedOn();
          }
          break;
        case 'disconnect_cleanup':
          if (this.loginAttempts === 1) {
            this._emitDisconnected();
          } else {
            this._emitLoggedOn();
          }
          break;
        case 'explicit_disconnect':
          // Remain in-flight until the harness sends an explicit disconnect.
          break;
        case 'guard_email':
          this._emitInitialGuard('email');
          break;
        case 'guard_2fa':
          this._emitInitialGuard('2fa');
          break;
        case 'sync_error_cleanup':
          if (this.loginAttempts === 1) {
            this.loginPending = false;
            const error = new Error('Synthetic synchronous login failure.');
            error.eresult = 20;
            throw error;
          }
          this._emitLoggedOn();
          break;
        default:
          throw new Error(`Unknown fake Steam scenario: ${scenario}`);
      }
    }

    logOff() {
      appendState({event: 'log_off'});
      this.loginPending = false;
    }

    gamesPlayed() {}

    setPersona() {}
  }

  FakeSteamUser.EResult = {};
  FakeSteamUser.EPersonaState = {Online: 1};

  Module._load = function loadWithSteamFake(request, parent, isMain) {
    if (request === 'steam-user') {
      return FakeSteamUser;
    }
    return originalLoad.call(this, request, parent, isMain);
  };
}

function parseJsonLines(raw) {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function readState(statePath) {
  if (!fs.existsSync(statePath)) {
    return [];
  }
  return parseJsonLines(fs.readFileSync(statePath, 'utf8'));
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function redacted(value) {
  let output = String(value || '');
  for (const sentinel of SECRET_SENTINELS) {
    output = output.split(sentinel).join('[REDACTED]');
  }
  return output;
}

function launchWorker(scenario) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hourboost-r1-login-'));
  const statePath = path.join(tempDir, 'state.jsonl');
  const workerDataDir = path.join(tempDir, 'worker-data');
  const workerPath = path.resolve(__dirname, '..', '..', 'steam_worker.js');
  const child = childProcess.spawn(
    process.execPath,
    ['--require', __filename, workerPath],
    {
      env: {
        ...process.env,
        [PRELOAD_FLAG]: '1',
        [STATE_PATH_KEY]: statePath,
        [SCENARIO_KEY]: scenario,
        [WORKER_DATA_KEY]: workerDataDir
      },
      stdio: ['pipe', 'pipe', 'pipe']
    }
  );

  const messages = [];
  const parseErrors = [];
  let stdout = '';
  let stderr = '';
  let spawnError = null;
  let closed = false;

  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });

  const lines = readline.createInterface({input: child.stdout});
  lines.on('line', (line) => {
    if (!line.trim()) {
      return;
    }
    try {
      messages.push(JSON.parse(line));
    } catch (error) {
      parseErrors.push({line, message: error.message});
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

  async function waitUntil(reader, predicate, label) {
    const deadline = Date.now() + TEST_TIMEOUT_MS;
    while (Date.now() < deadline) {
      const values = reader();
      const match = values.find(predicate);
      if (match) {
        return match;
      }
      if (closed) {
        throw new Error(`Worker exited while waiting for ${label}.`);
      }
      await delay(5);
    }
    throw new Error(`Timed out waiting for ${label}.`);
  }

  return {
    scenario,
    messages,
    send(command) {
      if (closed || child.stdin.destroyed || child.stdin.writableEnded) {
        throw new Error(`Cannot send ${command.id}: worker is not writable.`);
      }
      child.stdin.write(`${JSON.stringify(command)}\n`);
    },
    waitForMessage(predicate, label) {
      return waitUntil(() => messages, predicate, label);
    },
    waitForState(predicate, label) {
      return waitUntil(() => readState(statePath), predicate, label);
    },
    async finish() {
      if (!closed && !child.stdin.destroyed && !child.stdin.writableEnded) {
        child.stdin.end();
      }
      const killTimer = setTimeout(() => {
        if (!closed) {
          child.kill('SIGKILL');
        }
      }, TEST_TIMEOUT_MS);
      const exit = await closePromise;
      clearTimeout(killTimer);
      const events = readState(statePath);
      fs.rmSync(tempDir, {recursive: true, force: true});
      return {
        scenario,
        messages: messages.slice(),
        events,
        stdout,
        stderr,
        parseErrors: parseErrors.slice(),
        spawnError,
        code: exit.code,
        signal: exit.signal
      };
    }
  };
}

function diagnostic(result) {
  return redacted(JSON.stringify({
    scenario: result.scenario,
    code: result.code,
    signal: result.signal,
    messages: result.messages,
    events: result.events,
    stderr: result.stderr
  }, null, 2));
}

function assertNoCredentialLeak(result) {
  const inspected = [
    result.stdout,
    result.stderr,
    JSON.stringify(result.events)
  ];
  for (const sentinel of SECRET_SENTINELS) {
    for (const output of inspected) {
      assert.ok(
        !output.includes(sentinel),
        `${result.scenario}: credential sentinel leaked into probe output.`
      );
    }
  }
}

function assertHealthyChild(result) {
  assert.equal(
    result.spawnError,
    null,
    `${result.scenario}: child failed to spawn.`
  );
  assert.deepEqual(
    result.parseErrors,
    [],
    `${result.scenario}: worker emitted invalid JSON.`
  );
  assert.equal(
    result.code,
    0,
    `${result.scenario}: child exit was not clean.\n${diagnostic(result)}`
  );
  assert.equal(
    result.signal,
    null,
    `${result.scenario}: child was terminated by a signal.\n${diagnostic(result)}`
  );
  assertNoCredentialLeak(result);
  const constructor = result.events.find((event) => event.event === 'constructor');
  assert.ok(constructor, `${result.scenario}: constructor event missing.`);
  assert.equal(
    constructor.auto_relogin,
    false,
    `${result.scenario}: SteamUser autoRelogin must be disabled.`
  );
}

function eventsOf(result, eventName) {
  return result.events.filter((event) => event.event === eventName);
}

function messagesFor(result, id) {
  return result.messages.filter((message) => message.id === id);
}

async function runScenario(scenario, interaction) {
  const worker = launchWorker(scenario);
  let interactionError = null;
  try {
    await interaction(worker);
  } catch (error) {
    interactionError = error;
  }
  const result = await worker.finish();
  if (interactionError) {
    interactionError.message =
      `${interactionError.message}\n${diagnostic(result)}`;
    throw interactionError;
  }
  assertHealthyChild(result);
  return result;
}

async function testSingleFlightRace() {
  const result = await runScenario('race_success', async (worker) => {
    // Two writes without yielding reproduce the same-tick Python/manual race.
    worker.send({
      id: 'race-first',
      action: 'login',
      username: 'probe-first',
      password: PASSWORD_SENTINEL
    });
    worker.send({
      id: 'race-second',
      action: 'login',
      username: 'probe-second',
      password: SECOND_PASSWORD_SENTINEL
    });

    const busy = await worker.waitForMessage(
      (message) => message.id === 'race-second',
      'single-flight busy response'
    );
    assert.equal(busy.ok, false);
    assert.equal(busy.eresult, 20);
    assert.equal(busy.retryable, true);
    assert.equal(busy.login_in_progress, true);

    const first = await worker.waitForMessage(
      (message) => message.id === 'race-first',
      'original login success'
    );
    assert.equal(first.ok, true);
    assert.equal(first.eresult, 1);

    worker.send({id: 'race-status', action: 'status'});
    const status = await worker.waitForMessage(
      (message) => message.id === 'race-status',
      'post-race worker status'
    );
    assert.equal(status.ok, true);
    assert.equal(status.logged_in, true);
  });

  assert.equal(eventsOf(result, 'log_on').length, 1);
  assert.equal(eventsOf(result, 'duplicate_log_on_detected').length, 0);
  assert.equal(messagesFor(result, 'race-first').length, 1);
  assert.equal(messagesFor(result, 'race-second').length, 1);
  assert.equal(messagesFor(result, 'race-status').length, 1);
  assert.equal(
    result.messages.filter(
      (message) => message.event === 'logged_on' && !message.id
    ).length,
    0,
    'The pending login success must not also create a separate unsolicited event.'
  );
  assert.ok(!result.stderr.includes(DUPLICATE_LOGIN_MESSAGE));
  return result;
}

async function testEmailGuard() {
  const result = await runScenario('guard_email', async (worker) => {
    worker.send({
      id: 'email-initial',
      action: 'login',
      username: 'email-probe',
      password: PASSWORD_SENTINEL
    });
    const required = await worker.waitForMessage(
      (message) => message.id === 'email-initial',
      'email Guard requirement'
    );
    assert.equal(required.ok, false);
    assert.equal(required.need_code, true);
    assert.equal(required.code_type, 'email');
    assert.equal(required.eresult, 63);

    worker.send({
      id: 'email-code',
      action: 'login',
      username: 'email-probe',
      password: PASSWORD_SENTINEL,
      code: EMAIL_CODE_SENTINEL,
      code_type: 'email'
    });
    const accepted = await worker.waitForMessage(
      (message) => message.id === 'email-code',
      'email Guard acceptance'
    );
    assert.equal(accepted.ok, true);
    assert.equal(accepted.eresult, 1);
  });

  assert.equal(eventsOf(result, 'log_on').length, 1);
  const callbacks = eventsOf(result, 'guard_callback');
  assert.equal(callbacks.length, 1);
  assert.equal(callbacks[0].slot, 'email-initial');
  assert.equal(callbacks[0].call_count, 1);
  assert.equal(callbacks[0].code_class, 'email-correct');
  assert.equal(messagesFor(result, 'email-initial').length, 1);
  assert.equal(messagesFor(result, 'email-code').length, 1);
  return result;
}

async function testTwoFactorGuardWrongCode() {
  const result = await runScenario('guard_2fa', async (worker) => {
    worker.send({
      id: '2fa-initial',
      action: 'login',
      username: '2fa-probe',
      password: PASSWORD_SENTINEL
    });
    const required = await worker.waitForMessage(
      (message) => message.id === '2fa-initial',
      '2FA Guard requirement'
    );
    assert.equal(required.ok, false);
    assert.equal(required.need_code, true);
    assert.equal(required.code_type, '2fa');
    assert.equal(required.eresult, 85);

    worker.send({
      id: '2fa-wrong',
      action: 'login',
      username: '2fa-probe',
      password: PASSWORD_SENTINEL,
      code: WRONG_2FA_CODE_SENTINEL,
      code_type: '2fa'
    });
    const wrong = await worker.waitForMessage(
      (message) => message.id === '2fa-wrong',
      '2FA wrong-code response'
    );
    assert.equal(wrong.ok, false);
    assert.equal(wrong.need_code, true);
    assert.equal(wrong.code_type, '2fa');
    assert.equal(wrong.eresult, 88);

    worker.send({
      id: '2fa-correct',
      action: 'login',
      username: '2fa-probe',
      password: PASSWORD_SENTINEL,
      code: CORRECT_2FA_CODE_SENTINEL,
      code_type: '2fa'
    });
    const accepted = await worker.waitForMessage(
      (message) => message.id === '2fa-correct',
      '2FA corrected-code acceptance'
    );
    assert.equal(accepted.ok, true);
    assert.equal(accepted.eresult, 1);
  });

  assert.equal(eventsOf(result, 'log_on').length, 1);
  const callbacks = eventsOf(result, 'guard_callback');
  assert.deepEqual(
    callbacks.map((event) => [event.slot, event.call_count, event.code_class]),
    [
      ['2fa-initial', 1, '2fa-wrong'],
      ['2fa-retry', 1, '2fa-correct']
    ],
    'A consumed wrong Guard code must never be replayed into the replacement callback.'
  );
  assert.equal(messagesFor(result, '2fa-initial').length, 1);
  assert.equal(messagesFor(result, '2fa-wrong').length, 1);
  assert.equal(messagesFor(result, '2fa-correct').length, 1);
  return result;
}

async function testErrorCleanup() {
  const result = await runScenario('error_cleanup', async (worker) => {
    worker.send({
      id: 'error-first',
      action: 'login',
      username: 'error-probe',
      password: PASSWORD_SENTINEL
    });
    const failed = await worker.waitForMessage(
      (message) => message.id === 'error-first',
      'asynchronous login error'
    );
    assert.equal(failed.ok, false);
    assert.equal(failed.eresult, 20);

    worker.send({
      id: 'error-retry',
      action: 'login',
      username: 'error-probe',
      password: SECOND_PASSWORD_SENTINEL
    });
    const accepted = await worker.waitForMessage(
      (message) => message.id === 'error-retry',
      'login after asynchronous error'
    );
    assert.equal(accepted.ok, true);
    assert.equal(accepted.eresult, 1);
  });

  assert.equal(eventsOf(result, 'log_on').length, 2);
  assert.equal(messagesFor(result, 'error-first').length, 1);
  assert.equal(messagesFor(result, 'error-retry').length, 1);
  return result;
}

async function testSynchronousErrorCleanup() {
  const result = await runScenario('sync_error_cleanup', async (worker) => {
    worker.send({
      id: 'sync-first',
      action: 'login',
      username: 'sync-probe',
      password: PASSWORD_SENTINEL
    });
    const failed = await worker.waitForMessage(
      (message) => message.id === 'sync-first',
      'synchronous login error'
    );
    assert.equal(failed.ok, false);
    assert.equal(failed.eresult, 20);

    worker.send({
      id: 'sync-retry',
      action: 'login',
      username: 'sync-probe',
      password: SECOND_PASSWORD_SENTINEL
    });
    const accepted = await worker.waitForMessage(
      (message) => message.id === 'sync-retry',
      'login after synchronous error'
    );
    assert.equal(accepted.ok, true);
    assert.equal(accepted.eresult, 1);
  });

  assert.equal(eventsOf(result, 'log_on').length, 2);
  assert.equal(messagesFor(result, 'sync-first').length, 1);
  assert.equal(messagesFor(result, 'sync-retry').length, 1);
  return result;
}

async function testDisconnectCleanup() {
  const result = await runScenario('disconnect_cleanup', async (worker) => {
    worker.send({
      id: 'disconnect-first',
      action: 'login',
      username: 'disconnect-probe',
      password: PASSWORD_SENTINEL
    });
    const disconnected = await worker.waitForMessage(
      (message) => message.id === 'disconnect-first',
      'pending login disconnect response'
    );
    assert.equal(disconnected.ok, false);
    assert.equal(disconnected.eresult, 3);

    worker.send({
      id: 'disconnect-retry',
      action: 'login',
      username: 'disconnect-probe',
      password: SECOND_PASSWORD_SENTINEL
    });
    const accepted = await worker.waitForMessage(
      (message) => message.id === 'disconnect-retry',
      'login after disconnect cleanup'
    );
    assert.equal(accepted.ok, true);
    assert.equal(accepted.eresult, 1);
  });

  assert.equal(eventsOf(result, 'log_on').length, 2);
  assert.equal(messagesFor(result, 'disconnect-first').length, 1);
  assert.equal(messagesFor(result, 'disconnect-retry').length, 1);
  assert.ok(
    result.messages.filter((message) => message.event === 'disconnected').length <= 1,
    'A single transport disconnect must not publish duplicate events.'
  );
  return result;
}

async function testExplicitDisconnectCleanup() {
  const result = await runScenario('explicit_disconnect', async (worker) => {
    worker.send({
      id: 'held-login',
      action: 'login',
      username: 'held-probe',
      password: PASSWORD_SENTINEL
    });
    await worker.waitForState(
      (event) => event.event === 'log_on',
      'held login reaching fake Steam client'
    );

    worker.send({id: 'explicit-disconnect', action: 'disconnect'});
    const loginFailure = await worker.waitForMessage(
      (message) => message.id === 'held-login',
      'held login cancellation response'
    );
    const disconnected = await worker.waitForMessage(
      (message) => message.id === 'explicit-disconnect',
      'explicit disconnect command response'
    );
    assert.equal(loginFailure.ok, false);
    assert.equal(loginFailure.eresult, 3);
    assert.equal(disconnected.ok, true);
    assert.equal(disconnected.eresult, 1);

    worker.send({id: 'explicit-status', action: 'status'});
    const status = await worker.waitForMessage(
      (message) => message.id === 'explicit-status',
      'worker status after explicit disconnect'
    );
    assert.equal(status.ok, true);
    assert.equal(status.logged_in, false);
    assert.equal(status.login_state, 'stopping');

    worker.send({
      id: 'post-disconnect-login',
      action: 'login',
      username: 'held-probe',
      password: PASSWORD_SENTINEL
    });
    const rejectedLogin = await worker.waitForMessage(
      (message) => message.id === 'post-disconnect-login',
      'login rejection during disconnect/terminate window'
    );
    assert.equal(rejectedLogin.ok, false);
    assert.equal(rejectedLogin.eresult, 20);
    assert.equal(rejectedLogin.login_in_progress, true);
  });

  assert.equal(eventsOf(result, 'log_on').length, 1);
  assert.ok(eventsOf(result, 'log_off').length >= 1);
  assert.equal(messagesFor(result, 'held-login').length, 1);
  assert.equal(messagesFor(result, 'explicit-disconnect').length, 1);
  assert.equal(messagesFor(result, 'explicit-status').length, 1);
  assert.equal(messagesFor(result, 'post-disconnect-login').length, 1);
  return result;
}

async function runProbe() {
  const expectFixed = process.argv.includes('--expect-fixed');
  const tests = [
    ['single_flight_race', testSingleFlightRace],
    ['email_guard', testEmailGuard],
    ['two_factor_guard_wrong_code', testTwoFactorGuardWrongCode],
    ['async_error_cleanup', testErrorCleanup],
    ['sync_error_cleanup', testSynchronousErrorCleanup],
    ['disconnect_cleanup', testDisconnectCleanup],
    ['explicit_disconnect_cleanup', testExplicitDisconnectCleanup]
  ];
  const passed = [];

  for (const [name, test] of tests) {
    await test();
    passed.push(name);
  }

  process.stdout.write(`${JSON.stringify({
    mode: expectFixed ? 'expect-fixed' : 'fixed-regression',
    passed: passed.length,
    scenarios: passed
  }, null, 2)}\n`);
}

if (process.env[PRELOAD_FLAG] === '1') {
  installFakeSteamUser();
} else {
  runProbe().catch((error) => {
    process.stderr.write(`SSH-R1 regression contract failed: ${redacted(error.stack || error.message)}\n`);
    process.exitCode = 1;
  });
}
