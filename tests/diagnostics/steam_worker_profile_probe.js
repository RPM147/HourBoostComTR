'use strict';

/**
 * Deterministic SSH-R3 CM persona IPC probe.
 *
 * The child runs the real steam_worker.js while this file is preloaded to
 * replace steam-user with an in-memory fake. No network request is made.
 *
 *   node tests/diagnostics/steam_worker_profile_probe.js
 */

const assert = require('assert').strict;
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');

const PRELOAD = 'HOURBOOST_R3_PROFILE_PROBE_PRELOAD';
const STEAM_ID = '76561198000000041';
const PASSWORD_SECRET = 'R3_PROFILE_PASSWORD_MUST_NOT_LEAK';

if (process.env[PRELOAD] === '1') {
  const EventEmitter = require('events');
  const Module = require('module');
  const originalLoad = Module._load;

  class FakeSteamUser extends EventEmitter {
    constructor(options) {
      super();
      this.options = options;
      this.steamID = null;
    }

    logOn() {
      this.steamID = {
        getSteamID64() {
          return STEAM_ID;
        }
      };
      process.nextTick(() => this.emit('loggedOn'));
    }

    getPersonas(ids, callback) {
      assert.deepEqual(ids, [STEAM_ID]);
      process.nextTick(() => callback(null, {
        [STEAM_ID]: {
          player_name: 'Synthetic CM Persona',
          avatar_url_full:
            'https://steamcdn-a.akamaihd.net/steamcommunity/public/' +
            'images/avatars/ab/abcdef_full.jpg'
        }
      }));
    }

    setPersona() {}
    gamesPlayed() {}
    logOff() {}
  }

  FakeSteamUser.EResult = {OK: 1};
  FakeSteamUser.EPersonaState = {Online: 1};
  Module._load = function(request, parent, isMain) {
    if (request === 'steam-user') {
      return FakeSteamUser;
    }
    return originalLoad.call(this, request, parent, isMain);
  };
} else {
  const projectRoot = path.resolve(__dirname, '..', '..');
  const workerPath = path.join(projectRoot, 'steam_worker.js');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hourboost-r3-profile-'));
  const child = childProcess.spawn(
    process.execPath,
    ['-r', __filename, workerPath],
    {
      cwd: projectRoot,
      env: {
        ...process.env,
        [PRELOAD]: '1',
        STEAM_WORKER_DATA_DIR: tempDir
      },
      stdio: ['pipe', 'pipe', 'pipe']
    }
  );

  let stderr = '';
  const messages = [];
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString('utf8');
  });
  const lines = readline.createInterface({input: child.stdout});
  lines.on('line', (line) => {
    messages.push(JSON.parse(line));
  });

  function send(command) {
    child.stdin.write(`${JSON.stringify(command)}\n`);
  }

  function waitFor(predicate, timeoutMs = 2000) {
    return new Promise((resolve, reject) => {
      const started = Date.now();
      const timer = setInterval(() => {
        const found = messages.find(predicate);
        if (found) {
          clearInterval(timer);
          resolve(found);
        } else if (Date.now() - started >= timeoutMs) {
          clearInterval(timer);
          reject(new Error(`Timed out waiting for worker message: ${JSON.stringify(messages)}`));
        }
      }, 10);
    });
  }

  (async () => {
    try {
      send({
        id: 'login-1',
        action: 'login',
        username: 'synthetic-user',
        password: PASSWORD_SECRET
      });
      const login = await waitFor((message) => message.id === 'login-1');
      assert.equal(login.ok, true);
      assert.equal(login.steam_id, STEAM_ID);

      send({id: 'profile-1', action: 'get_profile'});
      const profile = await waitFor((message) => message.id === 'profile-1');
      assert.equal(profile.ok, true);
      assert.equal(profile.steam_id, STEAM_ID);
      assert.equal(profile.name, 'Synthetic CM Persona');
      assert.match(profile.avatar, /^https:\/\/steamcdn-a\.akamaihd\.net\//);

      const combinedOutput = `${JSON.stringify(messages)}\n${stderr}`;
      assert.equal(combinedOutput.includes(PASSWORD_SECRET), false);
      process.stdout.write('SSH-R3 Steam worker profile probe: PASS\n');
    } finally {
      child.stdin.end();
      child.kill('SIGTERM');
      fs.rmSync(tempDir, {recursive: true, force: true});
    }
  })().catch((error) => {
    process.stderr.write(`${error.stack || error}\n`);
    child.kill('SIGKILL');
    fs.rmSync(tempDir, {recursive: true, force: true});
    process.exitCode = 1;
  });
}
