'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const SteamUser = require('steam-user');

const DATA_DIR = process.env.STEAM_WORKER_DATA_DIR || path.join(__dirname, 'sentry', 'node');
fs.mkdirSync(DATA_DIR, {recursive: true, mode: 0o700});

const ERESULT = SteamUser.EResult || {};
const PERSONA = SteamUser.EPersonaState || {};

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function log(message) {
  process.stderr.write(`${new Date().toISOString()} ${message}\n`);
}

function eresultCode(value, fallback = 2) {
  if (typeof value === 'number') {
    return value;
  }
  if (value && typeof value.eresult === 'number') {
    return value.eresult;
  }
  return fallback;
}

function codeForNeedGuard(type, lastCodeWrong) {
  if (type === 'email') {
    return lastCodeWrong ? 65 : 63;
  }
  return lastCodeWrong ? 88 : 85;
}

function steamId64(client) {
  if (!client.steamID) {
    return null;
  }
  if (typeof client.steamID.getSteamID64 === 'function') {
    return client.steamID.getSteamID64();
  }
  return client.steamID.toString();
}

class SteamWorker {
  constructor() {
    this.client = new SteamUser({
      dataDirectory: DATA_DIR,
      autoRelogin: true,
      renewRefreshTokens: true
    });
    this.loggedIn = false;
    this.refreshToken = null;
    this.pendingLogin = null;
    this.guardCallback = null;
    this.guardType = null;
    this.bindEvents();
  }

  bindEvents() {
    this.client.on('steamGuard', (domain, callback, lastCodeWrong) => {
      const type = domain ? 'email' : '2fa';
      this.guardType = type;

      if (this.pendingLogin && this.pendingLogin.code) {
        const code = this.pendingLogin.code;
        this.pendingLogin.code = null;
        this.pendingLogin.usedCode = true;
        callback(code);
        return;
      }

      this.guardCallback = callback;
      const request = this.pendingLogin;
      this.pendingLogin = null;

      if (request) {
        send({
          id: request.id,
          ok: false,
          need_code: true,
          code_type: type,
          eresult: codeForNeedGuard(type, lastCodeWrong),
          message: lastCodeWrong ? 'Invalid Steam Guard code.' : 'Steam Guard code required.'
        });
      } else {
        send({
          event: 'steam_guard',
          need_code: true,
          code_type: type,
          eresult: codeForNeedGuard(type, lastCodeWrong)
        });
      }
    });

    this.client.on('loggedOn', () => {
      this.loggedIn = true;
      const payload = {
        ok: true,
        eresult: 1,
        steam_id: steamId64(this.client),
        refresh_token: this.refreshToken
      };

      if (this.pendingLogin) {
        payload.id = this.pendingLogin.id;
        this.pendingLogin = null;
        send(payload);
      } else {
        payload.event = 'logged_on';
        send(payload);
      }
    });

    this.client.on('refreshToken', (token) => {
      this.refreshToken = token;
      send({event: 'refresh_token', refresh_token: token});
    });

    this.client.on('disconnected', (eresult, message) => {
      this.loggedIn = false;
      send({
        event: 'disconnected',
        eresult: eresultCode(eresult, 3),
        message: message || 'Disconnected from Steam.'
      });
    });

    this.client.on('error', (error) => {
      const code = eresultCode(error, 2);
      this.loggedIn = false;

      if (this.pendingLogin) {
        send({
          id: this.pendingLogin.id,
          ok: false,
          eresult: code,
          message: error && error.message ? error.message : 'Steam login failed.'
        });
        this.pendingLogin = null;
      } else {
        send({
          event: 'error',
          eresult: code,
          message: error && error.message ? error.message : 'Steam client error.'
        });
      }
    });
  }

  login(command) {
    if (this.guardCallback) {
      if (!command.code) {
        send({
          id: command.id,
          ok: false,
          need_code: true,
          code_type: this.guardType || command.code_type || '2fa',
          eresult: codeForNeedGuard(this.guardType || command.code_type || '2fa', false)
        });
        return;
      }

      this.pendingLogin = {
        id: command.id,
        code: command.code,
        usedCode: false
      };
      const callback = this.guardCallback;
      this.guardCallback = null;
      callback(command.code);
      return;
    }

    if (this.loggedIn) {
      send({
        id: command.id,
        ok: true,
        eresult: 1,
        steam_id: steamId64(this.client),
        refresh_token: this.refreshToken
      });
      return;
    }

    this.pendingLogin = {
      id: command.id,
      code: command.code || null,
      usedCode: false
    };

    const details = {};
    if (command.refresh_token) {
      details.refreshToken = command.refresh_token;
    } else {
      details.accountName = command.username;
      details.password = command.password || '';
      if (command.code) {
        if (command.code_type === 'email') {
          details.authCode = command.code;
        } else {
          details.twoFactorCode = command.code;
        }
      }
    }

    try {
      this.client.logOn(details);
    } catch (error) {
      send({
        id: command.id,
        ok: false,
        eresult: eresultCode(error, 2),
        message: error && error.message ? error.message : 'Steam login failed.'
      });
      this.pendingLogin = null;
    }
  }

  startBoost(command) {
    if (!this.loggedIn) {
      send({id: command.id, ok: false, eresult: 3, message: 'Steam client is not logged in.'});
      return;
    }

    const state = Number(command.persona_state || 1);
    const appIds = Array.isArray(command.app_ids)
      ? command.app_ids.map((appId) => Number(appId)).filter((appId) => Number.isInteger(appId) && appId > 0)
      : [];

    this.client.setPersona(state);
    this.client.gamesPlayed(appIds);
    send({id: command.id, ok: true, eresult: 1});
  }

  gamesPlayed(command) {
    if (!this.loggedIn) {
      send({id: command.id, ok: false, eresult: 3, message: 'Steam client is not logged in.'});
      return;
    }

    const appIds = Array.isArray(command.app_ids)
      ? command.app_ids.map((appId) => Number(appId)).filter((appId) => Number.isInteger(appId) && appId > 0)
      : [];

    this.client.gamesPlayed(appIds);
    send({id: command.id, ok: true, eresult: 1});
  }


  stopBoost(command) {
    try {
      if (this.loggedIn) {
        this.client.gamesPlayed([]);
        this.client.setPersona(PERSONA.Online || 1);
      }
      send({id: command.id, ok: true, eresult: 1});
    } catch (error) {
      send({id: command.id, ok: false, eresult: eresultCode(error, 2), message: error.message});
    }
  }

  setPersona(command) {
    if (!this.loggedIn) {
      send({id: command.id, ok: false, eresult: 3});
      return;
    }
    try {
      this.client.setPersona(Number(command.state || 1));
      send({id: command.id, ok: true, eresult: 1});
    } catch (error) {
      send({id: command.id, ok: false, eresult: eresultCode(error, 2), message: error.message});
    }
  }

  status(command) {
    send({
      id: command.id,
      ok: true,
      eresult: 1,
      logged_in: this.loggedIn,
      steam_id: steamId64(this.client),
      refresh_token: this.refreshToken,
      pending_guard: Boolean(this.guardCallback),
      code_type: this.guardType
    });
  }

  disconnect(command) {
    try {
      if (this.loggedIn || this.guardCallback || this.pendingLogin) {
        this.client.logOff();
      }
    } catch (error) {
      log(`logOff failed: ${error.message}`);
    }
    this.loggedIn = false;
    this.guardCallback = null;
    this.pendingLogin = null;
    send({id: command.id, ok: true, eresult: 1});
  }
}

const worker = new SteamWorker();
const rl = readline.createInterface({input: process.stdin});

rl.on('line', (line) => {
  if (!line.trim()) {
    return;
  }

  let command;
  try {
    command = JSON.parse(line);
  } catch (error) {
    send({ok: false, eresult: 2, message: 'Invalid JSON command.'});
    return;
  }

  try {
    switch (command.action) {
      case 'login':
        worker.login(command);
        break;
      case 'start_boost':
        worker.startBoost(command);
        break;
      case 'games_played':
        worker.gamesPlayed(command);
        break;
      case 'stop_boost':
        worker.stopBoost(command);
        break;
      case 'set_persona':
        worker.setPersona(command);
        break;
      case 'status':
        worker.status(command);
        break;
      case 'disconnect':
        worker.disconnect(command);
        break;
      default:
        send({id: command.id, ok: false, eresult: 2, message: `Unknown action: ${command.action}`});
    }
  } catch (error) {
    send({
      id: command.id,
      ok: false,
      eresult: eresultCode(error, 2),
      message: error && error.message ? error.message : 'Unhandled worker error.'
    });
  }
});

process.on('SIGTERM', () => {
  try {
    worker.client.logOff();
  } catch (_) {
  }
  process.exit(0);
});
