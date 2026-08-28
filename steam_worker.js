'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const SteamUser = require('steam-user');

const DATA_DIR = process.env.STEAM_WORKER_DATA_DIR || path.join(__dirname, 'sentry', 'node');
fs.mkdirSync(DATA_DIR, {recursive: true, mode: 0o700});

const ERESULT = SteamUser.EResult || {};
const PERSONA = SteamUser.EPersonaState || {};

const LOGIN_STATE = Object.freeze({
  IDLE: 'idle',
  LOGGING_IN: 'logging_in',
  WAITING_GUARD: 'waiting_guard',
  LOGGED_IN: 'logged_in',
  STOPPING: 'stopping',
  CLOSED: 'closed'
});

// Keep this aligned with steam-user 5.3.0's nonFatalLogOffResults. With
// autoRelogin disabled, the worker reports these to Python so the account
// manager can apply its bounded, generation-fenced reconnect policy.
const TRANSIENT_SESSION_RESULTS = new Set([0, 2, 3, 20, 48]);

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

function isPlausibleSteamClientRefreshToken(token) {
  // steam-user validates refresh-token JWTs inside an async nextTick. A
  // malformed token therefore escapes the caller's try/catch and can terminate
  // the worker. Mirror the non-cryptographic checks needed for a Steam client
  // token before handing it to the library. Steam remains the authority for
  // signature, expiry and revocation validation.
  if (typeof token !== 'string' || token.length === 0 || token.length > 16384) {
    return false;
  }

  const parts = token.split('.');
  if (
    parts.length !== 3 ||
    parts.some((part) => !part || !/^[A-Za-z0-9_-]+$/.test(part))
  ) {
    return false;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64')
        .toString('utf8')
    );
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return false;
    }

    const audiences = Array.isArray(payload.aud)
      ? payload.aud
      : (typeof payload.aud === 'string' ? [payload.aud] : []);
    if (payload.iss !== 'steam' || !audiences.includes('client')) {
      return false;
    }

    // Steam client refresh tokens belong to public individual desktop users.
    // Checking the SteamID bit fields also prevents steam-user's async
    // SteamID constructor from throwing on malformed `sub` claims.
    if (typeof payload.sub !== 'string' || !/^\d{1,20}$/.test(payload.sub)) {
      return false;
    }
    const steamId = BigInt(payload.sub);
    const accountId = steamId & 0xffffffffn;
    const instance = (steamId >> 32n) & 0xfffffn;
    const type = (steamId >> 52n) & 0xfn;
    const universe = steamId >> 56n;
    return universe === 1n && type === 1n && instance === 1n && accountId > 0n;
  } catch (_) {
    return false;
  }
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
      autoRelogin: false,
      renewRefreshTokens: true
    });
    this.loggedIn = false;
    this.refreshToken = null;
    this.pendingLogin = null;
    this.guardCallback = null;
    this.guardType = null;
    this.guardLastCodeWrong = false;
    this.loginState = LOGIN_STATE.IDLE;
    this.loginAttemptSequence = 0;
    this.suppressDisconnectEvents = false;
    this.disconnectPublished = false;
    this.bindEvents();
  }

  requestLabel(request) {
    if (!request || typeof request.id !== 'string') {
      return 'none';
    }
    return request.id.slice(0, 8);
  }

  clearGuardState() {
    this.guardCallback = null;
    this.guardType = null;
    this.guardLastCodeWrong = false;
  }

  resetLoginState(nextState = LOGIN_STATE.IDLE) {
    this.pendingLogin = null;
    this.clearGuardState();
    this.loginState = nextState;
  }

  respondPending(payload) {
    const request = this.pendingLogin;
    this.pendingLogin = null;
    if (!request) {
      return false;
    }
    send({id: request.id, ...payload});
    return true;
  }

  failPending(code, message) {
    const responded = this.respondPending({
      event: 'login_error',
      ok: false,
      eresult: code,
      terminal: !TRANSIENT_SESSION_RESULTS.has(code),
      message
    });
    this.clearGuardState();
    this.loginState = LOGIN_STATE.IDLE;
    return responded;
  }

  publishDisconnected(code, message) {
    if (this.disconnectPublished || this.suppressDisconnectEvents) {
      return;
    }
    this.disconnectPublished = true;
    send({
      event: 'disconnected',
      eresult: code,
      terminal: !TRANSIENT_SESSION_RESULTS.has(code),
      message: message || 'Disconnected from Steam.'
    });
  }

  bindEvents() {
    this.client.on('steamGuard', (domain, callback, lastCodeWrong) => {
      if (
        this.loginState === LOGIN_STATE.STOPPING ||
        this.loginState === LOGIN_STATE.CLOSED ||
        this.suppressDisconnectEvents
      ) {
        return;
      }

      const type = domain ? 'email' : '2fa';
      this.guardType = type;
      this.guardLastCodeWrong = Boolean(lastCodeWrong);
      this.guardCallback = callback;
      const request = this.pendingLogin;
      this.pendingLogin = null;
      this.loginState = LOGIN_STATE.WAITING_GUARD;

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
      if (
        this.loginState === LOGIN_STATE.STOPPING ||
        this.loginState === LOGIN_STATE.CLOSED ||
        this.suppressDisconnectEvents
      ) {
        try {
          this.client.logOff();
        } catch (_) {
        }
        this.loggedIn = false;
        this.resetLoginState(
          this.loginState === LOGIN_STATE.CLOSED
            ? LOGIN_STATE.CLOSED
            : LOGIN_STATE.STOPPING
        );
        return;
      }

      this.loggedIn = true;
      this.loginState = LOGIN_STATE.LOGGED_IN;
      this.disconnectPublished = false;
      this.clearGuardState();
      const payload = {
        event: 'logged_on',
        ok: true,
        eresult: 1,
        steam_id: steamId64(this.client),
        refresh_token: this.refreshToken
      };

      if (this.pendingLogin) {
        payload.id = this.pendingLogin.id;
        this.pendingLogin = null;
      }
      send(payload);
    });

    this.client.on('refreshToken', (token) => {
      this.refreshToken = token;
      send({event: 'refresh_token', refresh_token: token});
    });

    this.client.on('disconnected', (eresult, message) => {
      const previousState = this.loginState;
      const wasLoggedIn = this.loggedIn || previousState === LOGIN_STATE.LOGGED_IN;
      const code = eresultCode(eresult, 3);
      this.loggedIn = false;

      if (
        this.suppressDisconnectEvents ||
        previousState === LOGIN_STATE.STOPPING ||
        previousState === LOGIN_STATE.CLOSED
      ) {
        this.resetLoginState(
          previousState === LOGIN_STATE.CLOSED
            ? LOGIN_STATE.CLOSED
            : LOGIN_STATE.STOPPING
        );
        return;
      }

      const pendingResponded = this.failPending(
        code,
        message || 'Disconnected while logging in to Steam.'
      );
      if (wasLoggedIn) {
        this.publishDisconnected(code, message);
      } else if (!pendingResponded && previousState === LOGIN_STATE.WAITING_GUARD) {
        send({
          event: 'error',
          eresult: code,
          terminal: !TRANSIENT_SESSION_RESULTS.has(code),
          message: message || 'Steam Guard login was disconnected.'
        });
      }
    });

    this.client.on('error', (error) => {
      const code = eresultCode(error, 2);
      const previousState = this.loginState;
      const wasLoggedIn = this.loggedIn || previousState === LOGIN_STATE.LOGGED_IN;
      const message = error && error.message ? error.message : 'Steam client error.';
      this.loggedIn = false;

      if (
        this.suppressDisconnectEvents ||
        previousState === LOGIN_STATE.STOPPING ||
        previousState === LOGIN_STATE.CLOSED
      ) {
        this.resetLoginState(
          previousState === LOGIN_STATE.CLOSED
            ? LOGIN_STATE.CLOSED
            : LOGIN_STATE.STOPPING
        );
        return;
      }

      const pendingResponded = this.failPending(code, message);
      if (wasLoggedIn) {
        this.publishDisconnected(code, message);
      } else if (!pendingResponded) {
        send({
          event: 'error',
          eresult: code,
          terminal: !TRANSIENT_SESSION_RESULTS.has(code),
          message
        });
      }
    });
  }

  login(command) {
    if (this.loginState === LOGIN_STATE.CLOSED) {
      send({
        id: command.id,
        ok: false,
        eresult: 3,
        retryable: false,
        message: 'Steam worker is closed.'
      });
      return;
    }

    if (
      this.loginState === LOGIN_STATE.WAITING_GUARD &&
      this.guardCallback
    ) {
      const requiredType = this.guardType || command.code_type || '2fa';
      if (!command.code) {
        send({
          id: command.id,
          ok: false,
          need_code: true,
          code_type: requiredType,
          eresult: codeForNeedGuard(requiredType, this.guardLastCodeWrong),
          message: this.guardLastCodeWrong
            ? 'Invalid Steam Guard code.'
            : 'Steam Guard code required.'
        });
        return;
      }

      if (command.code_type && command.code_type !== requiredType) {
        send({
          id: command.id,
          ok: false,
          need_code: true,
          code_type: requiredType,
          eresult: codeForNeedGuard(requiredType, this.guardLastCodeWrong),
          message: `Steam Guard ${requiredType} code required.`
        });
        return;
      }

      this.pendingLogin = {
        id: command.id,
        attempt: this.loginAttemptSequence
      };
      const callback = this.guardCallback;
      this.clearGuardState();
      this.loginState = LOGIN_STATE.LOGGING_IN;
      try {
        // A Guard continuation resumes steam-user's existing auth attempt. It
        // must never call client.logOn() here, and the supplied code is never
        // retained for an automatic replay.
        callback(command.code);
      } catch (error) {
        this.failPending(
          eresultCode(error, 2),
          error && error.message ? error.message : 'Steam Guard login failed.'
        );
      }
      return;
    }

    if (this.loggedIn || this.loginState === LOGIN_STATE.LOGGED_IN) {
      send({
        id: command.id,
        ok: true,
        eresult: 1,
        steam_id: steamId64(this.client),
        refresh_token: this.refreshToken
      });
      return;
    }

    if (
      this.loginState === LOGIN_STATE.LOGGING_IN ||
      this.loginState === LOGIN_STATE.STOPPING ||
      this.loginState === LOGIN_STATE.WAITING_GUARD
    ) {
      // A retransmission of the same logical request shares the original
      // eventual response. Sending a second response with the same id would
      // resolve the original Python queue with a false busy result.
      if (this.pendingLogin && this.pendingLogin.id === command.id) {
        return;
      }
      log(
        `login busy: state=${this.loginState} ` +
        `active_request=${this.requestLabel(this.pendingLogin)}`
      );
      send({
        id: command.id,
        ok: false,
        eresult: 20,
        retryable: true,
        login_in_progress: true,
        message: 'Steam login already in progress.'
      });
      return;
    }

    this.loginAttemptSequence += 1;
    this.pendingLogin = {
      id: command.id,
      attempt: this.loginAttemptSequence
    };
    this.loginState = LOGIN_STATE.LOGGING_IN;
    this.suppressDisconnectEvents = false;
    this.disconnectPublished = false;

    if (
      command.refresh_token &&
      !isPlausibleSteamClientRefreshToken(command.refresh_token)
    ) {
      this.failPending(5, 'Stored Steam session token is invalid.');
      return;
    }

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
      this.failPending(
        eresultCode(error, 2),
        error && error.message ? error.message : 'Steam login failed.'
      );
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

  getProfile(command) {
    if (!this.loggedIn) {
      send({id: command.id, ok: false, eresult: 3, message: 'Steam client is not logged in.'});
      return;
    }

    const steamId = steamId64(this.client);
    if (!steamId) {
      send({id: command.id, ok: false, eresult: 2, message: 'SteamID is unavailable.'});
      return;
    }

    try {
      this.client.getPersonas([steamId], (error, personas) => {
        if (error) {
          // Do not pass provider exception details across IPC; this path is
          // presentation-only and Python applies its own cooldown/fallback.
          send({id: command.id, ok: false, eresult: 2, message: 'Steam profile is unavailable.'});
          return;
        }
        const profile = personas && personas[steamId] ? personas[steamId] : {};
        send({
          id: command.id,
          ok: true,
          eresult: 1,
          steam_id: steamId,
          name: typeof profile.player_name === 'string' ? profile.player_name.slice(0, 100) : '',
          avatar: typeof profile.avatar_url_full === 'string' ? profile.avatar_url_full.slice(0, 512) : ''
        });
      });
    } catch (_) {
      send({id: command.id, ok: false, eresult: 2, message: 'Steam profile is unavailable.'});
    }
  }

  status(command) {
    send({
      id: command.id,
      ok: true,
      eresult: 1,
      logged_in: this.loggedIn,
      steam_id: steamId64(this.client),
      pending_guard: Boolean(this.guardCallback),
      code_type: this.guardType,
      login_state: this.loginState,
      login_in_progress: this.loginState === LOGIN_STATE.LOGGING_IN
    });
  }

  disconnect(command) {
    const hadSessionState = Boolean(
      this.loggedIn ||
      this.guardCallback ||
      this.pendingLogin ||
      this.loginState === LOGIN_STATE.LOGGING_IN ||
      this.loginState === LOGIN_STATE.WAITING_GUARD
    );
    this.loginState = LOGIN_STATE.STOPPING;
    this.suppressDisconnectEvents = true;
    this.disconnectPublished = true;
    this.loggedIn = false;
    this.failPending(3, 'Steam login was cancelled.');
    this.clearGuardState();
    this.loginState = LOGIN_STATE.STOPPING;
    try {
      if (hadSessionState) {
        this.client.logOff();
      }
    } catch (error) {
      log(`logOff failed: ${error.message}`);
    }
    // Python terminates the process after this acknowledgement. Staying in
    // STOPPING closes the small ack/terminate window to concurrent logins.
    this.pendingLogin = null;
    this.clearGuardState();
    this.loginState = LOGIN_STATE.STOPPING;
    send({id: command.id, ok: true, eresult: 1});
  }
}

const worker = new SteamWorker();
const rl = readline.createInterface({input: process.stdin});

function shutdown() {
  worker.loginState = LOGIN_STATE.CLOSED;
  worker.suppressDisconnectEvents = true;
  worker.loggedIn = false;
  worker.pendingLogin = null;
  worker.clearGuardState();
  try {
    worker.client.logOff();
  } catch (_) {
  }
  process.exit(0);
}

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
      case 'get_profile':
        worker.getProfile(command);
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

process.stdin.on('end', shutdown);
process.stdin.on('close', shutdown);
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
