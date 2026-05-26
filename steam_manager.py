import os
import time
import json
import logging
import gevent
from steam.client import SteamClient
from steam.enums import EResult
from steam.enums.common import EPersonaState

logger = logging.getLogger(__name__)

TOKEN_DIR = os.path.join(os.path.dirname(__file__), "tokens")
os.makedirs(TOKEN_DIR, exist_ok=True)
if os.name != 'nt':
    try:
        os.chmod(TOKEN_DIR, 0o700)
    except Exception:
        pass

SENTRY_DIR = os.path.join(os.path.dirname(__file__), "sentry")
os.makedirs(SENTRY_DIR, exist_ok=True)
if os.name != 'nt':
    try:
        os.chmod(SENTRY_DIR, 0o700)
    except Exception:
        pass

_FERNET = None


def _get_fernet():
    global _FERNET
    if _FERNET is not None:
        return _FERNET
    try:
        from cryptography.fernet import Fernet
        import base64
        import hashlib

        key_str = os.environ.get("CRED_KEY")
        if key_str:
            key = key_str.encode()
            logger.info("Sifreleme anahtari env den yuklendi")
        else:
            key_path = os.path.join(os.path.dirname(__file__), ".cred_key")
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    key = f.read().strip()
                logger.warning("DIKKAT: Sifreleme anahtari .cred_key dosyasindan okundu. Lutfen bunu CRED_KEY ortam degiskenine tasiyin ve dosyayi silin.")
            else:
                # SECRET_KEY tabanli guvenli bir anahtar uret (Dosyaya yazmadan)
                secret = os.environ.get("SECRET_KEY", "default_insecure_secret").encode()
                derived = hashlib.sha256(b"steam_cred_salt_" + secret).digest()
                key = base64.urlsafe_b64encode(derived)
                logger.info("Sifreleme anahtari SECRET_KEY uzerinden dinamik olarak uretildi")

        _FERNET = Fernet(key)
    except Exception as e:
        logger.error("Fernet baslatma hatasi: %s", e)
        _FERNET = None
    return _FERNET


def encrypt_password(password):
    f = _get_fernet()
    if not f or not password:
        return None
    try:
        return f.encrypt(password.encode()).decode()
    except Exception:
        return None


def decrypt_password(encrypted):
    f = _get_fernet()
    if not f or not encrypted:
        return None
    try:
        return f.decrypt(encrypted.encode()).decode()
    except Exception:
        return None


def _make_client():
    client = SteamClient()
    client.set_credential_location(SENTRY_DIR)
    return client


class SteamAccountManager:
    def __init__(self, account_id, steam_username):
        self.account_id = account_id
        self.steam_username = steam_username
        self.client = _make_client()
        self.logged_in = False
        self.boosting = False
        self.start_time = None
        self.original_start_time = None
        self.app_ids = []
        self.persona_state = 1
        self._reconnect_attempts = 0
        self._setup_events()

    def _cred_path(self):
        safe_name = self.steam_username.replace("/", "_").replace("\\", "_")
        return os.path.join(TOKEN_DIR, f"{self.account_id}_{safe_name}.cred")

    def save_credentials(self, password):
        try:
            enc = encrypt_password(password)
            if not enc:
                logger.warning("[%s] Sifre sifrelenemedi", self.steam_username)
                return False
            data = {
                "password": enc,
                "saved_at": time.time(),
            }
            with open(self._cred_path(), "w") as f:
                json.dump(data, f)
            os.chmod(self._cred_path(), 0o600)
            logger.info("[%s] Kimlik bilgileri kaydedildi", self.steam_username)
            return True
        except Exception as e:
            logger.error("[%s] Kimlik kaydetme hatasi: %s", self.steam_username, e)
            return False

    def load_credentials(self):
        path = self._cred_path()
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r") as f:
                data = json.load(f)
            password = decrypt_password(data.get("password"))
            if not password:
                return None
            return {"password": password}
        except Exception as e:
            logger.error("[%s] Kimlik yukleme hatasi: %s", self.steam_username, e)
            return None

    def delete_credentials(self):
        path = self._cred_path()
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    def has_credentials(self):
        return os.path.exists(self._cred_path())

    def has_token(self):
        return self.has_credentials()

    def _setup_events(self):
        @self.client.on("disconnected")
        def _on_dc():
            logger.warning("[%s] Baglanti koptu", self.steam_username)
            self.logged_in = False
            if self.boosting:
                self._schedule_reconnect()

        @self.client.on("logged_on")
        def _on_login():
            logger.info("[%s] Giris basarili", self.steam_username)
            self.logged_in = True
            self._reconnect_attempts = 0
            if self.boosting:
                self._resume_boost()

        @self.client.on("new_login_key")
        def _on_new_key():
            logger.info("[%s] new_login_key alindi", self.steam_username)

    def _schedule_reconnect(self):
        if self._reconnect_attempts >= 5:
            logger.error("[%s] Max reconnect asildi", self.steam_username)
            if self.boosting:
                elapsed = self.stop_boost()
                if elapsed > 0 and boost_service.fatal_disconnect_callback:
                    boost_service.fatal_disconnect_callback(self.account_id, elapsed)
            return
        delay = min(30 * (2 ** self._reconnect_attempts), 300)
        self._reconnect_attempts += 1
        logger.info("[%s] %dsn sonra reconnect", self.steam_username, delay)
        gevent.spawn_later(delay, self._try_reconnect)

    def _try_reconnect(self):
        try:
            creds = self.load_credentials()
            if creds:
                result = self._login_with_credentials(creds["password"])
                if result == EResult.OK:
                    return
                if result in (
                    EResult.AccountLoginDeniedNeedTwoFactor,
                    EResult.InvalidLoginAuthCode,
                    EResult.TwoFactorCodeMismatch,
                ):
                    logger.warning(
                        "[%s] 2FA gerekiyor, otomatik reconnect yapilamiyor",
                        self.steam_username,
                    )
                    return
            self.client.reconnect(maxdelay=30)
        except Exception as e:
            logger.error("[%s] Reconnect hatasi: %s", self.steam_username, e)
            self._schedule_reconnect()

    def _login_with_credentials(self, password, code=None, code_type="2fa"):
        try:
            if self.client.connected:
                try:
                    self.client.disconnect()
                except Exception:
                    pass
            self.client = _make_client()
            self._setup_events()

            if code:
                if code_type == "2fa":
                    result = self.client.login(
                        username=self.steam_username,
                        password=password,
                        two_factor_code=code,
                    )
                else:
                    result = self.client.login(
                        username=self.steam_username,
                        password=password,
                        auth_code=code,
                    )
            else:
                result = self.client.login(
                    username=self.steam_username,
                    password=password,
                )

            if result == EResult.OK:
                self.logged_in = True
                self._reconnect_attempts = 0
                logger.info(
                    "[%s] Kimlik bilgileriyle giris basarili", self.steam_username
                )
            else:
                logger.warning(
                    "[%s] Kimlik bilgileriyle giris basarisiz: %s",
                    self.steam_username,
                    result,
                )
            return result
        except Exception as e:
            logger.error("[%s] Credential login hatasi: %s", self.steam_username, e)
            return None

    def _resume_boost(self):
        try:
            self.client.change_status(
                persona_state=EPersonaState(self.persona_state)
            )
            self.client.games_played(self.app_ids)
            logger.info("[%s] Boost devam ediyor", self.steam_username)
        except Exception as e:
            logger.error("[%s] Resume hatasi: %s", self.steam_username, e)

    def login(self, password=None, code=None, code_type="email"):
        # Şifre verilmemişse kayıtlı kimlik bilgileriyle dene
        if not password:
            creds = self.load_credentials()
            if creds:
                result = self._login_with_credentials(creds["password"])
                # Gerçek sonucu döndür (2FA dahil) — InvalidPassword ile ezme
                return result
            return EResult.InvalidPassword

        # Yeni bağlantı için client sıfırla
        if self.client.connected:
            try:
                self.client.disconnect()
            except Exception:
                pass
        self.client = _make_client()
        self._setup_events()

        if code:
            if code_type == "2fa":
                result = self.client.login(
                    username=self.steam_username,
                    password=password,
                    two_factor_code=code,
                )
            else:
                result = self.client.login(
                    username=self.steam_username,
                    password=password,
                    auth_code=code,
                )
        else:
            result = self.client.login(
                username=self.steam_username,
                password=password,
            )

        if result == EResult.OK:
            self.logged_in = True
            self._reconnect_attempts = 0
            self.save_credentials(password)

        return result

    def start_boost(self, app_ids, persona_state=1):
        if not self.logged_in:
            raise Exception("Steam bagli degil")
        self.app_ids = app_ids
        self.persona_state = persona_state
        try:
            self.client.change_status(
                persona_state=EPersonaState(persona_state)
            )
        except Exception:
            pass
        self.client.games_played(app_ids)
        self.boosting = True
        self.start_time = time.time()
        self.original_start_time = time.time()

    def stop_boost(self):
        try:
            self.client.games_played([])
        except Exception:
            pass
        self.boosting = False
        elapsed = 0
        if self.start_time:
            elapsed = time.time() - self.start_time
        self.start_time = None
        self.original_start_time = None
        try:
            self.client.change_status(persona_state=EPersonaState.Online)
        except Exception:
            pass
        return elapsed

    def set_persona(self, state):
        self.persona_state = state
        if self.logged_in:
            try:
                self.client.change_status(persona_state=EPersonaState(state))
            except Exception:
                pass

    def disconnect(self):
        self.boosting = False
        self.start_time = None
        self.original_start_time = None
        try:
            self.client.games_played([])
        except Exception:
            pass
        try:
            self.client.disconnect()
        except Exception:
            pass
        self.logged_in = False

    def remove_completely(self):
        self.disconnect()
        self.delete_credentials()

    def summary(self):
        return {
            "id": self.account_id,
            "steam_username": self.steam_username,
            "logged_in": self.logged_in,
            "boosting": self.boosting,
            "start_time": self.original_start_time,
            "app_ids": self.app_ids,
            "persona_state": self.persona_state,
            "has_token": self.has_token(),
        }


class BoostService:
    def __init__(self):
        self._managers = {}
        self.fatal_disconnect_callback = None

    def get(self, account_id):
        return self._managers.get(account_id)

    def get_or_create(self, account_id, steam_username):
        if account_id not in self._managers:
            self._managers[account_id] = SteamAccountManager(
                account_id, steam_username
            )
        return self._managers[account_id]

    def remove(self, account_id):
        mgr = self._managers.pop(account_id, None)
        if mgr:
            mgr.remove_completely()

    def all_managers(self):
        return list(self._managers.items())

    def active_boosts(self):
        return sum(1 for m in self._managers.values() if m.boosting)

    def stats(self):
        return {
            "total": len(self._managers),
            "active_boosts": self.active_boosts(),
            "logged_in": sum(1 for m in self._managers.values() if m.logged_in),
        }


boost_service = BoostService()