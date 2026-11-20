"""Destructive schema fixtures restricted to explicit temporary test databases.

Production has no schema repair path. The frozen legacy bridge below exists
only to preserve historical migration regression tests and is never imported
by application code. New fixtures bootstrap the standalone migration HEAD.
"""

from pathlib import Path
import tempfile

from runtime_guardrails import runtime_sqlite_path
from schema_tools import _bootstrap_connection, bootstrap_disposable


def _test_path(value, *, existing):
    """Allow only canonical files inside a direct hourboost-* temp directory."""
    try:
        root = Path(tempfile.gettempdir()).resolve(strict=True)
        path = Path(value)
        if not path.is_absolute() or path != path.resolve(strict=existing):
            raise ValueError
        relative = path.relative_to(root)
        if len(relative.parts) != 2 or not relative.parts[0].startswith("hourboost-"):
            raise ValueError
        if not path.parent.is_dir():
            raise ValueError
        for component in (path, *path.parents):
            if component.is_symlink() or (
                hasattr(component, "is_junction") and component.is_junction()
            ):
                raise ValueError
        if existing:
            runtime_sqlite_path("sqlite:///" + path.as_posix())
        elif path.exists():
            raise ValueError
    except Exception:
        raise RuntimeError("Schema fixtures require an isolated canonical temp DB.") from None
    return path


def initialize_test_database(value):
    """Create one explicitly named disposable file before importing the app."""
    path = _test_path(value, existing=False)
    result = bootstrap_disposable(str(path))
    if not result.get("ok"):
        raise RuntimeError("Disposable test schema bootstrap failed.")
    return path


def _guard_test_app(app_module):
    if app_module.app.config.get("TESTING") is not True:
        raise RuntimeError("Destructive schema fixtures require TESTING=True.")
    path = runtime_sqlite_path(app_module.app.config["SQLALCHEMY_DATABASE_URI"])
    path = _test_path(path, existing=True)
    engine = app_module.db.engine
    if engine.dialect.name != "sqlite" or Path(engine.url.database or "") != path:
        raise RuntimeError("Schema fixture engine does not match its isolated DB.")
    return path


def _guard_connection(connection, path):
    databases = connection.exec_driver_sql("PRAGMA database_list").fetchall()
    main = next((row[2] for row in databases if row[1] == "main"), None)
    if main is None or _test_path(main, existing=True) != path:
        raise RuntimeError("Schema fixture connection points outside its isolated DB.")


def reset_test_schema(app_module):
    """Reset only test data/schema, preserving the runtime creator's DB inode."""
    path = _guard_test_app(app_module)
    db = app_module.db
    db.session.remove()
    with db.engine.connect() as connection:
        _guard_connection(connection, path)
        # PRAGMA inspection autobegins SQLAlchemy state, not a SQLite write
        # transaction. Close it before the explicit transactional DDL boundary.
        connection.rollback()
        connection.exec_driver_sql("BEGIN")
        try:
            db.metadata.drop_all(bind=connection)
            connection.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
            _bootstrap_connection(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    db.session.remove()


def repair_legacy_fixture(app_module):
    """Exercise the retired historical bridge on an isolated TESTING DB only."""
    path = _guard_test_app(app_module)
    with app_module.db.engine.connect() as connection:
        _guard_connection(connection, path)
    db = app_module.db
    Config = app_module.Config
    logger = app_module.logger
    valid_steam_id = app_module.valid_steam_id
    storage_utc = app_module.storage_utc
    UTC_EPOCH = app_module.UTC_EPOCH
    utc_now = app_module.utc_now
    migrate_boost_log_history = app_module.migrate_boost_log_history
    migrate_boost_duration_ledger = app_module.migrate_boost_duration_ledger
    _new_match_token = app_module._new_match_token
    re = app_module.re
    try:
        from sqlalchemy import inspect, text

        inspector = inspect(db.engine)
        dialect = db.engine.dialect.name
        false_literal = "FALSE" if dialect == "postgresql" else "0"
        true_literal = "TRUE" if dialect == "postgresql" else "1"
        cols = {c["name"] for c in inspector.get_columns("users")}
        if "tokens_valid_after" not in cols:
            col_type = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
            with db.engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN tokens_valid_after {col_type}"))
            logger.info("Şema güncellendi: users.tokens_valid_after eklendi")

        if "plan_activated_at" not in cols:
            col_type = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
            with db.engine.begin() as conn:
                conn.execute(text(
                    f"ALTER TABLE users ADD COLUMN plan_activated_at {col_type}"
                ))
            logger.info("Şema güncellendi: users.plan_activated_at eklendi")

        # Legacy login branches could persist the literal string "None" when
        # a worker reported success before exposing its SteamID. Such values
        # must not shadow a later valid CM identity.
        with db.engine.begin() as conn:
            steam_id_rows = conn.execute(text(
                "SELECT id, steam_id FROM steam_accounts "
                "WHERE steam_id IS NOT NULL"
            )).mappings().all()
            invalid_steam_account_ids = [
                row["id"]
                for row in steam_id_rows
                if valid_steam_id(row["steam_id"]) is None
            ]
            for account_id in invalid_steam_account_ids:
                conn.execute(text(
                    "UPDATE steam_accounts SET steam_id = NULL WHERE id = :id"
                ), {"id": account_id})
        if invalid_steam_account_ids:
            logger.warning(
                "steam_profile.invalid_persisted_ids_cleared count=%d",
                len(invalid_steam_account_ids),
            )

        # Legacy paid users must not receive a fresh quota merely because the
        # activation timestamp did not exist in their original schema. The
        # conservative fallback matches quota accounting: count from account
        # creation, or the Unix epoch for malformed legacy rows. Free users
        # intentionally remain NULL; a later paid activation opens a new usage
        # window explicitly.
        paid_plan_names = tuple(
            name
            for name, limits in Config.PLANS.items()
            if name != "free" and limits.get("total_hours") is not None
        )
        if paid_plan_names:
            plan_params = {
                f"paid_plan_{index}": name
                for index, name in enumerate(paid_plan_names)
            }
            plan_placeholders = ", ".join(
                f":{key}" for key in plan_params
            )
            with db.engine.begin() as conn:
                backfilled = conn.execute(text(
                    "UPDATE users SET plan_activated_at = "
                    "COALESCE(created_at, :legacy_plan_epoch) "
                    "WHERE plan_activated_at IS NULL "
                    f"AND plan IN ({plan_placeholders})"
                ), {
                    **plan_params,
                    "legacy_plan_epoch": storage_utc(UTC_EPOCH),
                })
            if backfilled.rowcount:
                logger.warning(
                    "Legacy plan quota window backfilled: %d users",
                    backfilled.rowcount,
                )

        boost_log_cols = {
            c["name"] for c in inspect(db.engine).get_columns("boost_logs")
        }
        if "remote_stopped_at" not in boost_log_cols:
            boost_datetime_type = (
                "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
            )
            with db.engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE boost_logs ADD COLUMN remote_stopped_at "
                    + boost_datetime_type
                ))
            logger.info(
                "Sema guncellendi: boost_logs.remote_stopped_at eklendi"
            )

        boost_history_report = migrate_boost_log_history(db.engine)
        logger.info(
            "phase5f.boost_log_migration rows=%s duration_seconds=%s "
            "added_columns=%s account_snapshots=%s steam_usernames=%s "
            "owner_ids=%s owner_usernames=%s detached_accounts=%s "
            "detached_users=%s unknown_accounts=%s unknown_usernames=%s "
            "fk_violations=%s",
            boost_history_report["rows"],
            boost_history_report["duration_seconds"],
            boost_history_report["added_columns"],
            boost_history_report["account_snapshot_backfilled"],
            boost_history_report["steam_username_backfilled"],
            boost_history_report["owner_id_backfilled"],
            boost_history_report["owner_username_backfilled"],
            boost_history_report["orphan_accounts_detached"],
            boost_history_report["orphan_users_detached"],
            boost_history_report["unknown_account_snapshots"],
            boost_history_report["unknown_steam_usernames"],
            boost_history_report["foreign_key_violations"],
        )

        duration_ledger_report = migrate_boost_duration_ledger(db.engine)
        logger.info(
            "phase5g2.duration_ledger rows=%s duration_seconds=%s "
            "duration_microseconds=%s added_columns=%s backfilled_rows=%s "
            "enforcement_added=%s",
            duration_ledger_report["rows"],
            duration_ledger_report["duration_seconds"],
            duration_ledger_report["duration_microseconds"],
            duration_ledger_report["added_columns"],
            duration_ledger_report["backfilled_rows"],
            duration_ledger_report["enforcement_added"],
        )

        session_cols = {
            c["name"] for c in inspector.get_columns("user_sessions")
        }
        with db.engine.begin() as conn:
            if "token_jti" not in session_cols:
                conn.execute(text(
                    "ALTER TABLE user_sessions ADD COLUMN token_jti VARCHAR(64)"
                ))
                logger.info("Şema güncellendi: user_sessions.token_jti eklendi")
            if "expires_at" not in session_cols:
                session_datetime_type = (
                    "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
                )
                conn.execute(text(
                    "ALTER TABLE user_sessions ADD COLUMN expires_at "
                    + session_datetime_type
                ))
                logger.info("Şema güncellendi: user_sessions.expires_at eklendi")

        session_indexes = {
            item["name"]: item
            for item in inspect(db.engine).get_indexes("user_sessions")
        }
        jti_index = session_indexes.get("ix_user_sessions_token_jti")
        if jti_index is not None and not jti_index.get("unique", False):
            raise RuntimeError(
                "ix_user_sessions_token_jti exists but is not unique"
            )
        if jti_index is None:
            with db.engine.begin() as conn:
                conn.execute(text(
                    "CREATE UNIQUE INDEX ix_user_sessions_token_jti "
                    "ON user_sessions (token_jti)"
                ))
            logger.info(
                "Şema güncellendi: ix_user_sessions_token_jti oluşturuldu"
            )

        # Eski token_hint değerlerinden JWT jti geri üretilemez. Kullanıcı
        # cutoff'u eski kodun da bu JWT'leri reddetmesini sağlar; ardından satır
        # kapatılır. Böylece auth migration sonrası güvenli kod rollback'i
        # iptal edilmiş legacy oturumları yeniden canlandırmaz.
        legacy_cutoff = storage_utc(utc_now())
        with db.engine.begin() as conn:
            conn.execute(text(
                "UPDATE users SET tokens_valid_after = :cutoff "
                "WHERE id IN ("
                "SELECT DISTINCT user_id FROM user_sessions "
                "WHERE is_active = " + true_literal + " "
                "AND (token_jti IS NULL OR expires_at IS NULL)"
                ") AND (tokens_valid_after IS NULL OR tokens_valid_after < :cutoff)"
            ), {"cutoff": legacy_cutoff})
            legacy_sessions = conn.execute(text(
                "UPDATE user_sessions SET is_active = " + false_literal + " "
                "WHERE is_active = " + true_literal + " "
                "AND (token_jti IS NULL OR expires_at IS NULL)"
            ))
        if legacy_sessions.rowcount:
            logger.warning(
                "Güvenli oturum migration'ı: %d legacy oturum kapatıldı",
                legacy_sessions.rowcount,
            )

        datetime_type = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
        pcols = {c["name"] for c in inspector.get_columns("payments")}
        payment_columns = {
            "owner_user_id_snapshot": "INTEGER",
            "owner_username_snapshot": "VARCHAR(80)",
            "owner_detached_at": datetime_type,
            "match_token": "VARCHAR(64)",
            "admin_hidden": f"BOOLEAN NOT NULL DEFAULT {false_literal}",
            "shopier_webhook_id": "VARCHAR(100)",
            "shopier_event": "VARCHAR(50)",
            "shopier_account_id": "VARCHAR(100)",
            "shopier_timestamp": "BIGINT",
            "webhook_body_sha256": "VARCHAR(64)",
            "webhook_received_at": datetime_type,
            "verification_attempts": "INTEGER NOT NULL DEFAULT 0",
            "verification_error": "VARCHAR(255)",
            "verification_last_http_status": "INTEGER",
            "next_verification_at": datetime_type,
            "verification_lock_until": datetime_type,
            "verified_at": datetime_type,
            "verified_amount_minor": "INTEGER",
        }
        with db.engine.begin() as conn:
            for column_name, column_type in payment_columns.items():
                if column_name not in pcols:
                    conn.execute(text(
                        f"ALTER TABLE payments ADD COLUMN {column_name} {column_type}"
                    ))
                    logger.info("Şema güncellendi: payments.%s eklendi", column_name)

        # Backfill durable ownership hints before any future user deletion.
        # The live FK is intentionally cleared on deletion, while these fields
        # keep the financial row attributable without relying on a reusable
        # SQLite integer ID alone.
        with db.engine.begin() as conn:
            conn.execute(text(
                "UPDATE payments SET owner_user_id_snapshot = user_id "
                "WHERE owner_user_id_snapshot IS NULL AND user_id IS NOT NULL"
            ))
            conn.execute(text(
                "UPDATE payments SET owner_username_snapshot = ("
                "SELECT users.username FROM users WHERE users.id = payments.user_id"
                ") WHERE owner_username_snapshot IS NULL AND user_id IS NOT NULL"
            ))

        if dialect == "postgresql":
            with db.engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE payments ALTER COLUMN match_token TYPE VARCHAR(64)"
                ))
                conn.execute(text(
                    "ALTER TABLE payments ALTER COLUMN status TYPE VARCHAR(32)"
                ))

        # Eski sürümde yalnızca checkout butonuna basmak status=pending üretiyordu.
        # match_token içeren ve henüz işlem görmemiş bu kayıtlar ödeme değil,
        # checkout niyetidir; idempotent biçimde admin kuyruğundan çıkarılır.
        with db.engine.begin() as conn:
            rows = conn.execute(text(
                "SELECT id, match_token, status FROM payments "
                "WHERE match_token IS NOT NULL ORDER BY id"
            )).mappings().all()
            used_tokens = set()
            for row in rows:
                token = str(row["match_token"] or "").strip().upper()
                if not token:
                    conn.execute(
                        text("UPDATE payments SET match_token = NULL WHERE id = :id"),
                        {"id": row["id"]},
                    )
                    continue
                status = row["status"]
                is_checkout_intent = status in ("checkout_started", "pending")
                needs_new_active_token = (
                    is_checkout_intent
                    and not re.fullmatch(r"HB-[0-9A-F]{32}", token)
                )
                duplicate = token in used_tokens

                if status == "verification_pending" and (
                    not re.fullmatch(r"HB-[0-9A-F]{32}", token) or duplicate
                ):
                    raise RuntimeError(
                        "verification_pending kaydında geçersiz/duplicate HB token bulundu"
                    )

                if is_checkout_intent and (needs_new_active_token or duplicate):
                    new_token = _new_match_token()
                    while new_token in used_tokens:
                        new_token = _new_match_token()
                    conn.execute(
                        text("UPDATE payments SET match_token = :token WHERE id = :id"),
                        {"token": new_token, "id": row["id"]},
                    )
                    used_tokens.add(new_token)
                elif duplicate:
                    conn.execute(
                        text("UPDATE payments SET match_token = NULL WHERE id = :id"),
                        {"id": row["id"]},
                    )
                else:
                    if token != row["match_token"]:
                        conn.execute(
                            text("UPDATE payments SET match_token = :token WHERE id = :id"),
                            {"token": token, "id": row["id"]},
                        )
                    used_tokens.add(token)

        with db.engine.begin() as conn:
            migrated = conn.execute(text(
                "UPDATE payments SET status = 'checkout_started' "
                "WHERE status = 'pending' "
                "AND match_token IS NOT NULL "
                "AND transaction_id IS NULL"
            ))
        if migrated.rowcount:
            logger.info(
                "Şema veri düzeltmesi: %d checkout kaydı checkout_started yapıldı",
                migrated.rowcount,
            )

        # Tek kullanıcı için yalnızca bir açık checkout/payment verification
        # bulunabilir. Eski checkout duplikelerinde en yeni kayıt korunur;
        # birden fazla verification_pending varsa güvenli otomatik karar yoktur.
        with db.engine.begin() as conn:
            open_rows = conn.execute(text(
                "SELECT id, user_id, status FROM payments "
                "WHERE user_id IS NOT NULL "
                "AND status IN ('checkout_started', 'verification_pending') "
                "ORDER BY user_id, id DESC"
            )).mappings().all()
            by_user = {}
            for row in open_rows:
                by_user.setdefault(row["user_id"], []).append(row)
            for user_id, rows in by_user.items():
                pending = [r for r in rows if r["status"] == "verification_pending"]
                if len(pending) > 1:
                    raise RuntimeError(
                        f"user_id={user_id} için birden fazla verification_pending bulundu"
                    )
                keep_id = pending[0]["id"] if pending else rows[0]["id"]
                for row in rows:
                    if row["id"] != keep_id and row["status"] == "checkout_started":
                        conn.execute(text(
                            "UPDATE payments SET status = 'cancelled' WHERE id = :id"
                        ), {"id": row["id"]})

        with db.engine.begin() as conn:
            duplicates = conn.execute(text(
                "SELECT transaction_id, COUNT(*) AS n FROM payments "
                "WHERE transaction_id IS NOT NULL GROUP BY transaction_id HAVING COUNT(*) > 1"
            )).mappings().all()
            if duplicates:
                raise RuntimeError(
                    f"payments.transaction_id duplicate kayıt sayısı: {len(duplicates)}"
                )

            if dialect in ("sqlite", "postgresql"):
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ux_payments_match_token "
                    "ON payments (match_token) WHERE match_token IS NOT NULL"
                ))
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ux_payments_transaction_id "
                    "ON payments (transaction_id) WHERE transaction_id IS NOT NULL"
                ))
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ux_payments_one_open_checkout "
                    "ON payments (user_id) WHERE user_id IS NOT NULL "
                    "AND status IN ('checkout_started', 'verification_pending')"
                ))
            else:
                conn.execute(text(
                    "CREATE UNIQUE INDEX ux_payments_match_token ON payments (match_token)"
                ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_payments_shopier_webhook_id "
                "ON payments (shopier_webhook_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_payments_verification_due "
                "ON payments (status, next_verification_at, verification_lock_until)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_boost_logs_user_window "
                "ON boost_logs (user_id, stopped_at, started_at)"
            ))
    except Exception as e:
        try:
            db.session.rollback()
        except RuntimeError:
            # _ensure_schema normalde app context içinde çağrılır. Hatalı bir
            # CLI/test çağrısı asli migration hatasını gölgelememelidir.
            pass
        logger.critical("Kritik şema güncelleme hatası; başlangıç durduruldu: %s", e)
        raise
