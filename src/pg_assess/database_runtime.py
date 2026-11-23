"""Optional read-only PostgreSQL posture inspection with strict host allowlisting."""
from __future__ import annotations

import os
from ipaddress import ip_address
from urllib.parse import parse_qs, urlparse


def inspect_postgres_readonly(conninfo: str | None = None) -> dict:
    connection_string = conninfo or os.getenv("PG_ASSESS_DATABASE_URL", "")
    if not connection_string:
        raise ValueError("PG_ASSESS_DATABASE_URL is required.")
    parsed = urlparse(connection_string)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
        raise ValueError("PG_ASSESS_DATABASE_URL must be a PostgreSQL connection URL.")
    host = parsed.hostname.lower()
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    allowed_hosts = {
        item.strip().lower()
        for item in os.getenv("PG_ASSESS_DATABASE_HOSTS", "").split(",")
        if item.strip()
    }
    if host not in local_hosts and host not in allowed_hosts:
        raise ValueError("Database hostname is not in PG_ASSESS_DATABASE_HOSTS.")
    hostaddr = None
    if host not in local_hosts:
        ip_map = {}
        for entry in os.getenv("PG_ASSESS_DATABASE_IPS", "").split(","):
            if "=" not in entry:
                continue
            name, value = entry.split("=", 1)
            try:
                ip_map[name.strip().lower()] = str(ip_address(value.strip()))
            except ValueError:
                raise ValueError("PG_ASSESS_DATABASE_IPS contains an invalid address.") from None
        hostaddr = ip_map.get(host)
        if not hostaddr:
            raise ValueError("Remote database host requires a pinned address in PG_ASSESS_DATABASE_IPS.")
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("Install the optional database extra: pip install '.[db]'.") from exc
    sslmode = parse_qs(parsed.query).get("sslmode", [""])[0]
    try:
        connect_options = {
            "connect_timeout": 5,
            "options": "-c statement_timeout=5000 -c lock_timeout=1000",
        }
        if hostaddr:
            connect_options["hostaddr"] = hostaddr
        connection = psycopg.connect(connection_string, **connect_options)
        try:
            connection.execute("SET TRANSACTION READ ONLY")
            read_only = connection.execute(
                "SELECT current_setting('transaction_read_only') = 'on'"
            ).fetchone()[0]
            row = connection.execute(
                """
                SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication,
                       has_database_privilege(current_user, current_database(), 'CREATE'),
                       has_schema_privilege(current_user, 'public', 'CREATE')
                FROM pg_roles AS r
                WHERE r.rolname = current_user
                """
            ).fetchone()
            if row is None:
                raise RuntimeError("Could not inspect current database role.")
            superuser, create_role, create_db, replication, db_create, schema_create = row
            snapshot = {
                "tls_required": bool(connection.info.ssl_in_use),
                "sslmode": sslmode,
                "application_role_not_superuser": not bool(
                    superuser or create_role or create_db or replication
                ),
                "separate_migration_role": False,
                "public_schema_create_revoked": not bool(schema_create),
                "backup_encryption_enabled": False,
                "audit_logging_enabled": False,
                "read_only_transaction_enforced": bool(read_only),
                "role_has_create_database": bool(db_create),
                "role_has_create_schema": bool(schema_create),
                "role_has_create_role": bool(create_role),
                "role_has_replication": bool(replication),
            }
            return snapshot
        finally:
            try:
                connection.rollback()
            finally:
                connection.close()
    except Exception as exc:
        raise RuntimeError(
            f"Read-only database inspection failed ({type(exc).__name__})."
        ) from None
