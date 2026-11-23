# Read-only PostgreSQL inspection

The optional database adapter uses psycopg 3 and issues SELECT statements only. It starts a read-only transaction, applies a 5-second statement timeout and 1-second lock timeout, inspects the current role's privilege flags and connection TLS state, then rolls back and closes the connection.

## Install and configure

    pip install -e '.[db]'

Set PG_ASSESS_DATABASE_URL in the local process environment. Do not paste connection strings into chat, source control, command history, or reports. For non-loopback databases, set PG_ASSESS_DATABASE_HOSTS to a comma-separated exact hostname allowlist.

For remote staging PostgreSQL, use sslmode=verify-full with a trusted CA configuration. Do not use sslmode=disable or prefer for production-grade verification.

## Run

    pg-assess assess-database --confirm-read-only

The command refuses remote hosts not in the explicit allowlist. It never executes DDL, DML, migrations, or application queries. The report intentionally does not record the connection string, username, database name, or hostname.

## What it checks

- Whether the session negotiated TLS and whether the URL requests verify-ca or verify-full.
- Whether the current role has superuser, CREATEDB, CREATEROLE, or REPLICATION privilege.
- Whether the current role can create objects in the public schema.
- Whether PostgreSQL confirmed transaction_read_only=on.

Backup encryption, audit configuration, and a separate migration role cannot be proven from one runtime session. They remain unconfirmed until supplied through an independently reviewed configuration inventory.
