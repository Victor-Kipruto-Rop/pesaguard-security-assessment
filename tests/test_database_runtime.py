import pytest
from pg_assess.database_runtime import inspect_postgres_readonly

def test_remote_database_host_requires_allowlist(monkeypatch):
    monkeypatch.delenv("PG_ASSESS_DATABASE_HOSTS", raising=False)
    with pytest.raises(ValueError, match="not in PG_ASSESS_DATABASE_HOSTS"):
        inspect_postgres_readonly("postgresql://assessor:secret@db.example.invalid:5432/pesaguard?sslmode=verify-full")

def test_invalid_database_url_is_rejected():
    with pytest.raises(ValueError, match="PostgreSQL connection URL"):
        inspect_postgres_readonly("https://example.invalid/database")

def test_database_url_must_be_supplied(monkeypatch):
    monkeypatch.delenv("PG_ASSESS_DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="PG_ASSESS_DATABASE_URL is required"):
        inspect_postgres_readonly()
