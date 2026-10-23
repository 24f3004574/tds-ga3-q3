import os
import threading

import psycopg

SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS evaluations (
        evaluation_id TEXT PRIMARY KEY,
        request_hash TEXT NOT NULL,
        input_digest TEXT NOT NULL,
        verifier JSONB NOT NULL,
        proposals JSONB NOT NULL,
        propose_response JSONB NOT NULL,
        commit_hash TEXT,
        commit_response JSONB,
        receipts JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS mailroom_decisions (
        dossier_id TEXT NOT NULL,
        cache_key TEXT NOT NULL,
        proposal JSONB NOT NULL,
        dossier JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (dossier_id, cache_key)
    )""",
]

_ready = False
_lock = threading.Lock()


def database_url():
    value = os.getenv("POSTGRES_URL")
    if not value:
        raise RuntimeError("Database configuration is missing")
    return value


def init_db():
    """Create tables once per process (safe across serverless instances)."""
    global _ready
    if _ready:
        return
    with _lock:
        if _ready:
            return
        with psycopg.connect(database_url(), connect_timeout=8) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(727274101)")
                for statement in SCHEMA_STATEMENTS:
                    cursor.execute(statement)
        _ready = True


def connect_db():
    init_db()
    return psycopg.connect(database_url(), connect_timeout=8)
