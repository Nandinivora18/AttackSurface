-- SentinelScan — PostgreSQL bootstrap (runs once on first container start).
--
-- NOTE: This file intentionally does NOT create any tables or enum types.
-- The database schema (tables, indexes, and the native PostgreSQL enums
-- userrole / scanstatus / risklevel / severity) is owned exclusively by
-- Alembic migrations:
--
--     docker compose up backend   # runs `alembic upgrade head` before uvicorn
--
-- Duplicating schema here caused drift (init.sql previously missed the
-- 'cancelled' ScanStatus value) and crashed `alembic upgrade head` with
-- DuplicateObject, since Alembic's op.create_table() emits an unconditional
-- CREATE TYPE for native enums. Migration history is now a single consolidated
-- head (migrations/versions/0001_initial_schema.py); schema must never be
-- duplicated here.

-- pg_trgm + unaccent power case/accent-insensitive asset search.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS unaccent;
