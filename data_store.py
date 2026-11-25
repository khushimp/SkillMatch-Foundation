"""JSON document storage backed by PostgreSQL, with isolated file storage for tests."""

import json
import os
import tempfile
import threading
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR = DEFAULT_DATA_DIR
DOCUMENTS_TABLE = "skillmatch_documents"
_document_lock = threading.RLock()


@contextmanager
def edit_documents(*filenames):
    """Atomically edit documents under database row locks (including new rows).

    Account uniqueness, token consumption and limits must survive concurrent
    requests and multiple server workers. Isolated tests use a process lock.
    """
    names = sorted(set(filenames))
    for name in names:
        _file_path(name)
    if _uses_test_file_storage():
        with _document_lock:
            documents = {name: deepcopy(load(name)) for name in names}
            yield documents
            for name in names:
                save(name, documents[name])
        return
    with psycopg.connect(_database_url()) as connection:
        with connection.cursor() as cursor:
            documents = {}
            for name in names:
                cursor.execute(
                    f"INSERT INTO {DOCUMENTS_TABLE} (filename, document) "
                    "VALUES (%s, %s) ON CONFLICT (filename) DO NOTHING",
                    (name, Jsonb({})),
                )
                cursor.execute(
                    f"SELECT document FROM {DOCUMENTS_TABLE} "
                    "WHERE filename = %s FOR UPDATE", (name,),
                )
                documents[name] = cursor.fetchone()[0]
            yield documents
            for name, document in documents.items():
                cursor.execute(
                    f"UPDATE {DOCUMENTS_TABLE} SET document = %s, updated_at = NOW() "
                    "WHERE filename = %s", (Jsonb(document), name),
                )


def _file_path(filename: str) -> Path:
    """Return a safe JSON filename contained directly in the shared data folder."""
    if not filename or Path(filename).name != filename or Path(filename).suffix != ".json":
        raise ValueError("Use a simple .json filename stored in the data directory.")
    return DATA_DIR / filename


def _uses_test_file_storage() -> bool:
    """Tests opt into temporary file storage by replacing DATA_DIR."""
    return DATA_DIR != DEFAULT_DATA_DIR


def _database_url() -> str:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is required for persistent SkillMatch storage. "
            "Tests may patch DATA_DIR to use temporary files."
        )
    return database_url


def load(filename: str) -> Any:
    """Load one JSON document from PostgreSQL or an explicitly isolated test folder."""
    path = _file_path(filename)
    if _uses_test_file_storage():
        if not path.exists():
            return {}

        with path.open("r", encoding="utf-8") as data_file:
            return json.load(data_file)

    with psycopg.connect(_database_url()) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT document FROM {DOCUMENTS_TABLE} WHERE filename = %s",
                (filename,),
            )
            row = cursor.fetchone()
    return row[0] if row else {}


def save(filename: str, data: Any) -> None:
    """Save a JSON document durably, or atomically in the test-only file backend."""
    path = _file_path(filename)
    if not _uses_test_file_storage():
        with psycopg.connect(_database_url()) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"""
                    INSERT INTO {DOCUMENTS_TABLE} (filename, document)
                    VALUES (%s, %s)
                    ON CONFLICT (filename) DO UPDATE
                    SET document = EXCLUDED.document, updated_at = NOW()
                    """,
                    (filename, Jsonb(data)),
                )
        return

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=DATA_DIR,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as data_file:
            json.dump(data, data_file, indent=2, ensure_ascii=False)
            data_file.write("\n")
        os.replace(temporary_name, path)
    finally:
        Path(temporary_name).unlink(missing_ok=True)
