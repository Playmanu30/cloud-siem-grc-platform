"""Test configuration: isolated database and no live API keys"""

import atexit
import os
import tempfile
from pathlib import Path

import pytest

# A unique file per pytest process keeps parallel runs from deleting each other's rows.
TEST_DB = Path(tempfile.gettempdir()) / f"cloud_siem_grc_test_{os.getpid()}.db"


def _cleanup_test_db() -> None:
    for suffix in ("", "-wal", "-shm"):
        Path(f"{TEST_DB}{suffix}").unlink(missing_ok=True)


_cleanup_test_db()
atexit.register(_cleanup_test_db)

# Must be set before src.* imports so the cached Settings picks them up.
os.environ.update(
    ENV="test",
    DEBUG="true",
    DATABASE_URL=f"sqlite:///{TEST_DB.as_posix()}",
    API_KEY="",
    RATE_LIMIT_RPM="10000",
    VT_API_KEY="",
    SHODAN_API_KEY="",
    ABUSEIPDB_API_KEY="",
    AWS_ACCESS_KEY_ID="",
    AWS_SECRET_ACCESS_KEY="",
    AZURE_TENANT_ID="",
    AZURE_CLIENT_ID="",
    AZURE_CLIENT_SECRET="",
    AZURE_SUBSCRIPTION_ID="",
)


@pytest.fixture(autouse=True)
def clean_database():
    from src.utils.store import get_store

    store = get_store()
    with store._connect() as conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM reports")
    yield


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from src.api.main import app

    with TestClient(app) as test_client:
        yield test_client
