import json
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kryoset.api.app import create_app
from kryoset.core.configuration import Configuration
from kryoset.core.permission_store import PermissionStore
from kryoset.core.user_manager import UserManager


@pytest.fixture()
def tmp_dir(tmp_path):
    return tmp_path


@pytest.fixture()
def config(tmp_dir):
    storage = tmp_dir / "storage"
    storage.mkdir()
    cfg_path = tmp_dir / "config.json"
    cfg_path.write_text(
        json.dumps({
            "storage_path": str(storage),
            "host": "127.0.0.1",
            "port": 2222,
            "host_key_path": str(tmp_dir / "host_key"),
            "users": {},
        })
    )
    cfg = Configuration(cfg_path)
    cfg.load()
    return cfg


@pytest.fixture()
def user_manager(config):
    return UserManager(config)


@pytest.fixture()
def permission_store(tmp_dir):
    db_path = tmp_dir / "permissions.db"
    store = PermissionStore(db_path)
    store.initialize()
    return store


@pytest.fixture()
def app(config, user_manager, permission_store):
    return create_app(
        configuration=config,
        user_manager=user_manager,
        permission_store=permission_store,
    )


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_user(user_manager):
    user_manager.add_user("admin", "adminpass1")
    user_manager.set_admin("admin", admin=True)
    return "admin"


@pytest.fixture()
def regular_user(user_manager):
    user_manager.add_user("alice", "alicepass1")
    return "alice"


@pytest.fixture()
def admin_token(client, admin_user):
    resp = client.post("/auth/login", json={"username": "admin", "password": "adminpass1"})
    return resp.json()["access_token"]


@pytest.fixture()
def user_token(client, regular_user, permission_store):
    resp = client.post("/auth/login", json={"username": "alice", "password": "alicepass1"})
    return resp.json()["access_token"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}
