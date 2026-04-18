import json
from fastapi.testclient import TestClient
from kryoset.api.app import create_app
from kryoset.core.user_manager import UserManager
from kryoset.core.permission_store import PermissionStore
from kryoset.core.permissions import PermissionRule, Permission
from kryoset.cli import _load_config
import os

def test():
    # 1) Setup
    cfg = _load_config()
    ps = PermissionStore()
    ps.initialize()
    
    um = UserManager(cfg)
    app = create_app(cfg, um, permission_store=ps)
    client = TestClient(app)

    # 2) Create user alice
    username = "alice"
    password = "password123"
    try:
        um.remove_user(username)
    except:
        pass
    um.add_user(username, password)
    um.set_enabled(username, enabled=True)
    
    # Get token via /auth/login
    print("Tentative de login...")
    response = client.post("/auth/login", json={"username": username, "password": password})
    if response.status_code != 200:
        # Try OAuth2 form if JSON fails
        response = client.post("/auth/login", data={"username": username, "password": password})
    
    print(f"Login Response: {response.status_code} {response.text}")
    token = response.json().get("access_token")
    if not token:
        print(f"Failed to get token: {response.json()}")
        return
    headers = {"Authorization": f"Bearer {token}"}

    # 3) Tente /files/list (doit être 403)
    print("\n--- Avant ajout de la règle ---")
    resp_before = client.get("/files/list", headers=headers, params={"path": "/"})
    print(f"Status: {resp_before.status_code}")
    print(f"JSON: {resp_before.json()}")

    # 4) Ajoute une règle LIST
    ps.add_rule(PermissionRule(
        principal=username,
        path="/",
        permission=Permission.LIST,
        allow=True
    ))
    print(f"\nRègle {Permission.LIST.name} ajoutée pour {username} sur '/'")

    # 5) Retente /files/list
    print("\n--- Après ajout de la règle ---")
    resp_after = client.get("/files/list", headers=headers, params={"path": "/"})
    print(f"Status: {resp_after.status_code}")
    print(f"JSON: {resp_after.json()}")

if __name__ == "__main__":
    test()
