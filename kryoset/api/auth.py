import os
import uuid
from datetime import timedelta
from pathlib import Path

from jose import JWTError, jwt

from kryoset.core.timezone import now_utc

SECRET_KEY_PATH = Path.home() / ".kryoset" / "api_secret.key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

_revoked_jtis: set[str] = set()
_all_issued_jtis: set[str] = set()


def _load_or_create_secret() -> str:
    """
    Load the JWT signing secret from disk, generating it if it does not exist.

    The secret file is created with mode 0o600 to prevent other users from
    reading it.
    """
    SECRET_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SECRET_KEY_PATH.exists():
        return SECRET_KEY_PATH.read_text().strip()
    secret = os.urandom(32).hex()
    SECRET_KEY_PATH.write_text(secret)
    os.chmod(SECRET_KEY_PATH, 0o600)
    return secret


_SECRET = _load_or_create_secret()


def create_access_token(username: str, is_admin: bool) -> str:
    """
    Create a signed JWT access token valid for 15 minutes.

    Args:
        username: The authenticated username to embed in the token.
        is_admin: Whether the user holds admin privileges.

    Returns:
        Encoded JWT string.
    """
    jti = str(uuid.uuid4())
    expire = now_utc() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "admin": is_admin,
        "type": "access",
        "jti": jti,
        "exp": expire,
    }
    _all_issued_jtis.add(jti)
    return jwt.encode(payload, _SECRET, algorithm=ALGORITHM)


def create_refresh_token(username: str) -> str:
    """
    Create a signed JWT refresh token valid for 7 days.

    Args:
        username: The authenticated username to embed in the token.

    Returns:
        Encoded JWT string.
    """
    jti = str(uuid.uuid4())
    expire = now_utc() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": username,
        "type": "refresh",
        "jti": jti,
        "exp": expire,
    }
    _all_issued_jtis.add(jti)
    return jwt.encode(payload, _SECRET, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.

    Args:
        token: The raw JWT string.

    Returns:
        The decoded payload dictionary.

    Raises:
        JWTError: If the token is invalid, expired, or has been revoked.
    """
    payload = jwt.decode(token, _SECRET, algorithms=[ALGORITHM])
    jti = payload.get("jti")
    if jti and jti in _revoked_jtis:
        raise JWTError("Token has been revoked.")
    return payload


def revoke_token(token: str) -> None:
    """
    Add a token's JTI to the in-memory revocation set.

    Args:
        token: The raw JWT string to revoke.
    """
    try:
        payload = jwt.decode(token, _SECRET, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if jti:
            _revoked_jtis.add(jti)
    except JWTError:
        pass


def revoke_all_tokens() -> None:
    """
    Revoke every token that has been issued since the server started.

    Called on server shutdown to force all clients to re-authenticate.
    """
    _revoked_jtis.update(_all_issued_jtis)


def is_jti_revoked(jti: str) -> bool:
    """
    Check whether a given JTI has been revoked.

    Args:
        jti: The JWT ID to check.
    """
    return jti in _revoked_jtis
