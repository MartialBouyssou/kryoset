import os
import uuid
from datetime import timedelta
from pathlib import Path

import jwt
from jwt import InvalidTokenError as JWTError

from kryoset.core.timezone import now_utc

SECRET_KEY_PATH = Path.home() / ".kryoset" / "api_secret.key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
MAX_TOKEN_BYTES = 4096

_revoked_jtis: set[str] = set()
_all_issued_jtis: set[str] = set()


def _load_or_create_secret() -> str:
    """
    Load the JWT signing secret from disk, generating it if it does not exist.

    The secret file is created with mode 0o600 to prevent other users from
    reading it.
    """
    SECRET_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(SECRET_KEY_PATH.parent, 0o700)
    except OSError:
        pass
    if SECRET_KEY_PATH.exists():
        os.chmod(SECRET_KEY_PATH, 0o600)
        return SECRET_KEY_PATH.read_text().strip()
    secret = os.urandom(32).hex()
    SECRET_KEY_PATH.write_text(secret)
    os.chmod(SECRET_KEY_PATH, 0o600)
    return secret


_SECRET = _load_or_create_secret()


def create_access_token(username: str, is_admin: bool, token_version: int = 0) -> str:
    """
    Create a signed JWT access token valid for 15 minutes.
    """
    jti = str(uuid.uuid4())
    expire = now_utc() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "admin": is_admin,
        "type": "access",
        "ver": token_version,
        "jti": jti,
        "exp": expire,
        "iat": now_utc(),
    }
    _all_issued_jtis.add(jti)
    return jwt.encode(payload, _SECRET, algorithm=ALGORITHM)


def create_refresh_token(username: str, token_version: int = 0) -> str:
    """
    Create a signed JWT refresh token valid for 7 days.
    """
    jti = str(uuid.uuid4())
    expire = now_utc() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": username,
        "type": "refresh",
        "ver": token_version,
        "jti": jti,
        "exp": expire,
        "iat": now_utc(),
    }
    _all_issued_jtis.add(jti)
    return jwt.encode(payload, _SECRET, algorithm=ALGORITHM)


def _preflight_token(token: str) -> None:
    if not isinstance(token, str) or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise JWTError("Invalid token.")
    # Kryoset issues compact signed JWTs only. Reject JWE/JWT bombs and malformed
    # tokens before handing them to the JWT library.
    if token.count(".") != 2:
        raise JWTError("Invalid token.")
    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        raise
    except Exception as error:
        raise JWTError("Invalid token.") from error
    if header.get("alg") != ALGORITHM:
        raise JWTError("Invalid token algorithm.")
    if "zip" in header:
        raise JWTError("Compressed JWTs are not accepted.")


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    """
    _preflight_token(token)
    try:
        payload = jwt.decode(
            token,
            _SECRET,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "iat", "jti", "sub", "type"]},
        )
    except JWTError:
        raise
    except Exception as error:
        raise JWTError("Invalid token.") from error
    jti = payload.get("jti")
    if jti and jti in _revoked_jtis:
        raise JWTError("Token has been revoked.")
    return payload


def revoke_token(token: str) -> None:
    """
    Add a token's JTI to the in-memory revocation set.
    """
    try:
        payload = decode_token(token)
        jti = payload.get("jti")
        if jti:
            _revoked_jtis.add(jti)
    except JWTError:
        pass


def revoke_all_tokens() -> None:
    """
    Revoke every token that has been issued since the server started.
    """
    _revoked_jtis.update(_all_issued_jtis)


def is_jti_revoked(jti: str) -> bool:
    return jti in _revoked_jtis
