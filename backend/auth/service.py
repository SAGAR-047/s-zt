"""
SentinelCloud Authentication Service
=====================================
Proper JWT-based auth with bcrypt password hashing.
No hardcoded credentials — initial admin created from env vars.
"""

import os
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
from jose import jwt, JWTError
from pydantic import BaseModel

from backend.config import settings

logger = logging.getLogger("sentinel.auth")


def _hash_password(password: str) -> str:
    """Hash password using bcrypt directly."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# ── Models ──

class User(BaseModel):
    username: str
    role: str  # admin, analyst
    display_name: str
    password_hash: str
    created_at: datetime


class TokenPayload(BaseModel):
    sub: str  # username
    role: str
    exp: float
    iat: float


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    authenticated: bool
    token: Optional[str] = None
    role: Optional[str] = None
    username: Optional[str] = None
    display_name: Optional[str] = None
    message: str = ""


class TokenVerifyResponse(BaseModel):
    authenticated: bool
    role: Optional[str] = None
    username: Optional[str] = None


# ── User Store ──

class AuthService:
    """Manages users and JWT tokens."""

    def __init__(self):
        self.users: dict[str, User] = {}
        self._init_default_users()

    def _init_default_users(self):
        """Create default users from environment variables."""
        admin_user = os.environ.get("SENTINEL_ADMIN_USER", "admin")
        admin_pass = os.environ.get("SENTINEL_ADMIN_PASSWORD", "sentinel-admin-2026")

        self.create_user(
            username=admin_user,
            password=admin_pass,
            role="admin",
            display_name="SOC Administrator"
        )

        analyst_user = os.environ.get("SENTINEL_ANALYST_USER", "")
        analyst_pass = os.environ.get("SENTINEL_ANALYST_PASSWORD", "")
        if analyst_user and analyst_pass:
            self.create_user(
                username=analyst_user,
                password=analyst_pass,
                role="analyst",
                display_name="Security Analyst"
            )

        logger.info("Auth service initialized with %d users", len(self.users))

    def create_user(self, username: str, password: str, role: str, display_name: str):
        """Create a new user with hashed password."""
        self.users[username] = User(
            username=username,
            role=role,
            display_name=display_name,
            password_hash=_hash_password(password),
            created_at=datetime.now(timezone.utc),
        )

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Verify credentials. Returns User on success, None on failure."""
        user = self.users.get(username)
        if not user:
            return None
        if not _verify_password(password, user.password_hash):
            return None
        return user

    def create_token(self, user: User) -> str:
        """Create a JWT token for the user."""
        now = time.time()
        payload = {
            "sub": user.username,
            "role": user.role,
            "iat": now,
            "exp": now + (settings.jwt_expiry_hours * 3600),
        }
        return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)

    def verify_token(self, token: str) -> Optional[TokenPayload]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(
                token,
                settings.secret_key,
                algorithms=[settings.jwt_algorithm],
            )
            return TokenPayload(**payload)
        except JWTError as e:
            logger.debug("Token verification failed: %s", e)
            return None

    def login(self, req: LoginRequest) -> LoginResponse:
        """Full login flow: verify credentials, issue token."""
        user = self.authenticate(req.username, req.password)
        if not user:
            return LoginResponse(
                authenticated=False,
                message="Invalid username or password."
            )
        token = self.create_token(user)
        return LoginResponse(
            authenticated=True,
            token=token,
            role=user.role,
            username=user.username,
            display_name=user.display_name,
            message=f"Authenticated as {user.display_name}"
        )


# Singleton
auth_service = AuthService()
