"""JWT Token management and enterprise token tracking.

Provides:
- JWT access token creation and verification
- Refresh token management with rotation support
- Enterprise token registry and blacklisting
- Invitation token handling
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Set, Tuple
from enum import Enum
from dataclasses import dataclass, field
from threading import Lock
import asyncio

import jwt

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


# Enterprise Token Management System
@dataclass
class TokenInfo:
    """Comprehensive token information for enterprise tracking."""

    token_id: str
    user_id: str
    org_id: str
    token_type: str  # 'access' or 'refresh'
    issued_at: datetime
    expires_at: datetime
    last_used: Optional[datetime] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    session_id: Optional[str] = None
    refresh_token_family_id: Optional[str] = None  # For token rotation


@dataclass
class UserSessionManager:
    """Manages all active sessions for a specific user."""

    user_id: str
    org_id: str
    active_tokens: Set[str] = field(default_factory=set)
    blacklisted_tokens: Set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TokenValidationResult(Enum):
    """Token validation result types."""

    VALID = "valid"
    EXPIRED = "expired"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_FORMAT = "invalid_format"
    DECODE_ERROR = "decode_error"
    BLACKLISTED = "blacklisted"


class EnterpriseTokenManager:
    """Thread-safe token management for enterprise environments."""

    def __init__(self):
        self._token_registry: Dict[str, TokenInfo] = {}
        self._user_sessions: Dict[str, UserSessionManager] = {}  # key: user_id
        self._blacklisted_tokens: Set[str] = set()
        self._refresh_token_families: Dict[str, Set[str]] = {}  # family_id -> token_ids
        self._lock = Lock()

        # Start background cleanup task
        self._cleanup_task = None
        self._start_cleanup_task()

    def _start_cleanup_task(self):
        """Start background task for token cleanup (deferred until async context)."""
        # Cleanup task is now started lazily when first needed
        # This avoids the deprecated asyncio.get_event_loop() warning
        pass

    async def _ensure_cleanup_task(self):
        """Ensure cleanup task is running (called from async context)."""
        if not self._cleanup_task:
            try:
                self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
            except RuntimeError:
                # No event loop in current thread
                logger.debug("Cleanup task will start when event loop is ready")

    async def _periodic_cleanup(self):
        """Periodic cleanup of expired tokens and blacklist entries."""
        while True:
            try:
                await asyncio.sleep(settings.TOKEN_BLACKLIST_CLEANUP_HOURS * 3600)
                self.cleanup_expired_tokens()
                logger.info("Completed periodic token cleanup")
            except Exception as e:
                logger.error("Error in periodic token cleanup", error=str(e))

    def register_token(self, token_info: TokenInfo) -> bool:
        """Register a new token in the system."""
        with self._lock:
            try:
                # Add to token registry
                self._token_registry[token_info.token_id] = token_info

                # Update user session
                user_key = f"{token_info.user_id}:{token_info.org_id}"
                if user_key not in self._user_sessions:
                    self._user_sessions[user_key] = UserSessionManager(
                        user_id=token_info.user_id, org_id=token_info.org_id
                    )

                session = self._user_sessions[user_key]
                session.active_tokens.add(token_info.token_id)
                session.last_activity = datetime.now(timezone.utc)

                # Handle refresh token families
                if token_info.refresh_token_family_id:
                    if (
                        token_info.refresh_token_family_id
                        not in self._refresh_token_families
                    ):
                        self._refresh_token_families[
                            token_info.refresh_token_family_id
                        ] = set()
                    self._refresh_token_families[
                        token_info.refresh_token_family_id
                    ].add(token_info.token_id)

                logger.debug(
                    "Token registered successfully",
                    token_id=token_info.token_id[:8] + "...",
                    user_id=token_info.user_id,
                    token_type=token_info.token_type,
                )
                return True

            except Exception as e:
                logger.error("Failed to register token", error=str(e))
                return False

    def blacklist_token(self, token_id: str, reason: str = "logout") -> bool:
        """Add a token to the blacklist."""
        with self._lock:
            try:
                self._blacklisted_tokens.add(token_id)

                # Update token info if exists
                if token_id in self._token_registry:
                    token_info = self._token_registry[token_id]
                    user_key = f"{token_info.user_id}:{token_info.org_id}"

                    if user_key in self._user_sessions:
                        session = self._user_sessions[user_key]
                        session.active_tokens.discard(token_id)
                        session.blacklisted_tokens.add(token_id)

                logger.info(
                    "Token blacklisted", token_id=token_id[:8] + "...", reason=reason
                )
                return True

            except Exception as e:
                logger.error(
                    "Failed to blacklist token", token_id=token_id, error=str(e)
                )
                return False

    def is_token_blacklisted(self, token_id: str) -> bool:
        """Check if a token is blacklisted."""
        with self._lock:
            return token_id in self._blacklisted_tokens

    def invalidate_user_tokens(
        self, user_id: str, org_id: str, exclude_token_id: Optional[str] = None
    ) -> int:
        """Invalidate all tokens for a user except optionally one."""
        with self._lock:
            try:
                user_key = f"{user_id}:{org_id}"
                if user_key not in self._user_sessions:
                    return 0

                session = self._user_sessions[user_key]
                tokens_to_invalidate = session.active_tokens.copy()

                if exclude_token_id:
                    tokens_to_invalidate.discard(exclude_token_id)

                for token_id in tokens_to_invalidate:
                    self._blacklisted_tokens.add(token_id)
                    session.blacklisted_tokens.add(token_id)

                session.active_tokens = (
                    {exclude_token_id} if exclude_token_id else set()
                )

                logger.info(
                    "Invalidated user tokens",
                    user_id=user_id,
                    org_id=org_id,
                    count=len(tokens_to_invalidate),
                    excluded_token=(
                        exclude_token_id[:8] + "..." if exclude_token_id else None
                    ),
                )

                return len(tokens_to_invalidate)

            except Exception as e:
                logger.error(
                    "Failed to invalidate user tokens",
                    user_id=user_id,
                    org_id=org_id,
                    error=str(e),
                )
                return 0

    def get_user_active_sessions(self, user_id: str, org_id: str) -> int:
        """Get count of active sessions for a user."""
        with self._lock:
            user_key = f"{user_id}:{org_id}"
            if user_key in self._user_sessions:
                return len(self._user_sessions[user_key].active_tokens)
            return 0

    def cleanup_expired_tokens(self) -> Tuple[int, int]:
        """Clean up expired tokens and blacklist entries."""
        with self._lock:
            try:
                now = datetime.now(timezone.utc)
                cleaned_tokens = 0
                cleaned_blacklist = 0

                # Clean up expired tokens from registry
                expired_token_ids = []
                for token_id, token_info in self._token_registry.items():
                    if token_info.expires_at < now:
                        expired_token_ids.append(token_id)

                for token_id in expired_token_ids:
                    del self._token_registry[token_id]
                    self._blacklisted_tokens.discard(token_id)
                    cleaned_tokens += 1

                # Clean up user sessions
                for user_key, session in list(self._user_sessions.items()):
                    # Remove expired tokens from active sessions
                    session.active_tokens = {
                        tid
                        for tid in session.active_tokens
                        if tid in self._token_registry
                    }

                    # Clean up old blacklisted tokens
                    expired_blacklisted = {
                        tid
                        for tid in session.blacklisted_tokens
                        if tid not in self._token_registry
                    }
                    session.blacklisted_tokens -= expired_blacklisted
                    cleaned_blacklist += len(expired_blacklisted)

                    # Remove empty sessions older than 24 hours
                    if (
                        not session.active_tokens
                        and not session.blacklisted_tokens
                        and (now - session.last_activity).total_seconds() > 86400
                    ):
                        del self._user_sessions[user_key]

                logger.info(
                    "Token cleanup completed",
                    cleaned_tokens=cleaned_tokens,
                    cleaned_blacklist=cleaned_blacklist,
                )

                return cleaned_tokens, cleaned_blacklist

            except Exception as e:
                logger.error("Error during token cleanup", error=str(e))
                return 0, 0


# Global enterprise token manager instance
_enterprise_token_manager = EnterpriseTokenManager()

# Legacy compatibility - using enterprise manager
_blacklisted_tokens = _enterprise_token_manager._blacklisted_tokens
_blacklist_lock = _enterprise_token_manager._lock


# JWT Token Functions


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Tuple[str, TokenInfo]:
    """
    Create a JWT access token with enterprise tracking.

    Args:
        data: Data to encode in the token
        expires_delta: Custom expiration time (overrides config)
        user_agent: Client user agent for tracking
        ip_address: Client IP address for tracking

    Returns:
        Tuple of (encoded JWT token, token info)
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)

    # Use configuration-based expiration
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.access_token_expire_minutes)

    # Generate unique token ID for tracking
    token_id = str(uuid.uuid4())

    # Add enterprise token metadata
    to_encode.update(
        {
            "exp": expire,
            "iat": now,
            "jti": token_id,  # JWT ID for tracking
            "token_type": "access",
        }
    )

    # Create the JWT
    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )

    # Create token info for enterprise tracking
    token_info = TokenInfo(
        token_id=token_id,
        user_id=data.get("sub", ""),
        org_id=data.get("org_id", ""),
        token_type="access",
        issued_at=now,
        expires_at=expire,
        user_agent=user_agent,
        ip_address=ip_address,
    )

    # Register token in enterprise manager
    _enterprise_token_manager.register_token(token_info)

    logger.debug(
        "Access token created",
        token_id=token_id[:8] + "...",
        user_id=data.get("sub"),
        org_id=data.get("org_id"),
        expires_in_minutes=settings.access_token_expire_minutes,
    )

    return encoded_jwt, token_info


def create_refresh_token(
    user_id: str,
    org_id: str,
    family_id: Optional[str] = None,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Tuple[str, TokenInfo]:
    """
    Create a JWT refresh token with enterprise tracking and rotation support.

    Args:
        user_id: User identifier
        org_id: Organization identifier
        family_id: Token family ID for rotation tracking
        user_agent: Client user agent for tracking
        ip_address: Client IP address for tracking

    Returns:
        Tuple of (encoded JWT refresh token, token info)
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.refresh_token_expire_days)

    # Generate unique token ID and family ID if not provided
    token_id = str(uuid.uuid4())
    if not family_id:
        family_id = str(uuid.uuid4())

    data = {
        "sub": user_id,
        "org_id": org_id,
        "type": "refresh",
        "jti": token_id,
        "family_id": family_id,
        "exp": expire,
        "iat": now,
    }

    # Create the JWT
    encoded_jwt = jwt.encode(
        data, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )

    # Create token info for enterprise tracking
    token_info = TokenInfo(
        token_id=token_id,
        user_id=user_id,
        org_id=org_id,
        token_type="refresh",
        issued_at=now,
        expires_at=expire,
        user_agent=user_agent,
        ip_address=ip_address,
        refresh_token_family_id=family_id,
    )

    # Register token in enterprise manager
    _enterprise_token_manager.register_token(token_info)

    logger.debug(
        "Refresh token created",
        token_id=token_id[:8] + "...",
        family_id=family_id[:8] + "...",
        user_id=user_id,
        org_id=org_id,
        expires_in_days=settings.refresh_token_expire_days,
    )

    return encoded_jwt, token_info


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify and decode a JWT token with enterprise tracking.

    Args:
        token: JWT token to verify

    Returns:
        Decoded token data or None if invalid
    """
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )

        # Extract token ID for enterprise tracking
        token_id = payload.get("jti")
        if token_id:
            # Update last used timestamp in enterprise manager
            with _enterprise_token_manager._lock:
                if token_id in _enterprise_token_manager._token_registry:
                    _enterprise_token_manager._token_registry[token_id].last_used = (
                        datetime.now(timezone.utc)
                    )

        if settings.ENABLE_AUTH_AUDIT_LOGGING:
            logger.debug(
                "Token verified successfully",
                token_id=token_id[:8] + "..." if token_id else "legacy",
                user_id=payload.get("sub"),
                org_id=payload.get("org_id"),
                token_type=payload.get("token_type", payload.get("type")),
            )

        return payload

    except jwt.ExpiredSignatureError:
        if settings.ENABLE_AUTH_AUDIT_LOGGING:
            logger.debug("Token verification failed: expired signature")
        return None
    except jwt.InvalidSignatureError:
        logger.warning(
            "Token verification failed: invalid signature - possible tampering attempt"
        )
        return None
    except jwt.InvalidTokenError:
        logger.warning("Token verification failed: invalid token format")
        return None
    except jwt.DecodeError:
        logger.warning("Token verification failed: decode error")
        return None
    except jwt.PyJWTError as e:
        logger.error("Token verification failed: unexpected JWT error", error=str(e))
        return None


def verify_token_detailed(
    token: str,
) -> tuple[Optional[Dict[str, Any]], TokenValidationResult]:
    """
    Verify and decode a JWT token with detailed validation result.

    Args:
        token: JWT token to verify

    Returns:
        Tuple of (decoded token data or None, validation result)
    """
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        logger.debug(
            "Token verified successfully",
            user_id=payload.get("sub"),
            org_id=payload.get("org_id"),
        )
        return payload, TokenValidationResult.VALID
    except jwt.ExpiredSignatureError:
        logger.debug("Token verification failed: expired signature")
        return None, TokenValidationResult.EXPIRED
    except jwt.InvalidSignatureError:
        logger.warning("Token verification failed: invalid signature")
        return None, TokenValidationResult.INVALID_SIGNATURE
    except jwt.InvalidTokenError:
        logger.warning("Token verification failed: invalid token format")
        return None, TokenValidationResult.INVALID_FORMAT
    except jwt.DecodeError:
        logger.warning("Token verification failed: decode error")
        return None, TokenValidationResult.DECODE_ERROR
    except jwt.PyJWTError as e:
        logger.error("Token verification failed: unexpected JWT error", error=str(e))
        return None, TokenValidationResult.DECODE_ERROR


def blacklist_token(token: str, reason: str = "logout") -> bool:
    """
    Add a token to the enterprise blacklist system.

    Args:
        token: JWT token to blacklist
        reason: Reason for blacklisting (for audit trail)

    Returns:
        True if token was successfully blacklisted
    """
    try:
        # Decode token to get token ID
        # Allow expired tokens but still verify signature for security
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        token_id = payload.get("jti")

        if token_id:
            return _enterprise_token_manager.blacklist_token(token_id, reason)
        else:
            # Legacy token without jti - use full token as ID
            _blacklisted_tokens.add(token)
            logger.warning("Blacklisted legacy token without jti", reason=reason)
            return True

    except Exception as e:
        logger.error("Failed to blacklist token", error=str(e), reason=reason)
        return False


def is_token_blacklisted(token: str) -> bool:
    """
    Check if a token is blacklisted using enterprise tracking.

    Args:
        token: JWT token to check

    Returns:
        True if token is blacklisted
    """
    try:
        # Try to decode token to get token ID
        # Allow expired tokens but still verify signature for security
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        token_id = payload.get("jti")

        if token_id:
            return _enterprise_token_manager.is_token_blacklisted(token_id)
        else:
            # Legacy token check
            return token in _blacklisted_tokens

    except Exception:
        # If we can't decode, check legacy blacklist
        return token in _blacklisted_tokens


def verify_token_not_blacklisted(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify token and check if it's not blacklisted.

    Args:
        token: JWT token to verify

    Returns:
        Token payload if valid and not blacklisted, None otherwise
    """
    # First check if token is blacklisted
    if is_token_blacklisted(token):
        return None

    # Then verify token normally
    return verify_token(token)


def create_user_token_data(
    user_id: str, org_id: str, email: str, role: str
) -> Dict[str, Any]:
    """
    Create the data payload for a user's JWT token.

    Args:
        user_id: User identifier
        org_id: Organization identifier
        email: User email
        role: User role

    Returns:
        Token data dictionary
    """
    return {
        "sub": user_id,  # Subject (user ID)
        "org_id": org_id,
        "email": email,
        "role": role,
        "type": "access",
    }


def generate_invitation_token(
    org_id: str, email: str, role: str, expires_hours: int = 168
) -> str:
    """
    Generate an invitation token for user registration.

    Args:
        org_id: Organization identifier
        email: Invitee email address
        role: Role to assign to the user
        expires_hours: Token expiration in hours (default 7 days)

    Returns:
        Encoded invitation token
    """
    data = {"org_id": org_id, "email": email, "role": role, "type": "invitation"}
    expire = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
    data.update({"exp": expire, "iat": datetime.now(timezone.utc)})

    encoded_jwt = jwt.encode(
        data, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def verify_invitation_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify an invitation token and return its data.

    Args:
        token: Invitation token to verify

    Returns:
        Token data or None if invalid/expired
    """
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        if payload.get("type") != "invitation":
            logger.debug("Token verification failed: not an invitation token")
            return None
        logger.debug(
            "Invitation token verified successfully",
            email=payload.get("email"),
            org_id=payload.get("org_id"),
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.debug("Invitation token verification failed: expired signature")
        return None
    except jwt.InvalidSignatureError:
        logger.warning("Invitation token verification failed: invalid signature")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invitation token verification failed: invalid token format")
        return None
    except jwt.DecodeError:
        logger.warning("Invitation token verification failed: decode error")
        return None
    except jwt.PyJWTError as e:
        logger.error(
            "Invitation token verification failed: unexpected JWT error", error=str(e)
        )
        return None


# Enterprise Session Management Functions


def invalidate_user_sessions(
    user_id: str, org_id: str, exclude_token_id: Optional[str] = None
) -> int:
    """
    Invalidate all active sessions for a user (enterprise feature).

    Args:
        user_id: User identifier
        org_id: Organization identifier
        exclude_token_id: Token ID to exclude from invalidation (e.g., current login)

    Returns:
        Number of tokens invalidated
    """
    return _enterprise_token_manager.invalidate_user_tokens(
        user_id, org_id, exclude_token_id
    )


def get_user_active_session_count(user_id: str, org_id: str) -> int:
    """
    Get the number of active sessions for a user.

    Args:
        user_id: User identifier
        org_id: Organization identifier

    Returns:
        Number of active sessions
    """
    return _enterprise_token_manager.get_user_active_sessions(user_id, org_id)


def cleanup_expired_tokens() -> Tuple[int, int]:
    """
    Clean up expired tokens and blacklist entries.

    Returns:
        Tuple of (cleaned_tokens, cleaned_blacklist_entries)
    """
    return _enterprise_token_manager.cleanup_expired_tokens()
