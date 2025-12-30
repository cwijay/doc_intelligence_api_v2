"""Security module for authentication and authorization.

This module provides:
- Password hashing and validation (bcrypt)
- JWT token management with enterprise tracking
- Token blacklisting and session management
- FastAPI security dependencies

Usage:
    from app.core.security import (
        hash_password,
        verify_password,
        create_access_token,
        verify_token,
        get_current_user_org,
    )
"""

# Password functions
from .password import (
    hash_password,
    verify_password,
    validate_password_strength,
    generate_secure_password,
    needs_rehash,
    pwd_context,
)

# Token management
from .tokens import (
    TokenInfo,
    UserSessionManager,
    TokenValidationResult,
    EnterpriseTokenManager,
    create_access_token,
    create_refresh_token,
    verify_token,
    verify_token_detailed,
    verify_token_not_blacklisted,
    blacklist_token,
    is_token_blacklisted,
    create_user_token_data,
    generate_invitation_token,
    verify_invitation_token,
    invalidate_user_sessions,
    get_user_active_session_count,
    cleanup_expired_tokens,
    # Legacy compatibility
    _enterprise_token_manager,
    _blacklisted_tokens,
    _blacklist_lock,
)

# FastAPI dependencies
from .dependencies import (
    security,
    get_current_user_org,
)

__all__ = [
    # Password
    "hash_password",
    "verify_password",
    "validate_password_strength",
    "generate_secure_password",
    "needs_rehash",
    "pwd_context",
    # Token types
    "TokenInfo",
    "UserSessionManager",
    "TokenValidationResult",
    "EnterpriseTokenManager",
    # Token functions
    "create_access_token",
    "create_refresh_token",
    "verify_token",
    "verify_token_detailed",
    "verify_token_not_blacklisted",
    "blacklist_token",
    "is_token_blacklisted",
    "create_user_token_data",
    "generate_invitation_token",
    "verify_invitation_token",
    "invalidate_user_sessions",
    "get_user_active_session_count",
    "cleanup_expired_tokens",
    # Dependencies
    "security",
    "get_current_user_org",
    # Legacy
    "_enterprise_token_manager",
    "_blacklisted_tokens",
    "_blacklist_lock",
]
