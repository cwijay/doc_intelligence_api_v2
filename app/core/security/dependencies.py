"""FastAPI security dependencies.

Provides:
- HTTPBearer security scheme
- get_current_user_org dependency for protected endpoints
"""

from typing import Dict, Any

from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.config import settings
from app.core.logging import get_logger
from .tokens import (
    verify_token_not_blacklisted,
    get_user_active_session_count,
)

logger = get_logger(__name__)

# Security scheme for authentication
security = HTTPBearer()


def get_current_user_org(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """
    Enterprise FastAPI dependency to get current user and organization from JWT token.

    Args:
        credentials: HTTPAuthorizationCredentials from HTTPBearer security scheme

    Returns:
        Dictionary containing user_id, org_id, email, role, and token metadata

    Raises:
        HTTPException: If token is invalid or missing
    """
    if settings.ENABLE_AUTH_AUDIT_LOGGING:
        logger.info(
            "Enterprise authentication started",
            token_present=bool(credentials.credentials),
            token_length=len(credentials.credentials) if credentials.credentials else 0,
        )

    token = credentials.credentials

    # Verify token is valid and not blacklisted
    payload = verify_token_not_blacklisted(token)
    if not payload:
        if settings.ENABLE_AUTH_AUDIT_LOGGING:
            logger.warning("Authentication failed: Invalid or expired token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )

    # Check token type - support both 'type' and 'token_type' for compatibility
    token_type = payload.get("token_type") or payload.get("type")
    if token_type != "access":
        if settings.ENABLE_AUTH_AUDIT_LOGGING:
            logger.warning(
                "Authentication failed: Invalid token type", provided_type=token_type
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type"
        )

    # Extract user and organization data
    user_id = payload.get("sub")
    org_id = payload.get("org_id")
    email = payload.get("email")
    role = payload.get("role")
    token_id = payload.get("jti")

    if not all([user_id, org_id, email, role]):
        logger.error(
            "Authentication failed: Invalid token payload",
            user_id=bool(user_id),
            org_id=bool(org_id),
            email=bool(email),
            role=bool(role),
            token_id=token_id[:8] + "..." if token_id else "legacy",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload"
        )

    if settings.ENABLE_AUTH_AUDIT_LOGGING:
        logger.info(
            "Enterprise authentication success",
            org_id=org_id,
            user_id=user_id,
            token_id=token_id[:8] + "..." if token_id else "legacy",
            active_sessions=get_user_active_session_count(user_id, org_id),
        )

    return {
        "user_id": user_id,
        "org_id": org_id,
        "email": email,
        "role": role,
        "token_id": token_id,
        "issued_at": payload.get("iat"),
        "expires_at": payload.get("exp"),
    }
