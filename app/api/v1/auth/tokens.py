"""Token management endpoints.

Provides:
- /refresh - Refresh access token
- /validate - Validate current session
- /refresh-session - Refresh session token
- /debug/session-info - Session diagnostics (hidden from docs)
"""

from typing import Dict, Any

from fastapi import APIRouter, HTTPException, status, Depends
from datetime import datetime, timezone

from app.core.logging import get_service_logger
from app.core.config import settings
from app.core.simple_auth import (
    get_current_user_dict,
    validate_user_session,
    refresh_user_session,
)
from app.core.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    RefreshTokenExpiredError,
    RefreshTokenInvalidError,
)
from app.services.auth_service import (
    auth_service,
    AuthenticationError,
)
from app.models.schemas.auth import (
    RefreshTokenRequest,
    AuthResponse,
    AccessTokenResponse,
)

logger = get_service_logger("auth_api")

router = APIRouter()


@router.post(
    "/refresh",
    response_model=AccessTokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    operation_id="refreshAccessToken",
    description="Get a new access token using a valid refresh token.",
)
async def refresh_access_token(request: RefreshTokenRequest) -> AccessTokenResponse:
    """
    Refresh access token using a refresh token.

    Args:
        request: Refresh token request

    Returns:
        New access token response

    Raises:
        HTTPException: If refresh fails
    """
    try:
        logger.debug("Enterprise token refresh attempt")

        access_token, new_refresh_token, token_info = (
            await auth_service.refresh_access_token(request.refresh_token)
        )

        logger.debug(
            "Enterprise token refresh successful",
            rotation_enabled=token_info["rotation_enabled"],
            refresh_token_rotated=token_info["refresh_token_rotated"],
        )

        return AccessTokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in=token_info["access_token_expires_in"],
            access_token_expires_at=token_info["access_token_expires_at"],
            refresh_token_expires_at=token_info.get("refresh_token_expires_at"),
            refresh_token_expires_in=token_info.get("refresh_token_expires_in"),
            rotation_enabled=token_info["rotation_enabled"],
            refresh_token_rotated=token_info["refresh_token_rotated"],
        )

    except AuthenticationError as e:
        logger.warning("Enterprise token refresh failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    except Exception as e:
        logger.error("Enterprise token refresh error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed due to server error",
        )


@router.get(
    "/validate",
    response_model=Dict[str, Any],
    summary="Validate access token",
    operation_id="validateToken",
    description="Validate the current session token and return expiration information for the frontend.",
)
async def validate_token(
    current_user: Dict[str, Any] = Depends(get_current_user_dict),
) -> Dict[str, Any]:
    """
    Validate session token and return validation info.

    This endpoint allows the frontend to check if the current session is valid
    and get information about when it expires.

    Args:
        current_user: Current user info from session validation

    Returns:
        Token validation information including expiry details

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        session_id = current_user.get("session_id")
        if not session_id:
            raise TokenInvalidError("Session ID not found in token")

        validation_info = validate_user_session(session_id)
        if not validation_info:
            raise TokenInvalidError("Session validation failed")

        logger.debug(
            "Token validation successful",
            user_id=current_user.get("user_id"),
            session_id=session_id[:8] + "...",
        )

        return {
            "valid": validation_info["valid"],
            "expires_at": validation_info["expires_at"],
            "time_remaining": validation_info["time_remaining"],
            "in_grace_period": validation_info["in_grace_period"],
            "can_refresh": validation_info["can_refresh"],
            "user": {
                "user_id": current_user["user_id"],
                "email": current_user["email"],
                "full_name": current_user["full_name"],
                "role": current_user["role"],
                "org_id": current_user["org_id"],
            },
        }

    except (TokenExpiredError, TokenInvalidError):
        raise
    except Exception as e:
        logger.error("Token validation error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token validation failed",
        )


@router.post(
    "/refresh-session",
    response_model=AuthResponse,
    summary="Refresh session token",
    operation_id="refreshSession",
    description="Refresh the session using a refresh token to get new access and refresh tokens.",
)
async def refresh_session_token(request: RefreshTokenRequest) -> AuthResponse:
    """
    Refresh session using refresh token.

    This endpoint allows the frontend to get a new session token when
    the current one is expired or about to expire.

    Args:
        request: Refresh token request containing the refresh token

    Returns:
        New authentication response with fresh tokens

    Raises:
        HTTPException: If refresh token is invalid or expired
    """
    try:
        logger.info(
            "Session refresh attempt", refresh_token=request.refresh_token[:8] + "..."
        )

        new_session = refresh_user_session(request.refresh_token)
        if not new_session:
            raise RefreshTokenInvalidError("Invalid or expired refresh token")

        # Calculate expiration times
        expires_in = new_session.time_until_expiry()
        refresh_expires_in = (
            int(
                (
                    new_session.refresh_expires_at - datetime.now(timezone.utc)
                ).total_seconds()
            )
            if new_session.refresh_expires_at
            else 0
        )

        logger.info(
            "Session refresh successful",
            user_id=new_session.user_id,
            new_session_id=new_session.session_id[:8] + "...",
        )

        return AuthResponse(
            access_token=new_session.session_id,
            refresh_token=new_session.refresh_token or "",
            token_type="bearer",
            expires_in=expires_in,
            refresh_expires_in=refresh_expires_in,
            access_token_expires_at=new_session.expires_at.isoformat(),
            refresh_token_expires_at=(
                new_session.refresh_expires_at.isoformat()
                if new_session.refresh_expires_at
                else ""
            ),
            user={
                "user_id": new_session.user_id,
                "email": new_session.email,
                "full_name": new_session.full_name,
                "username": new_session.username,
                "role": new_session.role,
                "org_id": new_session.org_id,
                "session_id": new_session.session_id,
            },
        )

    except (RefreshTokenExpiredError, RefreshTokenInvalidError):
        raise
    except Exception as e:
        logger.error("Session refresh error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Session refresh failed",
        )


@router.get(
    "/debug/session-info",
    summary="Session diagnostics",
    description="Debugging endpoint for session validation issues. Use for troubleshooting authentication problems.",
    include_in_schema=False,  # Hide from public API docs for security
)
async def debug_session_info(
    current_user: Dict[str, Any] = Depends(get_current_user_dict),
) -> Dict[str, Any]:
    """
    Session diagnostics endpoint for debugging authentication issues.

    This endpoint provides detailed information about session validation
    without performing actual operations. Useful for troubleshooting.

    Args:
        current_user: Current user info from session validation

    Returns:
        Detailed session diagnostic information

    Raises:
        HTTPException: If session cannot be analyzed
    """
    try:
        from app.core.simple_auth import validate_user_session, simple_auth_manager

        logger.info("SESSION DIAGNOSTICS requested")

        session_id = current_user.get("session_id")
        user_id = current_user.get("user_id")
        org_id = current_user.get("org_id")

        diagnostic_info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id_length": len(session_id) if session_id else 0,
            "session_id_prefix": session_id[:20] + "..." if session_id else "N/A",
            "validation_steps": {},
        }

        # Step 1: Session structure validation
        if session_id:
            try:
                # Check if it's a valid UUID format
                import uuid

                uuid.UUID(session_id)
                diagnostic_info["validation_steps"]["session_structure"] = {
                    "status": "valid",
                    "format": "UUID",
                    "session_id": session_id[:8] + "..." if session_id else "N/A",
                }
            except ValueError:
                diagnostic_info["validation_steps"]["session_structure"] = {
                    "status": "invalid",
                    "format": "non-UUID",
                    "error": "Session ID is not a valid UUID",
                }
        else:
            diagnostic_info["validation_steps"]["session_structure"] = {
                "status": "missing",
                "error": "No session ID found",
            }

        # Step 2: Session validation
        if session_id:
            try:
                validation_info = validate_user_session(session_id)
                if validation_info:
                    diagnostic_info["validation_steps"]["session_validation"] = {
                        "status": "valid",
                        "expires_at": validation_info["expires_at"],
                        "time_remaining": validation_info["time_remaining"],
                        "in_grace_period": validation_info["in_grace_period"],
                        "can_refresh": validation_info["can_refresh"],
                    }
                else:
                    diagnostic_info["validation_steps"]["session_validation"] = {
                        "status": "invalid",
                        "reason": "session_not_found_or_expired",
                    }
            except Exception as e:
                diagnostic_info["validation_steps"]["session_validation"] = {
                    "status": "error",
                    "error": str(e),
                }

        # Step 3: Session registry check
        try:
            with simple_auth_manager._lock:
                session_exists = (
                    session_id in simple_auth_manager._sessions if session_id else False
                )
                active_session_count = simple_auth_manager.get_active_session_count()
                user_session_count = (
                    simple_auth_manager.get_user_session_count(user_id, org_id)
                    if user_id and org_id
                    else 0
                )

                diagnostic_info["validation_steps"]["session_registry"] = {
                    "status": "tracked" if session_exists else "not_tracked",
                    "session_in_registry": session_exists,
                    "total_active_sessions": active_session_count,
                    "user_active_sessions": user_session_count,
                }

                if session_exists and session_id:
                    session = simple_auth_manager._sessions[session_id]
                    diagnostic_info["session_details"] = {
                        "user_id": session.user_id,
                        "org_id": session.org_id,
                        "email": session.email,
                        "role": session.role,
                        "created_at": session.created_at.isoformat(),
                        "last_used": session.last_used.isoformat(),
                        "expires_at": session.expires_at.isoformat(),
                        "has_refresh_token": session.refresh_token is not None,
                        "refresh_expires_at": (
                            session.refresh_expires_at.isoformat()
                            if session.refresh_expires_at
                            else None
                        ),
                    }

        except Exception as e:
            diagnostic_info["validation_steps"]["session_registry"] = {
                "status": "error",
                "error": str(e),
            }

        # Step 4: Configuration info
        diagnostic_info["system_configuration"] = {
            "session_duration_hours": settings.SESSION_DURATION_HOURS,
            "refresh_session_duration_days": settings.REFRESH_SESSION_DURATION_DAYS,
            "token_grace_period_minutes": settings.TOKEN_GRACE_PERIOD_MINUTES,
            "max_concurrent_sessions": settings.MAX_CONCURRENT_SESSIONS,
            "environment": settings.ENVIRONMENT,
        }

        logger.info(
            "SESSION DIAGNOSTICS completed",
            session_id=session_id[:8] + "..." if session_id else "N/A",
            user_id=user_id,
            validation_status=all(
                step.get("status") in ["valid", "tracked", "not_tracked"]
                for step in diagnostic_info["validation_steps"].values()
            ),
        )

        return diagnostic_info

    except Exception as e:
        logger.error("Session diagnostics error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Session diagnostics failed",
        )
