"""Invitation management endpoints.

Provides:
- /invite - Create invitation token for new users
"""

from fastapi import APIRouter, HTTPException, status

from app.core.logging import get_service_logger
from app.models.user import UserRole
from app.services.auth_service import auth_service, InvitationError
from app.models.schemas.auth import InvitationTokenResponse

logger = get_service_logger("auth_api")

router = APIRouter()


@router.post(
    "/invite",
    response_model=InvitationTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create invitation token",
    operation_id="createInvitation",
    description="Create an invitation token for a new user to join the organization. Requires admin or user permissions.",
)
async def create_invitation(
    org_id: str,
    email: str,
    role: UserRole = UserRole.USER,
    expires_hours: int = 168,  # 7 days default
) -> InvitationTokenResponse:
    """
    Create an invitation token for a new user.

    Note: This endpoint will need authentication middleware added later.
    For now, it's a basic implementation.

    Args:
        org_id: Organization ID
        email: Email address to invite
        role: Role to assign to the invited user
        expires_hours: Token expiration in hours

    Returns:
        Invitation token response

    Raises:
        HTTPException: If invitation creation fails
    """
    try:
        logger.info("Creating invitation", org_id=org_id, email=email, role=role.value)

        invitation_token = await auth_service.create_invitation_token(
            org_id=org_id, email=email, role=role, expires_hours=expires_hours
        )

        logger.info("Invitation created successfully", org_id=org_id, email=email)

        return InvitationTokenResponse(
            invitation_token=invitation_token, expires_in_hours=expires_hours
        )

    except InvitationError as e:
        logger.warning(
            "Invitation creation failed", org_id=org_id, email=email, error=str(e)
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(
            "Invitation creation error", org_id=org_id, email=email, error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invitation creation failed due to server error",
        )
