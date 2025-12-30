"""Organization lookup endpoints for authentication flow.

Provides:
- /organizations - List organizations for registration
- /organizations/lookup - Search organizations
- /organizations/check-availability/{name} - Check name availability
"""

from typing import Dict, Any, List

from fastapi import APIRouter, HTTPException, status, Query, Path

from app.core.logging import get_service_logger
from app.services.org_service import organization_service
from app.models.schemas import (
    OrganizationResponse,
    PaginationParams,
    OrganizationFilters,
)

logger = get_service_logger("auth_api")

router = APIRouter()


@router.get(
    "/organizations",
    response_model=List[OrganizationResponse],
    status_code=status.HTTP_200_OK,
    summary="List Organizations for Registration",
    operation_id="listOrganizationsForRegistration",
    description="""List all available organizations for user registration selection.

**Usage:**
This endpoint is used during the registration flow to show users
which organizations they can join. No authentication required.

**Response:**
Returns a list of all active organizations with their details.

**Example Response:**
```json
[
  {
    "id": "oJIChgDgktkF30dAPy2c",
    "name": "Google",
    "domain": "google.com",
    "plan_type": "free",
    "is_active": true,
    "created_at": "2025-08-15T05:31:35.921520"
  },
  {
    "id": "GUbmPT49OSDO3eFDU2r5",
    "name": "Tech Innovations Corp",
    "domain": "techinnovations.com",
    "plan_type": "pro",
    "is_active": true,
    "created_at": "2025-08-11T14:08:19.233046"
  }
]
```

**Organization Plan Types:**
- `free`: Free tier with basic features
- `starter`: Starter tier with additional features
- `pro`: Professional tier with all features
""",
    responses={
        200: {
            "description": "List of active organizations",
            "content": {
                "application/json": {
                    "examples": {
                        "organizations_list": {
                            "summary": "Available organizations",
                            "value": [
                                {
                                    "id": "oJIChgDgktkF30dAPy2c",
                                    "name": "Google",
                                    "domain": "google.com",
                                    "settings": {},
                                    "plan_type": "free",
                                    "is_active": True,
                                    "created_at": "2025-08-15T05:31:35.921520",
                                    "updated_at": "2025-08-15T05:31:35.921523",
                                },
                                {
                                    "id": "GUbmPT49OSDO3eFDU2r5",
                                    "name": "Tech Innovations Corp",
                                    "domain": "techinnovations.com",
                                    "settings": {},
                                    "plan_type": "pro",
                                    "is_active": True,
                                    "created_at": "2025-08-11T14:08:19.233046",
                                    "updated_at": "2025-08-11T14:08:19.233057",
                                },
                            ],
                        }
                    }
                }
            },
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {"example": {"detail": "Internal server error"}}
            },
        },
    },
)
async def list_organizations_for_registration() -> List[OrganizationResponse]:
    """
    List all available organizations for registration.

    This endpoint is used during the registration flow to allow users
    to select which organization they want to join.

    Returns:
        List of all active organizations

    Raises:
        HTTPException: If listing fails
    """
    try:
        logger.info("Listing organizations for registration")

        # Get all active organizations with basic pagination
        pagination = PaginationParams(
            page=1, per_page=100
        )  # Get up to 100 orgs for selection
        filters = OrganizationFilters(is_active=True)

        result = await organization_service.list_organizations(pagination, filters)

        logger.info("Organizations listed for registration", count=len(result.items))

        return result.items

    except Exception as e:
        logger.error("Failed to list organizations for registration", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list organizations",
        )


@router.get(
    "/organizations/lookup",
    response_model=List[OrganizationResponse],
    status_code=status.HTTP_200_OK,
    summary="Lookup organizations",
    operation_id="lookupOrganizations",
    description="Search for organizations by name. Used during login to help users find their organization.",
)
async def lookup_organizations(
    query: str = Query(
        "",
        description="Search query for organization name (empty string returns all active organizations)",
    )
) -> List[OrganizationResponse]:
    """
    Lookup organizations by name query.

    This endpoint is used during the authentication flow to help users
    find their organization. It searches for organizations where the name
    contains the query string (case-insensitive partial match).

    Args:
        query: Search query string

    Returns:
        List of matching organizations

    Raises:
        HTTPException: If lookup fails
    """
    try:
        logger.debug("Organization lookup", query=query)

        # Use the organization service to search with name filter
        filters = OrganizationFilters(name=query, is_active=True)
        pagination = PaginationParams(page=1, per_page=20)  # Limit results for lookup

        result = await organization_service.list_organizations(pagination, filters)

        logger.debug(
            "Organization lookup completed", query=query, count=len(result.items)
        )

        return result.items

    except Exception as e:
        logger.error("Organization lookup failed", query=query, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Organization lookup failed due to server error",
        )


@router.get(
    "/organizations/check-availability/{name}",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Check organization name availability",
    operation_id="checkOrganizationAvailability",
    description="Check if an organization name is available for registration.",
)
async def check_organization_availability(
    name: str = Path(..., description="Organization name to check")
) -> Dict[str, Any]:
    """
    Check if an organization name is available for registration.

    This endpoint helps users validate organization names before attempting
    to register, providing better user experience.

    Args:
        name: Organization name to check

    Returns:
        Dictionary with availability status and suggestions

    Raises:
        HTTPException: If check fails
    """
    try:
        logger.debug("Checking organization name availability", name=name)

        # Check if organization exists
        existing_org = await organization_service.get_organization_by_name(name)

        if existing_org:
            # Organization exists - not available
            result = {
                "available": False,
                "name": name,
                "message": f"Organization '{name}' already exists",
                "suggestions": [
                    "Contact an admin of this organization for an invitation",
                    "Choose a different organization name",
                    f"Try variations like '{name} LLC', '{name} Inc', etc.",
                ],
            }
        else:
            # Organization name is available
            result = {
                "available": True,
                "name": name,
                "message": f"Organization name '{name}' is available",
            }

        logger.debug(
            "Organization availability check completed",
            name=name,
            available=result["available"],
        )

        return result

    except Exception as e:
        logger.error("Organization availability check failed", name=name, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Availability check failed due to server error",
        )
