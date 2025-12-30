"""Authentication API package.

This package provides all authentication-related endpoints:
- Login, logout, and registration (login.py)
- Token management and validation (tokens.py)
- Organization lookup for registration (organizations.py)
- Invitation management (invitations.py)

Usage:
    from app.api.v1.auth import router
"""

from fastapi import APIRouter

from .login import router as login_router
from .tokens import router as tokens_router
from .organizations import router as organizations_router
from .invitations import router as invitations_router

# Create main router that includes all sub-routers
router = APIRouter()

# Include all sub-routers
router.include_router(login_router)
router.include_router(tokens_router)
router.include_router(organizations_router)
router.include_router(invitations_router)

__all__ = ["router"]
