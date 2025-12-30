"""Middleware configuration for FastAPI application.

Provides:
- CORS middleware setup
- Trusted host middleware (production)
- Request timing middleware
"""

import time
from typing import List

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def setup_cors_middleware(app: FastAPI) -> None:
    """Configure CORS middleware with settings from config.

    Args:
        app: FastAPI application instance
    """
    cors_origins = settings.resolved_cors_origins

    logger.info("=" * 80)
    logger.info(
        "CORS CONFIGURATION",
        environment=settings.ENVIRONMENT,
        debug_enabled=settings.ENABLE_CORS_DEBUG,
    )
    logger.info("Allowed CORS Origins:")
    for idx, origin in enumerate(cors_origins, 1):
        logger.info(f"  {idx}. {origin}")
    logger.info("CORS Credentials Enabled: %s", settings.CORS_CREDENTIALS)
    logger.info("CORS Methods: %s", ", ".join(settings.CORS_METHODS))
    logger.info("=" * 80)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=settings.CORS_CREDENTIALS,
        allow_methods=settings.CORS_METHODS,
        allow_headers=settings.CORS_HEADERS,
        expose_headers=["*"],
    )


def setup_trusted_host_middleware(app: FastAPI) -> None:
    """Configure trusted host middleware for production.

    Args:
        app: FastAPI application instance
    """
    if settings.ENVIRONMENT.lower() != "production":
        return

    allowed_hosts: List[str] = list(settings.ALLOWED_HOST_PATTERNS)
    if settings.FRONTEND_DOMAIN:
        allowed_hosts.append(settings.FRONTEND_DOMAIN)
        allowed_hosts.append(f"*.{settings.FRONTEND_DOMAIN}")

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=allowed_hosts,
    )


def setup_timing_middleware(app: FastAPI) -> None:
    """Add request timing middleware.

    Args:
        app: FastAPI application instance
    """

    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        """Add processing time header to responses."""
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(round(process_time, 4))
        return response


def setup_all_middleware(app: FastAPI) -> None:
    """Setup all middleware in correct order.

    CORS must be added first for OPTIONS requests to work correctly.

    Args:
        app: FastAPI application instance
    """
    # CORS must be first
    setup_cors_middleware(app)

    # Trusted hosts (production only)
    setup_trusted_host_middleware(app)

    # Request timing
    setup_timing_middleware(app)
