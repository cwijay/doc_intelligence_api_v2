"""OpenAPI schema customization.

Provides custom OpenAPI schema with:
- Security schemes
- Tag descriptions
- Example responses for all endpoints
"""

from typing import Dict, Any
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi


def create_custom_openapi(app: FastAPI) -> Dict[str, Any]:
    """Create custom OpenAPI schema with authentication and examples.

    Args:
        app: FastAPI application instance

    Returns:
        Customized OpenAPI schema dictionary
    """
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        servers=app.servers,
        tags=get_tag_descriptions(),
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "SessionAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "UUID",
            "description": "Session-based authentication using UUID tokens. Format: `Bearer <uuid>`. Tokens expire after 24 hours.",
        }
    }

    # Add examples to components
    openapi_schema["components"]["examples"] = get_openapi_examples()

    app.openapi_schema = openapi_schema
    return app.openapi_schema


def get_tag_descriptions() -> list:
    """Get OpenAPI tag descriptions."""
    return [
        {
            "name": "Authentication",
            "description": """Session-based JWT authentication with refresh tokens.

**Key Features:**
- UUID-based session tokens (24-hour expiration)
- Automatic token rotation on refresh
- Grace period for seamless token refresh
- Multi-device session management

**Endpoints:** login, register, logout, refresh, validate""",
        },
        {
            "name": "Documents",
            "description": """Document upload, storage, and management.

**Supported Formats:** PDF, XLSX, CSV, JPEG, PNG, DOCX, DOC, PPTX, PPT, TXT, GIF, WEBP, TIFF
**Max File Size:** 50MB
**Storage:** Google Cloud Storage with signed URLs

**Key Features:**
- Target path control for precise storage location
- Folder-based organization (legacy support)
- Signed download URLs with configurable expiration
- Document status tracking (uploading → uploaded → parsing → parsed)""",
        },
        {
            "name": "Organizations",
            "description": """Multi-tenant organization management.

**Plan Types:** FREE, STARTER, PRO
**Features:** Domain configuration, settings management, user quotas

**Key Operations:** Create, update, delete, list organizations""",
        },
        {
            "name": "Users",
            "description": """User management and profiles.

**Roles:** admin, user
**Features:** User CRUD, role management, organization membership

**Key Operations:** Create, update, delete, list users within organizations""",
        },
        {
            "name": "Folders",
            "description": """Document organization and folder management.

**Features:** Hierarchical folder structure, folder statistics, tree view

**Key Operations:** Create, update, delete, list folders, get folder tree""",
        },
        {
            "name": "Audit",
            "description": """Audit logging and activity tracking.

**Tracked Events:** CREATE, UPDATE, DELETE, LOGIN, LOGOUT, UPLOAD, DOWNLOAD, MOVE
**Entity Types:** ORGANIZATION, USER, FOLDER, DOCUMENT

**Access Control:** Admins see all logs, users see only their activity""",
        },
        {
            "name": "Health",
            "description": """API health checks and status monitoring.

**Endpoints:**
- `/health` - Basic health check
- `/status` - Detailed service status
- `/ready` - Kubernetes readiness probe
- `/live` - Kubernetes liveness probe""",
        },
    ]


def get_openapi_examples() -> Dict[str, Any]:
    """Get OpenAPI example responses."""
    return {
        # Authentication Examples
        "LoginRequest": {
            "summary": "Login request",
            "value": {"email": "user@example.com", "password": "Password123!"},
        },
        "RegisterRequest": {
            "summary": "Registration request",
            "value": {
                "email": "user@example.com",
                "password": "Password123!",
                "full_name": "John Doe",
                "username": "johndoe",
                "organization_id": "oJIChgDgktkF30dAPy2c",
            },
        },
        "AuthResponse": {
            "summary": "Authentication response",
            "value": {
                "access_token": "b9a85c75-15de-4a7b-b278-651eaf42383f",
                "refresh_token": "b9a85c75-15de-4a7b-b278-651eaf42383f",
                "token_type": "bearer",
                "expires_in": 86400,
                "refresh_expires_in": 86400,
                "access_token_expires_at": "2025-08-16T10:12:27.931957",
                "refresh_token_expires_at": "2025-08-16T10:12:27.931957",
                "user": {
                    "user_id": "jhYXgm0s4avwacnBSXH9",
                    "email": "user@example.com",
                    "full_name": "John Doe",
                    "username": "johndoe",
                    "role": "user",
                    "org_id": "oJIChgDgktkF30dAPy2c",
                    "org_name": "Google",
                    "session_id": "b9a85c75-15de-4a7b-b278-651eaf42383f",
                },
            },
        },
        # User Examples
        "UserResponse": {
            "summary": "User response",
            "value": {
                "id": "jhYXgm0s4avwacnBSXH9",
                "email": "john.doe@example.com",
                "username": "johndoe",
                "full_name": "John Doe",
                "role": "user",
                "org_id": "oJIChgDgktkF30dAPy2c",
                "is_active": True,
                "created_at": "2025-08-15T10:12:36.993659",
                "updated_at": "2025-08-15T10:12:36.993662",
            },
        },
        "UserList": {
            "summary": "Users list with pagination",
            "value": {
                "users": [
                    {
                        "id": "jhYXgm0s4avwacnBSXH9",
                        "email": "john.doe@example.com",
                        "username": "johndoe",
                        "full_name": "John Doe",
                        "role": "user",
                        "org_id": "oJIChgDgktkF30dAPy2c",
                        "is_active": True,
                    }
                ],
                "total": 25,
                "page": 1,
                "per_page": 20,
                "total_pages": 2,
            },
        },
        # Organization Examples
        "OrganizationResponse": {
            "summary": "Organization response",
            "value": {
                "id": "oJIChgDgktkF30dAPy2c",
                "name": "Acme Corporation",
                "domain": "acme.com",
                "settings": {"timezone": "America/New_York", "default_language": "en"},
                "plan_type": "starter",
                "is_active": True,
                "created_at": "2025-08-15T05:31:35.921520",
                "updated_at": "2025-08-15T05:31:35.921523",
            },
        },
        "OrganizationList": {
            "summary": "Organizations list with pagination",
            "value": {
                "organizations": [
                    {
                        "id": "oJIChgDgktkF30dAPy2c",
                        "name": "Acme Corporation",
                        "domain": "acme.com",
                        "plan_type": "starter",
                        "is_active": True,
                    }
                ],
                "total": 10,
                "page": 1,
                "per_page": 20,
                "total_pages": 1,
            },
        },
        # Folder Examples
        "FolderResponse": {
            "summary": "Folder response",
            "value": {
                "id": "folder_xyz789",
                "name": "invoices",
                "path": "/invoices",
                "parent_id": None,
                "org_id": "oJIChgDgktkF30dAPy2c",
                "depth": 0,
                "is_active": True,
                "created_at": "2025-08-15T10:12:36.993659",
                "updated_at": "2025-08-15T10:12:36.993662",
            },
        },
        "FolderTree": {
            "summary": "Folder tree structure",
            "value": {
                "id": "root_folder",
                "name": "Root",
                "path": "/",
                "children": [
                    {
                        "id": "folder_invoices",
                        "name": "invoices",
                        "path": "/invoices",
                        "children": [
                            {
                                "id": "folder_2025",
                                "name": "2025",
                                "path": "/invoices/2025",
                                "children": [],
                            }
                        ],
                    },
                    {
                        "id": "folder_contracts",
                        "name": "contracts",
                        "path": "/contracts",
                        "children": [],
                    },
                ],
            },
        },
        # Document Examples
        "DocumentUpload": {
            "summary": "Document upload response",
            "value": {
                "success": True,
                "message": "Document uploaded successfully",
                "document": {
                    "id": "78258b82-db53-41a3-848a-ce45a32f99c7",
                    "filename": "invoice-2025-001.pdf",
                    "file_type": "pdf",
                    "file_size": 1024567,
                    "status": "uploading",
                    "storage_path": "Google/original/invoices/invoice-2025-001.pdf",
                    "org_id": "oJIChgDgktkF30dAPy2c",
                    "uploaded_by": "jhYXgm0s4avwacnBSXH9",
                    "created_at": "2025-08-15T10:12:36.993659",
                },
                "upload_time_ms": 234,
            },
        },
        "DocumentResponse": {
            "summary": "Document details",
            "value": {
                "id": "78258b82-db53-41a3-848a-ce45a32f99c7",
                "filename": "invoice-2025-001.pdf",
                "original_filename": "invoice-2025-001.pdf",
                "file_type": "pdf",
                "file_size": 1024567,
                "storage_path": "Google/original/invoices/invoice-2025-001.pdf",
                "status": "uploaded",
                "metadata": {"category": "invoice", "vendor": "Acme Corp"},
                "org_id": "oJIChgDgktkF30dAPy2c",
                "uploaded_by": "jhYXgm0s4avwacnBSXH9",
                "is_active": True,
                "created_at": "2025-08-15T10:12:36.993659",
                "updated_at": "2025-08-15T10:12:36.993662",
            },
        },
        "DocumentList": {
            "summary": "Documents list with pagination",
            "value": {
                "documents": [
                    {
                        "id": "78258b82-db53-41a3-848a-ce45a32f99c7",
                        "filename": "invoice-2025-001.pdf",
                        "file_type": "pdf",
                        "file_size": 1024567,
                        "status": "uploaded",
                        "storage_path": "Google/original/invoices/invoice-2025-001.pdf",
                        "created_at": "2025-08-15T10:12:36.993659",
                    }
                ],
                "total": 45,
                "page": 1,
                "per_page": 10,
                "total_pages": 5,
            },
        },
        "DocumentDownload": {
            "summary": "Document download URL response",
            "value": {
                "success": True,
                "document_id": "78258b82-db53-41a3-848a-ce45a32f99c7",
                "filename": "invoice-2025-001.pdf",
                "download_url": "https://storage.googleapis.com/bucket/path?X-Goog-Algorithm=...",
                "expires_at": "2025-08-15T11:12:36.993659",
                "file_size": 1024567,
                "content_type": "application/pdf",
            },
        },
        # Audit Examples
        "AuditLogEntry": {
            "summary": "Single audit log entry",
            "value": {
                "id": "audit_123",
                "org_id": "oJIChgDgktkF30dAPy2c",
                "action": "UPLOAD",
                "entity_type": "DOCUMENT",
                "entity_id": "78258b82-db53-41a3-848a-ce45a32f99c7",
                "user_id": "jhYXgm0s4avwacnBSXH9",
                "details": {"filename": "invoice.pdf", "file_size": 1024567},
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "created_at": "2025-08-15T10:12:36.993659",
            },
        },
        "AuditLogList": {
            "summary": "Audit logs list with pagination",
            "value": {
                "logs": [
                    {
                        "id": "audit_123",
                        "action": "UPLOAD",
                        "entity_type": "DOCUMENT",
                        "entity_id": "78258b82-db53-41a3-848a-ce45a32f99c7",
                        "user_id": "jhYXgm0s4avwacnBSXH9",
                        "created_at": "2025-08-15T10:12:36.993659",
                    }
                ],
                "total": 150,
                "page": 1,
                "per_page": 50,
                "total_pages": 3,
            },
        },
        # Error Examples
        "NotFoundError": {
            "summary": "Resource not found error",
            "value": {
                "detail": "Document with ID '78258b82-db53-41a3-848a-ce45a32f99c7' not found"
            },
        },
        "ValidationError": {
            "summary": "Validation error",
            "value": {
                "detail": [
                    {
                        "loc": ["body", "email"],
                        "msg": "value is not a valid email address",
                        "type": "value_error.email",
                    }
                ]
            },
        },
        "ConflictError": {
            "summary": "Conflict error (duplicate resource)",
            "value": {"detail": "User with this email already exists in this organization"},
        },
        "UnauthorizedError": {
            "summary": "Unauthorized error",
            "value": {"detail": "Invalid or expired session token"},
        },
        "ForbiddenError": {
            "summary": "Forbidden error",
            "value": {"detail": "Admin access required to perform this operation"},
        },
        "ErrorResponse": {
            "summary": "Structured error response",
            "value": {
                "error": {
                    "code": "TOKEN_EXPIRED",
                    "message": "Access token has expired",
                    "error_id": "abc123-unique-id",
                    "details": {
                        "expired_at": "2025-08-17T08:00:00Z",
                        "action": "refresh_token_or_relogin",
                    },
                }
            },
        },
    }
