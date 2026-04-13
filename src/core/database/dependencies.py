"""
FastAPI Database Dependencies and Error Handling

Provides comprehensive dependency injection for database operations,
authentication, and error handling in FastAPI applications.
"""

import logging
from typing import Optional, Dict, Any, Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from .session import get_db_session, get_read_only_db_session
from .repositories import RepositoryFactory, get_repository_factory
from .services import DatabaseServiceFactory, get_database_services
from .models import User
from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Security scheme
security = HTTPBearer(auto_error=False)


class DatabaseException(Exception):
    """Custom exception for database operations."""
    
    def __init__(self, message: str, error_code: str = "DATABASE_ERROR", 
                 status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(self.message)


class AuthenticationException(Exception):
    """Custom exception for authentication failures."""
    
    def __init__(self, message: str = "Authentication failed", 
                 error_code: str = "AUTH_FAILED",
                 status_code: int = status.HTTP_401_UNAUTHORIZED):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(self.message)


class AuthorizationException(Exception):
    """Custom exception for authorization failures."""
    
    def __init__(self, message: str = "Access denied", 
                 error_code: str = "ACCESS_DENIED",
                 status_code: int = status.HTTP_403_FORBIDDEN):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(self.message)


# Database Dependencies
def get_db() -> Session:
    """
    Get database session dependency.
    
    Usage:
        @app.get("/items/")
        def get_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    return get_db_session()


def get_read_only_db() -> Session:
    """
    Get read-only database session dependency.
    
    Usage:
        @app.get("/items/{item_id}")
        def get_item(item_id: int, db: Session = Depends(get_read_only_db)):
            return db.query(Item).filter(Item.id == item_id).first()
    """
    return get_read_only_db_session()


def get_repositories(db: Session = Depends(get_db)) -> RepositoryFactory:
    """
    Get repository factory dependency.
    
    Usage:
        @app.get("/users/")
        def get_users(repos: RepositoryFactory = Depends(get_repositories)):
            return repos.get_user_repository().get_all()
    """
    return RepositoryFactory(db)


def get_services(db: Session = Depends(get_db)) -> DatabaseServiceFactory:
    """
    Get service factory dependency.
    
    Usage:
        @app.post("/users/")
        def create_user(user_data: dict, services: DatabaseServiceFactory = Depends(get_services)):
            return services.get_user_service().create_user_account(**user_data)
    """
    return DatabaseServiceFactory(db)


# Authentication Dependencies
def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    services: DatabaseServiceFactory = Depends(get_services)
) -> Optional[Dict[str, Any]]:
    """
    Get current user from token (optional - doesn't raise if no token).
    
    Usage:
        @app.get("/profile/")
        def get_profile(user: Optional[Dict] = Depends(get_current_user_optional)):
            if user:
                return {"message": f"Hello {user['username']}"}
            return {"message": "Hello anonymous user"}
    """
    if not credentials:
        return None
    
    try:
        user_service = services.get_user_service()
        user_info = user_service.validate_session(credentials.credentials)
        
        if user_info:
            logger.debug(f"User authenticated: {user_info['username']}")
        
        return user_info
    
    except Exception as e:
        logger.warning(f"Token validation failed: {e}")
        return None


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    services: DatabaseServiceFactory = Depends(get_services)
) -> Dict[str, Any]:
    """
    Get current user from token (required - raises if no valid token).
    
    Usage:
        @app.get("/protected/")
        def protected_endpoint(user: Dict = Depends(get_current_user)):
            return {"message": f"Hello {user['username']}"}
    """
    if not credentials:
        raise AuthenticationException("Authentication token required")
    
    try:
        user_service = services.get_user_service()
        user_info = user_service.validate_session(credentials.credentials)
        
        if not user_info:
            raise AuthenticationException("Invalid or expired token")
        
        logger.debug(f"User authenticated: {user_info['username']}")
        return user_info
    
    except AuthenticationException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise AuthenticationException("Authentication failed")


def get_admin_user(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get current user with admin role requirement.
    
    Usage:
        @app.delete("/users/{user_id}")
        def delete_user(user_id: str, admin: Dict = Depends(get_admin_user)):
            # Only admins can delete users
            pass
    """
    if current_user.get("role") != "admin":
        raise AuthorizationException("Admin privileges required")
    
    return current_user


def require_roles(*required_roles: str):
    """
    Factory function to create role-based authorization dependency.
    
    Usage:
        @app.post("/policies/")
        def create_policy(
            policy_data: dict,
            user: Dict = Depends(require_roles("admin", "policy_manager"))
        ):
            # Only admins and policy managers can create policies
            pass
    """
    def role_dependency(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = current_user.get("role")
        if user_role not in required_roles:
            raise AuthorizationException(
                f"One of the following roles required: {', '.join(required_roles)}"
            )
        return current_user
    
    return role_dependency


# Request Context Dependencies
def get_client_ip(request: Request) -> str:
    """
    Get client IP address from request.
    
    Usage:
        @app.post("/login/")
        def login(credentials: dict, ip: str = Depends(get_client_ip)):
            # Use IP for audit logging
            pass
    """
    # Check for forwarded headers first
    if "x-forwarded-for" in request.headers:
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    elif "x-real-ip" in request.headers:
        return request.headers["x-real-ip"]
    else:
        return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    """
    Get user agent from request.
    
    Usage:
        @app.post("/login/")
        def login(credentials: dict, user_agent: str = Depends(get_user_agent)):
            # Use user agent for session tracking
            pass
    """
    return request.headers.get("user-agent", "unknown")


# Audit Logging Dependency
def audit_request(
    request: Request,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional),
    services: DatabaseServiceFactory = Depends(get_services)
):
    """
    Dependency for automatic audit logging of API requests.
    
    Usage:
        @app.post("/documents/", dependencies=[Depends(audit_request)])
        def upload_document(document_data: dict):
            # Request will be automatically audited
            pass
    """
    try:
        audit_service = services.get_audit_service()
        
        user_id = UUID(current_user["user_id"]) if current_user else None
        ip_address = get_client_ip(request)
        
        audit_service.log_user_activity(
            user_id=user_id,
            activity_type="api_request",
            description=f"{request.method} {request.url.path}",
            metadata={
                "method": request.method,
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "user_agent": get_user_agent(request)
            },
            ip_address=ip_address
        )
    except Exception as e:
        logger.warning(f"Audit logging failed: {e}")


# Validation Dependencies
def validate_uuid(uuid_string: str) -> UUID:
    """
    Validate and convert UUID string parameter.
    
    Usage:
        @app.get("/users/{user_id}")
        def get_user(user_id: UUID = Depends(validate_uuid)):
            # user_id is guaranteed to be a valid UUID
            pass
    """
    try:
        return UUID(uuid_string)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid UUID format"
        )


def validate_pagination(
    page: int = 1,
    size: int = 10,
    max_size: int = 100
) -> Dict[str, int]:
    """
    Validate pagination parameters.
    
    Usage:
        @app.get("/users/")
        def get_users(pagination: Dict = Depends(validate_pagination)):
            offset = (pagination['page'] - 1) * pagination['size']
            limit = pagination['size']
            return get_users_with_pagination(offset, limit)
    """
    if page < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Page number must be >= 1"
        )
    
    if size < 1 or size > max_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Page size must be between 1 and {max_size}"
        )
    
    return {
        "page": page,
        "size": size,
        "offset": (page - 1) * size,
        "limit": size
    }


# Error Handling
def handle_database_errors(func):
    """
    Decorator to handle database errors consistently.
    
    Usage:
        @handle_database_errors
        def some_database_operation():
            # Database operations that might fail
            pass
    """
    from functools import wraps
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        
        except IntegrityError as e:
            logger.error(f"Database integrity error: {e}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Data integrity constraint violated"
            )
        
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database operation failed"
            )
        
        except DatabaseException as e:
            logger.error(f"Custom database error: {e}")
            raise HTTPException(
                status_code=e.status_code,
                detail={
                    "message": e.message,
                    "error_code": e.error_code
                }
            )
        
        except AuthenticationException as e:
            logger.warning(f"Authentication error: {e}")
            raise HTTPException(
                status_code=e.status_code,
                detail={
                    "message": e.message,
                    "error_code": e.error_code
                }
            )
        
        except AuthorizationException as e:
            logger.warning(f"Authorization error: {e}")
            raise HTTPException(
                status_code=e.status_code,
                detail={
                    "message": e.message,
                    "error_code": e.error_code
                }
            )
    
    return wrapper


# Health Check Dependencies
def check_database_health(
    repos: RepositoryFactory = Depends(get_repositories)
) -> Dict[str, Any]:
    """
    Dependency for checking database health.
    
    Usage:
        @app.get("/health/database")
        def database_health(health: Dict = Depends(check_database_health)):
            return health
    """
    try:
        # Simple database query to test connectivity
        repos.session.execute("SELECT 1")
        
        return {
            "status": "healthy",
            "timestamp": "2024-01-01T00:00:00Z",  # Should use actual timestamp
            "message": "Database is accessible"
        }
    
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": "2024-01-01T00:00:00Z",  # Should use actual timestamp
            "message": f"Database error: {str(e)}"
        }


# Typed Dependencies (Python 3.9+)
DatabaseSession = Annotated[Session, Depends(get_db)]
ReadOnlySession = Annotated[Session, Depends(get_read_only_db)]
Repositories = Annotated[RepositoryFactory, Depends(get_repositories)]
Services = Annotated[DatabaseServiceFactory, Depends(get_services)]
CurrentUser = Annotated[Dict[str, Any], Depends(get_current_user)]
OptionalUser = Annotated[Optional[Dict[str, Any]], Depends(get_current_user_optional)]
AdminUser = Annotated[Dict[str, Any], Depends(get_admin_user)]
ClientIP = Annotated[str, Depends(get_client_ip)]
UserAgent = Annotated[str, Depends(get_user_agent)]
Pagination = Annotated[Dict[str, int], Depends(validate_pagination)]