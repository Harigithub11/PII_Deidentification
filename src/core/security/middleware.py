"""
Security Middleware for FastAPI Application

Provides CORS, rate limiting, security headers, and request logging.
"""

import time
from typing import Dict, Callable
from collections import defaultdict

from fastapi import Request, Response, HTTPException, status
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from ..config.settings import get_settings

settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Check if request is HTTPS
        is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        
        # Core security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # HTTPS-specific headers
        if is_https:
            # Strict Transport Security - only for HTTPS
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
            
            # Content Security Policy with HTTPS requirements
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self' https:; "
                "media-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "upgrade-insecure-requests"
            )
        else:
            # Less strict CSP for HTTP (development)
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: http: https:; "
                "font-src 'self' data:; "
                "connect-src 'self' http: https:; "
                "media-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )
        
        response.headers["Content-Security-Policy"] = csp
        
        # Additional security headers
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
        
        # Remove server information headers
        response.headers.pop("server", None)
        response.headers.pop("x-powered-by", None)
        
        # Add custom security header for encrypted data handling
        if is_https:
            response.headers["X-Encryption-Status"] = "data-in-transit-encrypted"
        else:
            response.headers["X-Encryption-Warning"] = "data-in-transit-not-encrypted"
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Global rate limiting middleware."""
    
    def __init__(self, app, calls_per_minute: int = 60, burst_limit: int = 10):
        super().__init__(app)
        self.calls_per_minute = calls_per_minute
        self.burst_limit = burst_limit
        self.clients = defaultdict(list)
        self.burst_clients = defaultdict(int)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/api/v1/auth/health"]:
            return await call_next(request)
        
        client_ip = self.get_client_ip(request)
        current_time = time.time()
        
        # Clean old requests (older than 1 minute)
        self.clients[client_ip] = [
            req_time for req_time in self.clients[client_ip]
            if current_time - req_time < 60
        ]
        
        # Check burst limit (requests in last 10 seconds)
        recent_requests = [
            req_time for req_time in self.clients[client_ip]
            if current_time - req_time < 10
        ]
        
        if len(recent_requests) > self.burst_limit:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests in a short time. Please try again later."
                }
            )
        
        # Check per-minute limit
        if len(self.clients[client_ip]) >= self.calls_per_minute:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Maximum {self.calls_per_minute} requests per minute exceeded."
                }
            )
        
        # Record this request
        self.clients[client_ip].append(current_time)
        
        return await call_next(request)
    
    def get_client_ip(self, request: Request) -> str:
        """Get client IP address, considering proxy headers."""
        # Check for forwarded IP headers (for load balancers/proxies)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests for security monitoring."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        # Log request details
        client_ip = self.get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            
            # Log successful request
            self.log_request(
                request,
                response.status_code,
                process_time,
                client_ip,
                user_agent
            )
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            
            # Log failed request
            self.log_request(
                request,
                500,
                process_time,
                client_ip,
                user_agent,
                error=str(e)
            )
            
            raise
    
    def get_client_ip(self, request: Request) -> str:
        """Get client IP address, considering proxy headers."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host
    
    def log_request(
        self,
        request: Request,
        status_code: int,
        process_time: float,
        client_ip: str,
        user_agent: str,
        error: str = None
    ):
        """Log request details."""
        log_data = {
            "timestamp": time.time(),
            "method": request.method,
            "path": str(request.url.path),
            "query_params": str(request.url.query) if request.url.query else None,
            "status_code": status_code,
            "process_time": round(process_time, 4),
            "client_ip": client_ip,
            "user_agent": user_agent,
            "error": error
        }
        
        # In production, send to proper logging system
        print(f"REQUEST LOG: {log_data}")


class ContentSecurityMiddleware(BaseHTTPMiddleware):
    """Content security and validation middleware."""
    
    BLOCKED_USER_AGENTS = [
        "sqlmap", "nikto", "nmap", "masscan", "dirb", "dirbuster",
        "burpsuite", "w3af", "owasp-zap"
    ]
    
    SUSPICIOUS_PATTERNS = [
        "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
        "<script", "javascript:", "onload=", "onerror=",
        "../", "..\\", "/etc/passwd", "web.config"
    ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check user agent for known scanners/bots
        user_agent = request.headers.get("user-agent", "").lower()
        if any(blocked_agent in user_agent for blocked_agent in self.BLOCKED_USER_AGENTS):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access denied"}
            )
        
        # Check for suspicious patterns in URL and headers
        full_url = str(request.url).lower()
        if any(pattern.lower() in full_url for pattern in self.SUSPICIOUS_PATTERNS):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Invalid request"}
            )
        
        # Check request headers for suspicious content
        for header_name, header_value in request.headers.items():
            if any(pattern.lower() in header_value.lower() for pattern in self.SUSPICIOUS_PATTERNS):
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "Invalid request headers"}
                )
        
        return await call_next(request)


def setup_cors_middleware(app):
    """Setup CORS middleware with secure defaults."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=[
            "Accept",
            "Accept-Language", 
            "Content-Language",
            "Content-Type",
            "Authorization",
            "X-Requested-With"
        ],
        expose_headers=["Content-Range", "X-Content-Range"],
        max_age=86400  # 24 hours
    )


def setup_security_middleware(app):
    """Setup all security middleware."""
    # Add middleware in reverse order (last added is executed first)
    
    # Content security (first check)
    app.add_middleware(ContentSecurityMiddleware)
    
    # Rate limiting
    app.add_middleware(RateLimitMiddleware, calls_per_minute=100, burst_limit=20)
    
    # Request logging
    app.add_middleware(RequestLoggingMiddleware)
    
    # Security headers (last, so they're added to all responses)
    app.add_middleware(SecurityHeadersMiddleware)
    
    # CORS (handled separately)
    setup_cors_middleware(app)


class IPWhitelistMiddleware(BaseHTTPMiddleware):
    """IP whitelist middleware for admin endpoints."""
    
    def __init__(self, app, whitelist: list = None, admin_paths: list = None):
        super().__init__(app)
        self.whitelist = whitelist or ["127.0.0.1", "::1"]  # localhost by default
        self.admin_paths = admin_paths or ["/admin", "/api/admin"]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = self.get_client_ip(request)
        request_path = request.url.path
        
        # Check if this is an admin path
        is_admin_path = any(request_path.startswith(admin_path) for admin_path in self.admin_paths)
        
        if is_admin_path and client_ip not in self.whitelist:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Access denied from this IP address"}
            )
        
        return await call_next(request)
    
    def get_client_ip(self, request: Request) -> str:
        """Get client IP address."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host


# Health check for middleware
async def security_health_check():
    """Security middleware health check."""
    return {
        "status": "healthy",
        "middleware": "security",
        "timestamp": time.time(),
        "features": {
            "rate_limiting": True,
            "security_headers": True,
            "request_logging": True,
            "content_security": True,
            "cors": True
        }
    }