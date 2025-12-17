from __future__ import annotations

from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.config import get_settings


settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        response = await call_next(request)

        # TLS / transport security – HSTS
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload",
        )

        # Clickjacking protection
        response.headers.setdefault("X-Frame-Options", "DENY")

        # MIME-type sniffing protection
        response.headers.setdefault("X-Content-Type-Options", "nosniff")

        # Basic XSS protection via modern CSP
        # Adjust in production to match asset hosting (CDN, etc.)
        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers.setdefault("Content-Security-Policy", csp)

        # Referrer & feature policies
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        )

        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Double-submit cookie CSRF protection.
    For state-changing requests, require:
      - CSRF cookie present, and
      - Matching header token.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            csrf_cookie = request.cookies.get(settings.CSRF_COOKIE_NAME)
            csrf_header = request.headers.get(settings.CSRF_HEADER_NAME)
            # Only enforce when a session cookie is present (authenticated context)
            session_cookie = request.cookies.get(settings.SESSION_COOKIE_NAME, None)
            if session_cookie and (not csrf_cookie or not csrf_header or csrf_cookie != csrf_header):
                from fastapi import HTTPException, status

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF token invalid or missing",
                )

        response = await call_next(request)
        return response


