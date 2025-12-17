from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app import get_settings
from app.api import api_router
from app.core.logging import logger, log_security_event
from app.core.middleware import CSRFMiddleware, SecurityHeadersMiddleware
from app.core.rate_limit import limiter


settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


# CORS – strict, origin-based
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", settings.CSRF_HEADER_NAME],
)


# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
app.add_middleware(SlowAPIMiddleware)


# Security headers and CSRF protection
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CSRFMiddleware)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning("validation_error", errors=exc.errors())
    log_security_event(
        "validation_failed",
        ip=str(request.client.host) if request.client else None,
        path=request.url.path,
    )
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request payload."},
    )


@app.middleware("http")
async def add_secure_error_handling(request: Request, call_next):
    try:
        response = await call_next(request)
        return response
    except Exception:  # pragma: no cover - generic safety net
        logger.exception("unhandled_error")
        return JSONResponse(
            status_code=500,
            content={"detail": "An error occurred."},
        )


@app.get("/healthz", tags=["health"])
async def healthcheck():
    return {"status": "ok"}


app.include_router(api_router)



