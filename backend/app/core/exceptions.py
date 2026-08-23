"""
PatchForge AI - Domain Exceptions & Error Handlers
=================================================
Centralized error hierarchy and FastAPI exception handlers ensuring
uniform, secure, and sanitized error responses.
"""

from typing import Any, Dict, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse
from app.core.logging import get_logger, request_id_ctx

logger = get_logger("patchforge.exceptions")


class PatchForgeException(Exception):
    """Base exception for all PatchForge domain errors."""

    def __init__(self, message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class EntityNotFoundException(PatchForgeException):
    def __init__(self, entity_name: str, entity_id: Any):
        super().__init__(
            message=f"{entity_name} with id '{entity_id}' was not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            details={"entity_name": entity_name, "entity_id": str(entity_id)}
        )


class AuthenticationException(PatchForgeException):
    def __init__(self, message: str = "Authentication failed or token invalid."):
        super().__init__(message=message, status_code=status.HTTP_401_UNAUTHORIZED)


class AuthorizationException(PatchForgeException):
    def __init__(self, message: str = "Permission denied for the requested resource."):
        super().__init__(message=message, status_code=status.HTTP_403_FORBIDDEN)


class ScannerException(PatchForgeException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message=f"Scanner error: {message}", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, details=details)


class SandboxException(PatchForgeException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message=f"Sandbox error: {message}", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, details=details)


class LLMException(PatchForgeException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message=f"LLM inference error: {message}", status_code=status.HTTP_502_BAD_GATEWAY, details=details)


class PatchValidationException(PatchForgeException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message=f"Patch validation failed: {message}", status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, details=details)


class WebhookSignatureException(PatchForgeException):
    def __init__(self, message: str = "Invalid GitHub webhook signature."):
        super().__init__(message=message, status_code=status.HTTP_401_UNAUTHORIZED)


async def patchforge_exception_handler(request: Request, exc: PatchForgeException) -> JSONResponse:
    """Handles domain-specific PatchForge exceptions."""
    req_id = request_id_ctx.get()
    logger.warning(f"Handled PatchForge exception [{exc.__class__.__name__}]: {exc.message}")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "type": exc.__class__.__name__,
            "message": exc.message,
            "details": exc.details,
            "request_id": req_id,
        }
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catches unhandled errors, logs traceback, and returns sanitized response."""
    req_id = request_id_ctx.get()
    logger.exception(f"Unhandled internal server error on {request.method} {request.url.path}: {str(exc)}")

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": True,
            "type": "InternalServerError",
            "message": "An unexpected internal server error occurred. Please contact system administrator.",
            "request_id": req_id,
        }
    )
