"""
Analytical-Intelligence v1 - Security Utilities
"""

from fastapi import HTTPException, status, Depends
from fastapi.security import APIKeyHeader
from app.config import settings

# OpenAPI-aware header scheme – shows "Authorize" lock icon in Swagger UI
_api_key_header = APIKeyHeader(
    name="INGEST_API_KEY",
    description="API key required for all ingestion endpoints. "
                "Set via the INGEST_API_KEY environment variable.",
    auto_error=False,
)


async def verify_api_key(api_key: str | None = Depends(_api_key_header)) -> str:
    """
    Verify the API key from the INGEST_API_KEY header.
    Returns the key if valid, raises 401 if not.
    """
    if not api_key or api_key != settings.ingest_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "API-Key"},
        )
    return api_key


# Dependency for protected routes
api_key_dependency = Depends(verify_api_key)
