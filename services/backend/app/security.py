"""
Mini-SIEM v1 - Security Utilities
"""

from fastapi import Header, HTTPException, status, Depends
from app.config import settings


async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    """
    Verify the API key from the X-API-Key header.
    Returns the key if valid, raises 401 if not.
    """
    if x_api_key != settings.ingest_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "API-Key"},
        )
    return x_api_key


# Dependency for protected routes
api_key_dependency = Depends(verify_api_key)
