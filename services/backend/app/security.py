"""
Analytical-Intelligence v1 - Security Utilities
"""

from fastapi import Header, HTTPException, status, Depends
from app.config import settings


async def verify_api_key(ingest_api_key: str = Header(..., alias="INGEST_API_KEY")) -> str:
    """
    Verify the API key from the INGEST_API_KEY header.
    Returns the key if valid, raises 401 if not.
    """
    if ingest_api_key != settings.ingest_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "API-Key"},
        )
    return ingest_api_key


# Dependency for protected routes
api_key_dependency = Depends(verify_api_key)
