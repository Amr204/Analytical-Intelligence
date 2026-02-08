"""
Analytical-Intelligence v1 - Authentication Utilities
Password verification for UI login.
"""

import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def verify_password(password: str, stored_password: str) -> bool:
    """
    Verify a password against stored password.
    
    Supports both:
    - Plain text passwords (for simplicity)
    - Hashed passwords in format: pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
    
    Args:
        password: The plain text password entered by user
        stored_password: The stored password (plain text or hashed)
    
    Returns:
        True if password matches, False otherwise
    """
    # Check if it's a hashed password (starts with pbkdf2_sha256$)
    if stored_password.startswith('pbkdf2_sha256$'):
        try:
            parts = stored_password.split('$')
            if len(parts) != 4:
                return False
            
            iterations = int(parts[1])
            salt = base64.b64decode(parts[2])
            stored_hash_bytes = base64.b64decode(parts[3])
            
            computed_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                iterations
            )
            
            return secrets.compare_digest(computed_hash, stored_hash_bytes)
        except Exception:
            return False
    else:
        # Plain text password comparison
        return password == stored_password


# =====================================================
# User Authentication Functions
# =====================================================

async def get_user_by_username(session: AsyncSession, username: str) -> Optional[Dict[str, Any]]:
    """Get user by username."""
    result = await session.execute(
        text("""
            SELECT id, username, full_name, password_hash, is_active, created_at, last_login
            FROM users
            WHERE username = :username
        """),
        {"username": username}
    )
    row = result.first()
    if not row:
        return None
    
    return {
        "id": row[0],
        "username": row[1],
        "full_name": row[2],
        "password_hash": row[3],
        "is_active": row[4],
        "created_at": row[5],
        "last_login": row[6]
    }


async def get_user_login_state(session: AsyncSession, user_id: int) -> Optional[Dict[str, Any]]:
    """Get user login state for lockout tracking."""
    result = await session.execute(
        text("""
            SELECT user_id, failed_count, lock_level, lock_until, last_failed, updated_at
            FROM user_login_state
            WHERE user_id = :user_id
        """),
        {"user_id": user_id}
    )
    row = result.first()
    if not row:
        return None
    
    return {
        "user_id": row[0],
        "failed_count": row[1],
        "lock_level": row[2],
        "lock_until": row[3],
        "last_failed": row[4],
        "updated_at": row[5]
    }


async def increment_failed_attempt(session: AsyncSession, user_id: int) -> Dict[str, Any]:
    """
    Increment failed login count and apply lockout if threshold reached.
    
    Lockout rules:
    - 5 failed attempts at lock_level 0 -> 5 minute lock, move to lock_level 1
    - 5 failed attempts at lock_level 1 -> 1 hour lock, move to lock_level 2
    
    Returns dict with is_locked, lock_until, failed_count
    """
    # Get or create login state
    state = await get_user_login_state(session, user_id)
    
    if not state:
        # Create initial state
        await session.execute(
            text("""
                INSERT INTO user_login_state (user_id, failed_count, lock_level, last_failed, updated_at)
                VALUES (:user_id, 1, 0, NOW(), NOW())
            """),
            {"user_id": user_id}
        )
        await session.commit()
        return {"is_locked": False, "lock_until": None, "failed_count": 1}
    
    new_failed_count = state["failed_count"] + 1
    lock_level = state["lock_level"]
    lock_until = None
    
    # Check if we need to apply lockout
    if new_failed_count >= 5:
        if lock_level == 0:
            # First lockout: 5 minutes
            lock_until = datetime.utcnow() + timedelta(minutes=5)
            lock_level = 1
            new_failed_count = 0
        elif lock_level == 1:
            # Second lockout: 1 hour
            lock_until = datetime.utcnow() + timedelta(hours=1)
            lock_level = 2
            new_failed_count = 0
        else:
            # Already at max lock level, keep 1 hour lock
            lock_until = datetime.utcnow() + timedelta(hours=1)
            new_failed_count = 0
    
    await session.execute(
        text("""
            UPDATE user_login_state
            SET failed_count = :failed_count,
                lock_level = :lock_level,
                lock_until = :lock_until,
                last_failed = NOW(),
                updated_at = NOW()
            WHERE user_id = :user_id
        """),
        {
            "user_id": user_id,
            "failed_count": new_failed_count,
            "lock_level": lock_level,
            "lock_until": lock_until
        }
    )
    await session.commit()
    
    return {
        "is_locked": lock_until is not None,
        "lock_until": lock_until,
        "failed_count": new_failed_count
    }


async def reset_login_state(session: AsyncSession, user_id: int) -> None:
    """Reset login state after successful login."""
    await session.execute(
        text("""
            INSERT INTO user_login_state (user_id, failed_count, lock_level, lock_until, updated_at)
            VALUES (:user_id, 0, 0, NULL, NOW())
            ON CONFLICT (user_id) DO UPDATE
            SET failed_count = 0,
                lock_level = 0,
                lock_until = NULL,
                updated_at = NOW()
        """),
        {"user_id": user_id}
    )
    await session.commit()


async def update_last_login(session: AsyncSession, user_id: int) -> None:
    """Update user's last_login timestamp."""
    await session.execute(
        text("UPDATE users SET last_login = NOW() WHERE id = :user_id"),
        {"user_id": user_id}
    )
    await session.commit()


def is_account_locked(login_state: Optional[Dict[str, Any]]) -> tuple[bool, Optional[datetime]]:
    """
    Check if account is locked.
    
    Returns (is_locked, lock_until)
    """
    if not login_state or not login_state.get("lock_until"):
        return (False, None)
    
    lock_until = login_state["lock_until"]
    if lock_until.replace(tzinfo=None) > datetime.utcnow():
        return (True, lock_until)
    
    return (False, None)
