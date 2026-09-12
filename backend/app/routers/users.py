from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models.user import User
from app.schemas.user import UserResponse, UserUpdate, ChangePassword
from app.services.auth_service import get_verified_user
from app.utils.security import verify_password, hash_password
from pydantic import BaseModel

router = APIRouter(prefix="/api/users", tags=["Users"])


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_verified_user)):
    return current_user


@router.put("/me", response_model=UserResponse)
async def update_me(
    payload: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    if payload.name is not None:
        current_user.name = payload.name
    if payload.avatar_url is not None:
        current_user.avatar_url = payload.avatar_url
    await db.commit()
    await db.refresh(current_user)
    return current_user


@router.put("/me/password")
async def change_password(
    payload: ChangePassword,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    if not current_user.password_hash:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Google/OAuth account — use Set Password endpoint to configure a password")
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    current_user.password_hash = hash_password(payload.new_password)
    await db.commit()
    return {"message": "Password changed successfully"}


class SetPasswordRequest(BaseModel):
    new_password: str


@router.post("/me/password/set")
async def set_password_for_oauth(
    payload: SetPasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    """Set a local password for Google/OAuth accounts."""
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters long")
    current_user.password_hash = hash_password(payload.new_password)
    await db.commit()
    return {"message": "Password configured successfully"}


@router.delete("/me")
async def delete_account(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    await db.delete(current_user)
    await db.commit()
    return {"message": "Account deleted successfully"}
