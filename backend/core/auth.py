# backend/core/auth.py
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from core.config import settings

logger = logging.getLogger(__name__)

# 密码哈希上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 方案（从 Authorization: Bearer <token> header 读取 token）
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login", auto_error=False)

class TokenData(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """生成密码哈希"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """生成 JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> dict:
    """
    获取当前认证用户（用于 HTTP 路由）
    返回: dict (例如 {"user_id": "123", "username": "admin"})
    """
    # P0 安全修复：显式检查 token 是否为空
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        username: str = payload.get("username", "user")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id, username=username)
    except JWTError as e:
        logger.warning(f"JWT decode failed: {e}")
        raise credentials_exception
    
    # TODO: 这里可以查询数据库验证用户是否被禁用
    # user = await get_user_by_id(token_data.user_id)
    # if user.is_disabled:
    #     raise HTTPException(status_code=403, detail="User disabled")
    
    return {"user_id": token_data.user_id, "username": token_data.username}

def verify_ws_token(token: str) -> Optional[str]:
    """
    验证 WebSocket token（用于 WS 握手鉴权）
    返回: user_id (str) 或 None（鉴权失败）
    """
    if not token:
        logger.warning("WebSocket token is empty")
        return None
    
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            logger.warning("WebSocket token missing 'sub' claim")
            return None
        return user_id
    except JWTError as e:
        logger.warning(f"WebSocket JWT decode failed: {e}")
        return None