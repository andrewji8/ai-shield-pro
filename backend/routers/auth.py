# backend/routers/auth.py
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm
from core.auth import create_access_token

router = APIRouter()

# ️ 临时测试用：硬编码账号密码。生产环境应查询数据库。
@router.post("/auth/login", tags=["auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    兼容 Swagger UI 的 OAuth2 授权流程。
    接收表单数据：username 和 password。
    """
    # 硬编码校验
    if form_data.username == "admin" and form_data.password == "admin123":
        # 生成 JWT Token
        access_token = create_access_token(
            data={"sub": form_data.username, "username": form_data.username}
        )
        return {"access_token": access_token, "token_type": "bearer"}
    
    # 校验失败
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )