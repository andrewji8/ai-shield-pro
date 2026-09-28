# backend/core/config.py
import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # 1. 应用基础配置
    DEBUG: bool = False
    APP_NAME: str = "AI Shield Pro"

    # 2. 数据库配置 (默认使用 SQLite 异步驱动，方便本地零配置测试)
    # 生产环境通过环境变量覆盖: DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db
    DATABASE_URL: str = "sqlite+aiosqlite:///./shield.db"

    # 3. JWT 鉴权配置
    # ⚠️ 生产环境必须通过环境变量 JWT_SECRET_KEY 覆盖此默认值！
    JWT_SECRET_KEY: str = "dev-secret-key-change-in-production-12345"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # 4. 限流配置 (用于 slowapi)
    RATE_LIMIT_PER_MINUTE: int = 10

    # 5. CORS 配置 (逗号分隔的字符串，在 property 中转为 List)
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    # Pydantic V2 标准配置
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False, # 允许环境变量大小写不敏感
    )

# 全局单例
settings = Settings()