# backend/core/limiter.py
from slowapi import Limiter
from slowapi.util import get_remote_address

# 统一实例化 Limiter，使用内存后端 (生产环境可换为 redis://...)
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")