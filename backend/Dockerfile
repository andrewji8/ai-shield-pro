# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /app

# 🛠️ 核心优化：彻底移除 apt-get！
# asyncpg, cryptography, bcrypt 均有预编译 wheel，无需 gcc 现场编译。
# 这直接绕过了容器内网络被拦截的问题。

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /app/requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

COPY --from=builder /install /usr/local
COPY . /app/

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["gunicorn", "main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
