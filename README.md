### 📄 README.md
```markdown
# 🛡️ AI Shield Pro

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.2.0-61dafb.svg)](https://reactjs.org/)
[![Docker](https://img.shields.io/badge/Docker-Multi--stage-blue.svg)](https://www.docker.com/)

---

## 🇬🇧 English Description

**AI Shield Pro** is an AI-powered malware detection and threat management system that combines machine learning, real-time monitoring, and enterprise-grade security practices to protect your infrastructure.

### ✨ Key Features

- 🤖 **AI-Powered Detection**: RandomForest-based PE file analysis with SHA256 model integrity verification
- ⚡ **Fully Asynchronous Backend**: FastAPI + SQLAlchemy 2.0 Async + asyncpg for high concurrency
- 🔒 **Enterprise Security**: JWT authentication, rate limiting (SlowAPI), CORS protection, data leak prevention
- 📡 **Real-Time WebSocket Monitoring**: Live threat alerts with auto-quarantine and exponential backoff reconnection
- 🐳 **Production-Ready Docker**: Multi-stage builds, non-root user, health checks, and PostgreSQL/Redis orchestration
- 📊 **PDF Audit Reports**: One-click security report export with jsPDF
- 🔄 **Threat Lifecycle Management**: Quarantine, restore, permanently delete with optimistic locking

### 🛠️ Tech Stack

**Backend**
- Python 3.11, FastAPI (async), SQLAlchemy 2.0 (Async), Alembic
- python-jose (JWT), SlowAPI (rate limiting), scikit-learn, joblib
- PostgreSQL 16 (asyncpg), Redis 7

**Frontend**
- React 18, TypeScript, Vite
- Tailwind CSS, shadcn/ui, Axios, WebSocket
- jsPDF + jspdf-autotable (PDF export)

**DevOps**
- Docker Multi-stage Builds, Docker Compose
- Gunicorn + Uvicorn workers (4 workers)
- Health checks, non-root container user

### 🚀 Quick Start (Docker)

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/ai-shield-pro.git
cd ai-shield-pro

# 2. Configure environment variables
cp .env.example .env
# Edit .env and set JWT_SECRET_KEY and other production values

# 3. Start all services
docker-compose up -d

# 4. Access Swagger UI
open http://localhost:8000/docs
```

**Default Test Credentials** (for `/api/auth/login`):
- Username: `admin`
- Password: `admin123`

---

## 🇨🇳 中文简介

**AI Shield Pro** 是一套 AI 驱动的恶意软件检测与威胁管理系统，结合机器学习、实时监控与企业级安全实践，为您的基础设施提供全方位防护。

### ✨ 核心特性

- 🤖 **AI 智能检测**: 基于 RandomForest 的 PE 文件分析，内置 SHA256 模型完整性校验
- ⚡ **全异步后端**: FastAPI + SQLAlchemy 2.0 Async + asyncpg，支持高并发场景
- 🔒 **企业级安全**: JWT 鉴权、SlowAPI 速率限制、CORS 保护、数据泄漏防护
- 📡 **WebSocket 实时监控**: 实时威胁告警，支持自动隔离与指数退避重连
- 🐳 **生产级 Docker**: 多阶段构建、非 root 用户、健康检查、PostgreSQL/Redis 编排
- 📊 **PDF 审计报告**: 一键导出安全审计报告 (jsPDF)
- 🔄 **威胁生命周期管理**: 隔离、恢复、永久删除，内置乐观锁防冲突

### 🛠️ 技术栈

**后端**
- Python 3.11, FastAPI (异步), SQLAlchemy 2.0 (Async), Alembic
- python-jose (JWT), SlowAPI (限流), scikit-learn, joblib
- PostgreSQL 16 (asyncpg), Redis 7

**前端**
- React 18, TypeScript, Vite
- Tailwind CSS, shadcn/ui, Axios, WebSocket
- jsPDF + jspdf-autotable (PDF 导出)

**DevOps**
- Docker 多阶段构建, Docker Compose
- Gunicorn + Uvicorn workers (4 workers)
- 健康检查, 非 root 容器用户

### 🚀 快速开始 (Docker)

```bash
# 1. 克隆仓库
git clone https://github.com/YOUR_USERNAME/ai-shield-pro.git
cd ai-shield-pro

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env 文件，设置 JWT_SECRET_KEY 等生产环境配置

# 3. 启动所有服务
docker-compose up -d

# 4. 访问 Swagger UI
open http://localhost:8000/docs
```

**默认测试账号** (用于 `/api/auth/login`):
- 用户名: `admin`
- 密码: `admin123`

---

## 📜 License / 许可证

This project is licensed under the **MIT License**.  
本项目采用 **MIT License**。

---

## ⚠️ Security Note / 安全提示

- 🚫 **Never commit `.env` to Git** — 切勿将 `.env` 文件提交到 Git 仓库
- 🔑 **Change `JWT_SECRET_KEY` immediately** — 生产环境必须修改默认的 `JWT_SECRET_KEY`
- 🐳 **Use strong passwords for PostgreSQL** — Docker Compose 中的默认数据库密码仅用于开发环境
- 📁 **Restrict file upload directory permissions** — 确保 `uploads/` 和 `quarantine/` 目录权限最小化

---

*Built with ❤️ by the AI Shield Pro Team*
```
