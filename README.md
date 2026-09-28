```markdown
## 🛡️ AI Shield Pro / AI 智能威胁检测系统

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

**English** | [中文](#中文简介)

---

## 🇬🇧 English Description

**AI Shield Pro** is an enterprise-grade, real-time intelligent threat detection and management system. Built with a modern, fully asynchronous architecture, it provides robust file scanning, behavioral analysis, and automated threat lifecycle management (quarantine, clean, restore, delete).

### ✨ Key Features
- 🚀 **Fully Asynchronous Backend**: Built with FastAPI and SQLAlchemy 2.0, ensuring non-blocking I/O and high concurrency.
- 🔐 **Secure Authentication**: Standard OAuth2 JWT authentication with WebSocket handshake verification.
- ⚡ **Real-time Monitoring**: WebSocket-based live threat alerts and scanning progress updates.
- 🛡️ **Rate Limiting**: Integrated SlowAPI with Redis support to prevent API abuse.
- 🐳 **Production-Ready Deployment**: Multi-stage Docker builds with health checks, non-root user execution, and Docker Compose orchestration (PostgreSQL 16 + Redis 7).
- 📊 **Automated Reporting**: One-click PDF security audit report generation.

### 🛠️ Tech Stack
- **Backend**: Python 3.11, FastAPI, SQLAlchemy (Async), Alembic, SlowAPI, python-jose
- **Frontend**: React 18, TypeScript, Tailwind CSS, Axios, WebSocket
- **Database & Cache**: PostgreSQL 16, Redis 7
- **DevOps**: Docker, Docker Compose, Gunicorn + Uvicorn Workers

### 🚀 Quick Start (Docker)
```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/ai-shield-pro.git
cd ai-shield-pro

# 2. Configure environment variables
cp .env.example .env
# Edit .env and set a strong JWT_SECRET_KEY

# 3. Start all services (API, PostgreSQL, Redis)
docker-compose up -d --build

# 4. Access the API documentation
# http://localhost:8000/docs
```

## 🇨🇳 中文简介

**AI Shield Pro** 是一款企业级的实时智能威胁检测与管理系统。基于现代化的全异步架构构建，提供强大的文件扫描、行为分析以及自动化的威胁生命周期管理（隔离、清除、恢复、删除）。

### ✨ 核心特性
- 🚀 **全异步后端**：基于 FastAPI 和 SQLAlchemy 2.0 构建，确保非阻塞 I/O 和高并发处理能力。
- 🔐 **安全鉴权**：标准的 OAuth2 JWT 认证，并包含 WebSocket 握手鉴权机制。
- ⚡ **实时监控**：基于 WebSocket 的实时威胁告警与扫描进度推送。
- 🛡️ **速率限制**：集成 SlowAPI（支持 Redis），有效防止 API 滥用和恶意请求。
- 🐳 **生产级部署**：多阶段 Docker 构建，包含健康检查、非 root 用户运行，以及完整的 Docker Compose 编排 (PostgreSQL 16 + Redis 7)。
- 📊 **自动化报告**：一键生成包含威胁统计与详细列表的 PDF 安全审计报告。

### 🛠️ 技术栈
- **后端**: Python 3.11, FastAPI, SQLAlchemy (Async), Alembic, SlowAPI, python-jose
- **前端**: React 18, TypeScript, Tailwind CSS, Axios, WebSocket
- **数据库与缓存**: PostgreSQL 16, Redis 7
- **DevOps**: Docker, Docker Compose, Gunicorn + Uvicorn Workers

### 🚀 快速开始 (Docker)
```bash
# 1. 克隆仓库
git clone https://github.com/YOUR_USERNAME/ai-shield-pro.git
cd ai-shield-pro

# 2. 配置环境变量
cp .env.example .env
# 请编辑 .env 文件，设置一个强随机的 JWT_SECRET_KEY

# 3. 一键启动所有服务 (API, PostgreSQL, Redis)
docker-compose up -d --build

# 4. 访问 API 文档
# http://localhost:8000/docs
```

---

## 📜 License / 许可证
This project is licensed under the MIT License. / 本项目采用 MIT 许可证。
```

