from routers.auth import router as auth_router
from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
import logging

from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from core.database import engine
from core.limiter import limiter
from routers.upload import router as upload_router
from routers.lifecycle import router as lifecycle_router
from routers.threats import router as threats_router
from routers.reports import router as reports_router
from routers.websocket import router as websocket_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Application startup complete")
    yield
    await engine.dispose()
    logger.info("Application shutdown")


app = FastAPI(title="AI Shield Pro Backend", lifespan=lifespan)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    logger.warning("Rate limit exceeded ip=%s path=%s", request.client.host if request.client else "unknown", request.url.path)
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Please try again later."})


app.include_router(upload_router, prefix="/api", tags=["upload"])
app.include_router(lifecycle_router, prefix="/api", tags=["lifecycle"])
app.include_router(threats_router, prefix="/api", tags=["threats"])
app.include_router(reports_router, prefix="/api", tags=["reports"])
app.include_router(websocket_router)
app.include_router(auth_router, prefix="/api", tags=["auth"])