import asyncio
import logging
import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), "..")))

from core.config import settings
from core.database import Base

config = context.config
fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", settings.ASYNC_DATABASE_URL)

target_metadata = Base.metadata

logger = logging.getLogger(__name__)


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()
    logger.info("Async migrations completed")


if context.is_offline_mode():
    url = settings.ASYNC_DATABASE_URL
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()
    logger.info("Offline async migrations completed")
else:
    asyncio.run(run_async_migrations())
