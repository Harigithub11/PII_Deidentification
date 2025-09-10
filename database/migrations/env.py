"""
Alembic environment configuration for PII De-identification System.
"""

import os
import sys
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

# Add src directory to path so we can import our models
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from core.database.models import Base
from core.config.settings import get_settings

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def get_database_url():
    """Get database URL from settings or environment."""
    settings = get_settings()
    
    # Check if we have a specific migration database URL
    migration_url = os.getenv('MIGRATION_DATABASE_URL')
    if migration_url:
        return migration_url
    
    # Use the application database URL
    db_url = settings.database_url
    
    # Convert SQLite URLs to PostgreSQL for production migrations
    if db_url.startswith('sqlite'):
        # For development, we might want to use PostgreSQL instead
        pg_url = os.getenv('POSTGRESQL_URL')
        if pg_url:
            return pg_url
        else:
            print("Warning: Using SQLite database for migrations. Consider using PostgreSQL for production.")
    
    return db_url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        render_as_batch=True,  # For SQLite compatibility
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    # Get database URL
    database_url = get_database_url()
    
    # Override the sqlalchemy.url in the alembic config
    config.set_main_option('sqlalchemy.url', database_url)
    
    # Create engine configuration
    configuration = config.get_section(config.config_ini_section)
    configuration['sqlalchemy.url'] = database_url
    
    # Additional configuration for PostgreSQL
    if 'postgresql' in database_url:
        configuration['sqlalchemy.pool_pre_ping'] = 'true'
        configuration['sqlalchemy.pool_recycle'] = '300'
    
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            render_as_batch=True,  # For SQLite compatibility
            transaction_per_migration=True,  # Each migration in its own transaction
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()