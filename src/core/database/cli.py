"""
CLI Commands for Database Management

Provides command-line interface for database operations including initialization,
migrations, backups, and maintenance tasks.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

from .initialization import get_database_initializer, initialize_database_system
from .connection import get_database_manager
from .repositories import RepositoryFactory
from .session import transaction_scope
from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()
console = Console()


@click.group(name="database")
@click.pass_context
def database_cli(ctx):
    """Database management commands."""
    ctx.ensure_object(dict)


@database_cli.command()
@click.option('--force', is_flag=True, help='Force recreate database (WARNING: destroys all data)')
@click.option('--verbose', is_flag=True, help='Show verbose output')
def init(force: bool, verbose: bool):
    """Initialize the database schema and seed initial data."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    console.print("[bold blue]Initializing Database...[/bold blue]")
    
    if force:
        if not click.confirm(
            "⚠️  This will destroy all existing data. Are you sure?",
            default=False
        ):
            console.print("[yellow]Operation cancelled.[/yellow]")
            return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing database...", total=None)
        
        try:
            result = initialize_database_system(force_recreate=force)
            
            if result["success"]:
                progress.update(task, description="✅ Database initialization completed")
                
                # Show summary
                table = Table(title="Database Initialization Summary")
                table.add_column("Step", style="cyan")
                table.add_column("Status", style="green")
                
                for step in result["steps_completed"]:
                    table.add_row(step, "✅ Completed")
                
                if result.get("database_info"):
                    db_info = result["database_info"]
                    if "version" in db_info:
                        table.add_row("Database Version", db_info["version"])
                
                console.print(table)
                console.print("[bold green]Database initialization successful![/bold green]")
            
            else:
                progress.update(task, description="❌ Database initialization failed")
                console.print("[bold red]Database initialization failed![/bold red]")
                
                for error in result["errors"]:
                    console.print(f"[red]• {error}[/red]")
                
                sys.exit(1)
        
        except Exception as e:
            progress.update(task, description="❌ Database initialization failed")
            console.print(f"[bold red]Error: {e}[/bold red]")
            sys.exit(1)


@database_cli.command()
@click.option('--target', help='Target migration revision (defaults to head)')
def migrate(target: Optional[str]):
    """Run database migrations."""
    console.print("[bold blue]Running Database Migrations...[/bold blue]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running migrations...", total=None)
        
        try:
            initializer = get_database_initializer()
            result = initializer.run_migrations(target)
            
            if result["success"]:
                progress.update(task, description="✅ Migrations completed")
                console.print(f"[bold green]Migrations applied successfully![/bold green]")
                console.print(f"Current revision: {result.get('current_revision', 'unknown')}")
                console.print(f"Migrations applied: {result['migrations_applied']}")
            
            else:
                progress.update(task, description="❌ Migrations failed")
                console.print("[bold red]Migration failed![/bold red]")
                
                for error in result["errors"]:
                    console.print(f"[red]• {error}[/red]")
                
                sys.exit(1)
        
        except Exception as e:
            progress.update(task, description="❌ Migrations failed")
            console.print(f"[bold red]Error: {e}[/bold red]")
            sys.exit(1)


@database_cli.command()
@click.argument('message')
@click.option('--autogenerate/--no-autogenerate', default=True, help='Auto-detect model changes')
def create_migration(message: str, autogenerate: bool):
    """Create a new database migration."""
    console.print(f"[bold blue]Creating Migration: {message}[/bold blue]")
    
    try:
        initializer = get_database_initializer()
        result = initializer.create_migration(message, autogenerate)
        
        if result["success"]:
            console.print(f"[bold green]Migration created successfully![/bold green]")
            if result.get("migration_file"):
                console.print(f"Migration file: {result['migration_file']}")
        
        else:
            console.print("[bold red]Migration creation failed![/bold red]")
            for error in result["errors"]:
                console.print(f"[red]• {error}[/red]")
            sys.exit(1)
    
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        sys.exit(1)


@database_cli.command()
def health():
    """Check database health and connectivity."""
    console.print("[bold blue]Database Health Check[/bold blue]")
    
    try:
        db_manager = get_database_manager()
        health_info = db_manager.health_check()
        
        if health_info["healthy"]:
            status_panel = Panel(
                "[bold green]✅ Database is healthy[/bold green]",
                title="Health Status",
                style="green"
            )
        else:
            status_panel = Panel(
                f"[bold red]❌ Database is unhealthy[/bold red]\n{health_info.get('error', 'Unknown error')}",
                title="Health Status",
                style="red"
            )
        
        console.print(status_panel)
        
        # Detailed information table
        table = Table(title="Database Information")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Response Time", f"{health_info.get('response_time_ms', 'N/A')} ms")
        table.add_row("Connection Status", "✅ Connected" if health_info["healthy"] else "❌ Disconnected")
        
        if health_info.get("database_info"):
            db_info = health_info["database_info"]
            for key, value in db_info.items():
                table.add_row(key.replace('_', ' ').title(), str(value))
        
        if health_info.get("connection_stats"):
            stats = health_info["connection_stats"]
            table.add_row("Total Connections", str(stats.get("total_connections", 0)))
            table.add_row("Active Connections", str(stats.get("active_connections", 0)))
            table.add_row("Failed Connections", str(stats.get("failed_connections", 0)))
        
        console.print(table)
    
    except Exception as e:
        console.print(f"[bold red]Health check failed: {e}[/bold red]")
        sys.exit(1)


@database_cli.command()
@click.option('--format', type=click.Choice(['table', 'json']), default='table', help='Output format')
def status(format: str):
    """Show database and migration status."""
    try:
        initializer = get_database_initializer()
        migration_status = initializer.get_migration_status()
        
        db_manager = get_database_manager()
        db_stats = db_manager.get_statistics()
        
        if format == 'json':
            import json
            output = {
                "migration_status": migration_status,
                "database_stats": db_stats
            }
            console.print_json(json.dumps(output, indent=2))
        
        else:
            # Migration Status
            migration_table = Table(title="Migration Status")
            migration_table.add_column("Property", style="cyan")
            migration_table.add_column("Value", style="white")
            
            migration_table.add_row("Alembic Configured", "✅ Yes" if migration_status["alembic_configured"] else "❌ No")
            migration_table.add_row("Current Revision", migration_status.get("current_revision") or "None")
            migration_table.add_row("Pending Migrations", str(len(migration_status.get("pending_migrations", []))))
            
            console.print(migration_table)
            
            # Database Statistics
            stats_table = Table(title="Database Statistics")
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", style="white")
            
            if "connection_stats" in db_stats:
                conn_stats = db_stats["connection_stats"]
                for key, value in conn_stats.items():
                    stats_table.add_row(key.replace('_', ' ').title(), str(value))
            
            if "engine_info" in db_stats:
                engine_info = db_stats["engine_info"]
                stats_table.add_row("Database URL", engine_info.get("url", "N/A"))
                stats_table.add_row("Driver", engine_info.get("driver", "N/A"))
            
            console.print(stats_table)
    
    except Exception as e:
        console.print(f"[bold red]Status check failed: {e}[/bold red]")
        sys.exit(1)


@database_cli.command()
@click.option('--backup-name', help='Custom backup name')
def backup(backup_name: Optional[str]):
    """Create an encrypted database backup."""
    console.print("[bold blue]Creating Database Backup...[/bold blue]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Creating backup...", total=None)
        
        try:
            initializer = get_database_initializer()
            result = initializer.backup_database()
            
            if result["success"]:
                progress.update(task, description="✅ Backup completed")
                console.print("[bold green]Backup created successfully![/bold green]")
                
                if result.get("encrypted_file"):
                    console.print(f"Backup file: {result['encrypted_file']}")
                    console.print(f"Original size: {result.get('original_size', 0)} bytes")
                    console.print(f"Encrypted size: {result.get('encrypted_size', 0)} bytes")
            
            else:
                progress.update(task, description="❌ Backup failed")
                console.print("[bold red]Backup failed![/bold red]")
                console.print(f"[red]Error: {result.get('error', 'Unknown error')}[/red]")
                sys.exit(1)
        
        except Exception as e:
            progress.update(task, description="❌ Backup failed")
            console.print(f"[bold red]Error: {e}[/bold red]")
            sys.exit(1)


@database_cli.command()
@click.option('--days', default=30, help='Number of days to keep audit logs')
@click.option('--dry-run', is_flag=True, help='Show what would be cleaned without actually doing it')
def cleanup(days: int, dry_run: bool):
    """Clean up old audit logs and expired sessions."""
    console.print(f"[bold blue]Database Cleanup (keeping {days} days of data)[/bold blue]")
    
    if dry_run:
        console.print("[yellow]DRY RUN MODE - No changes will be made[/yellow]")
    
    try:
        with transaction_scope() as session:
            repos = RepositoryFactory(session)
            
            # Clean up expired sessions
            session_repo = repos.get_session_repository()
            expired_sessions = session_repo.cleanup_expired_sessions()
            
            if not dry_run:
                console.print(f"✅ Cleaned up {expired_sessions} expired sessions")
            else:
                console.print(f"Would clean up {expired_sessions} expired sessions")
            
            # Clean up old audit logs (this would need implementation in repository)
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            console.print(f"Cutoff date for cleanup: {cutoff_date.isoformat()}")
            
            if not dry_run:
                session.commit()
                console.print("[bold green]Cleanup completed successfully![/bold green]")
            else:
                console.print("[yellow]Dry run completed - no changes made[/yellow]")
    
    except Exception as e:
        console.print(f"[bold red]Cleanup failed: {e}[/bold red]")
        sys.exit(1)


@database_cli.command()
@click.option('--table', help='Specific table to analyze (optional)')
def analyze(table: Optional[str]):
    """Analyze database performance and suggest optimizations."""
    console.print("[bold blue]Database Performance Analysis[/bold blue]")
    
    try:
        with transaction_scope() as session:
            # Basic table statistics
            if table:
                # Analyze specific table
                result = session.execute(f"SELECT COUNT(*) FROM {table}")
                count = result.scalar()
                console.print(f"Table '{table}' has {count} rows")
            else:
                # Analyze all tables
                db_manager = get_database_manager()
                
                with db_manager.get_connection() as conn:
                    from sqlalchemy import inspect
                    inspector = inspect(conn)
                    tables = inspector.get_table_names()
                    
                    table_stats = Table(title="Table Statistics")
                    table_stats.add_column("Table Name", style="cyan")
                    table_stats.add_column("Row Count", style="white")
                    
                    for table_name in tables:
                        try:
                            result = session.execute(f"SELECT COUNT(*) FROM {table_name}")
                            count = result.scalar()
                            table_stats.add_row(table_name, str(count))
                        except Exception:
                            table_stats.add_row(table_name, "Error")
                    
                    console.print(table_stats)
        
        # Performance recommendations
        recommendations = [
            "Consider adding indexes on frequently queried columns",
            "Monitor connection pool usage during peak loads",
            "Regular VACUUM operations for PostgreSQL",
            "Consider partitioning for large audit tables"
        ]
        
        rec_panel = Panel(
            "\n".join(f"• {rec}" for rec in recommendations),
            title="Performance Recommendations",
            style="yellow"
        )
        console.print(rec_panel)
    
    except Exception as e:
        console.print(f"[bold red]Analysis failed: {e}[/bold red]")
        sys.exit(1)


@database_cli.command()
def shell():
    """Open an interactive database shell."""
    console.print("[bold blue]Starting Database Shell...[/bold blue]")
    console.print("[dim]Type 'exit' or press Ctrl+C to exit[/dim]")
    
    try:
        with transaction_scope() as session:
            console.print(f"Connected to: {session.bind.url}")
            
            while True:
                try:
                    query = click.prompt("SQL", prompt_suffix="> ")
                    
                    if query.lower().strip() in ['exit', 'quit']:
                        break
                    
                    result = session.execute(query)
                    
                    if result.returns_rows:
                        rows = result.fetchall()
                        if rows:
                            # Create table for results
                            if hasattr(result, 'keys') and result.keys():
                                results_table = Table()
                                for column in result.keys():
                                    results_table.add_column(column, style="cyan")
                                
                                for row in rows:
                                    results_table.add_row(*[str(value) for value in row])
                                
                                console.print(results_table)
                            else:
                                for row in rows:
                                    console.print(str(row))
                        else:
                            console.print("[dim]No results returned[/dim]")
                    else:
                        console.print(f"[green]Query executed successfully[/green]")
                
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")
    
    except Exception as e:
        console.print(f"[bold red]Shell startup failed: {e}[/bold red]")
        sys.exit(1)
    
    console.print("[dim]Database shell closed[/dim]")


# Register CLI commands
def register_database_commands(app):
    """Register database CLI commands with the main application."""
    if hasattr(app, 'cli'):
        app.cli.add_command(database_cli)
    return database_cli


if __name__ == "__main__":
    database_cli()