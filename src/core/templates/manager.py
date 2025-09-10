"""
Template Manager

Provides high-level template management functionality including
template lifecycle, versioning, sharing, and organizational features.
"""

import logging
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Set, Tuple
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
import shutil
import zipfile
from io import BytesIO

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .engine import TemplateEngine, TemplateConfig, TemplateType, TemplateStatus, get_template_engine
from ..database.session import get_db_session

logger = logging.getLogger(__name__)


class TemplateCategory(str, Enum):
    """Categories for organizing templates."""
    REPORTS = "reports"
    DASHBOARDS = "dashboards"
    COMMUNICATIONS = "communications"
    COMPLIANCE = "compliance"
    ANALYTICS = "analytics"
    CUSTOM = "custom"
    SYSTEM = "system"


class SharingPermission(str, Enum):
    """Sharing permission levels."""
    VIEW = "view"
    EDIT = "edit"
    ADMIN = "admin"


class TemplateVersion(BaseModel):
    """Template version information."""
    version: str
    template_id: UUID
    content: str
    changes: str = ""
    created_by: UUID
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_current: bool = False


@dataclass
class TemplateMetadata:
    """Extended metadata for templates."""
    template_id: UUID
    name: str
    description: Optional[str]
    category: TemplateCategory
    tags: List[str] = field(default_factory=list)
    author: str = ""
    organization: str = ""
    license: str = ""
    documentation: str = ""
    dependencies: List[UUID] = field(default_factory=list)
    compatible_versions: List[str] = field(default_factory=list)
    rating: float = 0.0
    review_count: int = 0
    download_count: int = 0
    featured: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SharingInfo:
    """Template sharing information."""
    template_id: UUID
    shared_by: UUID
    shared_with: UUID
    permission: SharingPermission
    shared_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    message: str = ""


class TemplateCollection(BaseModel):
    """Collection of related templates."""
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    owner_id: UUID
    template_ids: List[UUID] = Field(default_factory=list)
    is_public: bool = False
    category: TemplateCategory = TemplateCategory.CUSTOM
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class TemplateManager:
    """
    High-level template manager that provides organizational features,
    versioning, sharing, and lifecycle management for templates.
    """
    
    def __init__(self, session: Optional[Session] = None):
        self._session = session
        self._template_engine = get_template_engine(session)
        
        # Extended storage
        self._metadata: Dict[UUID, TemplateMetadata] = {}
        self._versions: Dict[UUID, List[TemplateVersion]] = {}
        self._sharing: Dict[UUID, List[SharingInfo]] = {}
        self._collections: Dict[UUID, TemplateCollection] = {}
        
        # Category organization
        self._categories: Dict[TemplateCategory, Set[UUID]] = {
            category: set() for category in TemplateCategory
        }
        
        # Search indices
        self._tag_index: Dict[str, Set[UUID]] = {}
        self._author_index: Dict[str, Set[UUID]] = {}
        
        logger.info("Template Manager initialized")
    
    async def create_template_with_metadata(self,
                                          config: TemplateConfig,
                                          metadata: TemplateMetadata) -> Tuple[TemplateConfig, TemplateMetadata]:
        """Create template with extended metadata."""
        try:
            # Create template through engine
            created_config = await self._template_engine.create_template(config)
            
            # Store metadata
            metadata.template_id = created_config.id
            self._metadata[created_config.id] = metadata
            
            # Update indices
            self._update_search_indices(created_config.id, metadata)
            self._categories[metadata.category].add(created_config.id)
            
            # Create initial version
            await self.create_version(
                created_config.id,
                config.version,
                config.content,
                f"Initial version: {config.name}",
                config.owner_id
            )
            
            logger.info(f"Template with metadata created: {created_config.id}")
            return created_config, metadata
            
        except Exception as e:
            logger.error(f"Failed to create template with metadata: {e}")
            raise
    
    async def get_template_with_metadata(self, template_id: UUID) -> Optional[Tuple[TemplateConfig, TemplateMetadata]]:
        """Get template with its metadata."""
        config = await self._template_engine.get_template(template_id)
        metadata = self._metadata.get(template_id)
        
        if config and metadata:
            return config, metadata
        return None
    
    async def update_template_metadata(self, template_id: UUID, updates: Dict[str, Any]) -> TemplateMetadata:
        """Update template metadata."""
        if template_id not in self._metadata:
            raise ValueError(f"Template metadata not found: {template_id}")
        
        metadata = self._metadata[template_id]
        old_category = metadata.category
        old_tags = set(metadata.tags)
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(metadata, key):
                setattr(metadata, key, value)
        
        metadata.updated_at = datetime.utcnow()
        
        # Update indices if needed
        if metadata.category != old_category:
            self._categories[old_category].discard(template_id)
            self._categories[metadata.category].add(template_id)
        
        new_tags = set(metadata.tags)
        if new_tags != old_tags:
            self._update_tag_index(template_id, old_tags, new_tags)
        
        logger.info(f"Template metadata updated: {template_id}")
        return metadata
    
    async def create_version(self,
                           template_id: UUID,
                           version: str,
                           content: str,
                           changes: str,
                           user_id: UUID) -> TemplateVersion:
        """Create a new version of a template."""
        try:
            # Mark previous versions as not current
            if template_id in self._versions:
                for v in self._versions[template_id]:
                    v.is_current = False
            
            # Create new version
            new_version = TemplateVersion(
                version=version,
                template_id=template_id,
                content=content,
                changes=changes,
                created_by=user_id,
                is_current=True
            )
            
            # Store version
            if template_id not in self._versions:
                self._versions[template_id] = []
            self._versions[template_id].append(new_version)
            
            # Update template content in engine
            await self._template_engine.update_template(template_id, {
                "content": content,
                "version": version
            })
            
            logger.info(f"Template version created: {template_id} v{version}")
            return new_version
            
        except Exception as e:
            logger.error(f"Failed to create template version: {e}")
            raise
    
    def get_template_versions(self, template_id: UUID) -> List[TemplateVersion]:
        """Get all versions of a template."""
        return self._versions.get(template_id, [])
    
    def get_current_version(self, template_id: UUID) -> Optional[TemplateVersion]:
        """Get current version of a template."""
        versions = self._versions.get(template_id, [])
        for version in versions:
            if version.is_current:
                return version
        return None
    
    async def rollback_to_version(self, template_id: UUID, version: str, user_id: UUID) -> bool:
        """Rollback template to a specific version."""
        try:
            versions = self._versions.get(template_id, [])
            target_version = None
            
            for v in versions:
                if v.version == version:
                    target_version = v
                    break
            
            if not target_version:
                return False
            
            # Create new version with old content
            new_version_num = f"{version}.rollback.{int(datetime.utcnow().timestamp())}"
            await self.create_version(
                template_id,
                new_version_num,
                target_version.content,
                f"Rollback to version {version}",
                user_id
            )
            
            logger.info(f"Template rolled back: {template_id} to v{version}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback template: {e}")
            return False
    
    async def share_template(self,
                           template_id: UUID,
                           shared_by: UUID,
                           shared_with: UUID,
                           permission: SharingPermission,
                           message: str = "",
                           expires_at: Optional[datetime] = None) -> SharingInfo:
        """Share template with another user."""
        try:
            sharing_info = SharingInfo(
                template_id=template_id,
                shared_by=shared_by,
                shared_with=shared_with,
                permission=permission,
                message=message,
                expires_at=expires_at
            )
            
            if template_id not in self._sharing:
                self._sharing[template_id] = []
            
            self._sharing[template_id].append(sharing_info)
            
            # Update template shared_with list
            config = await self._template_engine.get_template(template_id)
            if config and shared_with not in config.shared_with:
                await self._template_engine.update_template(template_id, {
                    "shared_with": config.shared_with + [shared_with]
                })
            
            logger.info(f"Template shared: {template_id} with {shared_with}")
            return sharing_info
            
        except Exception as e:
            logger.error(f"Failed to share template: {e}")
            raise
    
    def get_shared_templates(self, user_id: UUID) -> List[UUID]:
        """Get templates shared with a user."""
        shared_templates = []
        
        for template_id, sharing_list in self._sharing.items():
            for sharing in sharing_list:
                if (sharing.shared_with == user_id and
                    (not sharing.expires_at or sharing.expires_at > datetime.utcnow())):
                    shared_templates.append(template_id)
                    break
        
        return shared_templates
    
    def get_templates_shared_by_user(self, user_id: UUID) -> List[Tuple[UUID, List[SharingInfo]]]:
        """Get templates shared by a user."""
        shared_by_user = []
        
        for template_id, sharing_list in self._sharing.items():
            user_shares = [s for s in sharing_list if s.shared_by == user_id]
            if user_shares:
                shared_by_user.append((template_id, user_shares))
        
        return shared_by_user
    
    async def create_collection(self, collection: TemplateCollection) -> TemplateCollection:
        """Create a template collection."""
        self._collections[collection.id] = collection
        logger.info(f"Template collection created: {collection.id} - {collection.name}")
        return collection
    
    async def add_template_to_collection(self, collection_id: UUID, template_id: UUID) -> bool:
        """Add template to collection."""
        if collection_id not in self._collections:
            return False
        
        collection = self._collections[collection_id]
        if template_id not in collection.template_ids:
            collection.template_ids.append(template_id)
            collection.updated_at = datetime.utcnow()
            logger.info(f"Template added to collection: {template_id} -> {collection_id}")
        
        return True
    
    async def remove_template_from_collection(self, collection_id: UUID, template_id: UUID) -> bool:
        """Remove template from collection."""
        if collection_id not in self._collections:
            return False
        
        collection = self._collections[collection_id]
        if template_id in collection.template_ids:
            collection.template_ids.remove(template_id)
            collection.updated_at = datetime.utcnow()
            logger.info(f"Template removed from collection: {template_id} <- {collection_id}")
        
        return True
    
    def get_collections_for_user(self, user_id: UUID, include_public: bool = True) -> List[TemplateCollection]:
        """Get collections for a user."""
        collections = []
        
        for collection in self._collections.values():
            if collection.owner_id == user_id or (include_public and collection.is_public):
                collections.append(collection)
        
        return collections
    
    def search_templates(self,
                        query: str = "",
                        category: Optional[TemplateCategory] = None,
                        tags: Optional[List[str]] = None,
                        author: Optional[str] = None,
                        template_type: Optional[TemplateType] = None,
                        user_id: Optional[UUID] = None,
                        include_shared: bool = True) -> List[UUID]:
        """Search templates with various criteria."""
        results = set()
        
        # Start with all templates or filtered by category
        if category:
            candidates = self._categories.get(category, set())
        else:
            candidates = set()
            for category_templates in self._categories.values():
                candidates.update(category_templates)
        
        # Filter by tags
        if tags:
            tag_matches = set()
            for tag in tags:
                if tag in self._tag_index:
                    if not tag_matches:
                        tag_matches = self._tag_index[tag].copy()
                    else:
                        tag_matches &= self._tag_index[tag]
            candidates &= tag_matches
        
        # Filter by author
        if author and author in self._author_index:
            candidates &= self._author_index[author]
        
        # Apply text search and other filters
        for template_id in candidates:
            metadata = self._metadata.get(template_id)
            if not metadata:
                continue
            
            # Check user access
            if user_id:
                config = await self._template_engine.get_template(template_id)
                if config:
                    has_access = (
                        config.is_public or
                        config.owner_id == user_id or
                        (include_shared and user_id in config.shared_with)
                    )
                    if not has_access:
                        continue
            
            # Text search
            if query:
                searchable_text = f"{metadata.name} {metadata.description or ''} {' '.join(metadata.tags)}".lower()
                if query.lower() not in searchable_text:
                    continue
            
            # Template type filter
            if template_type:
                config = await self._template_engine.get_template(template_id)
                if config and config.template_type != template_type:
                    continue
            
            results.add(template_id)
        
        return list(results)
    
    def get_popular_templates(self, limit: int = 10, category: Optional[TemplateCategory] = None) -> List[UUID]:
        """Get popular templates based on usage metrics."""
        template_popularity = []
        
        for template_id, metadata in self._metadata.items():
            if category and metadata.category != category:
                continue
            
            # Calculate popularity score
            metrics = self._template_engine.get_template_metrics(template_id)
            if metrics:
                popularity_score = (
                    metrics.usage_count * 0.4 +
                    metadata.download_count * 0.3 +
                    metadata.rating * metadata.review_count * 0.2 +
                    (10 if metadata.featured else 0) * 0.1
                )
                template_popularity.append((template_id, popularity_score))
        
        # Sort by popularity and return top results
        template_popularity.sort(key=lambda x: x[1], reverse=True)
        return [t[0] for t in template_popularity[:limit]]
    
    def get_recommended_templates(self, user_id: UUID, limit: int = 10) -> List[UUID]:
        """Get recommended templates for a user based on their usage patterns."""
        # This would implement recommendation algorithms
        # For now, return popular templates from categories the user has used
        
        user_categories = set()
        for template_id, metadata in self._metadata.items():
            config = await self._template_engine.get_template(template_id)
            if config and config.owner_id == user_id:
                user_categories.add(metadata.category)
        
        recommendations = []
        for category in user_categories:
            popular = self.get_popular_templates(limit=5, category=category)
            recommendations.extend(popular)
        
        # Remove duplicates and limit
        return list(dict.fromkeys(recommendations))[:limit]
    
    async def export_template(self, template_id: UUID, include_versions: bool = False) -> BytesIO:
        """Export template as a package."""
        try:
            config = await self._template_engine.get_template(template_id)
            metadata = self._metadata.get(template_id)
            
            if not config or not metadata:
                raise ValueError(f"Template not found: {template_id}")
            
            # Create ZIP package
            package = BytesIO()
            
            with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add template configuration
                zip_file.writestr("template.json", config.json(indent=2))
                
                # Add metadata
                metadata_dict = {
                    "template_id": str(metadata.template_id),
                    "name": metadata.name,
                    "description": metadata.description,
                    "category": metadata.category.value,
                    "tags": metadata.tags,
                    "author": metadata.author,
                    "organization": metadata.organization,
                    "license": metadata.license,
                    "documentation": metadata.documentation,
                    "created_at": metadata.created_at.isoformat(),
                    "updated_at": metadata.updated_at.isoformat()
                }
                zip_file.writestr("metadata.json", json.dumps(metadata_dict, indent=2))
                
                # Add template content
                zip_file.writestr("content.html", config.content)
                
                # Add versions if requested
                if include_versions:
                    versions = self.get_template_versions(template_id)
                    versions_data = []
                    for version in versions:
                        versions_data.append({
                            "version": version.version,
                            "changes": version.changes,
                            "created_at": version.created_at.isoformat(),
                            "is_current": version.is_current
                        })
                        zip_file.writestr(f"versions/{version.version}.html", version.content)
                    
                    zip_file.writestr("versions.json", json.dumps(versions_data, indent=2))
            
            package.seek(0)
            logger.info(f"Template exported: {template_id}")
            return package
            
        except Exception as e:
            logger.error(f"Failed to export template {template_id}: {e}")
            raise
    
    async def import_template(self, package: BytesIO, user_id: UUID) -> TemplateConfig:
        """Import template from a package."""
        try:
            with zipfile.ZipFile(package, 'r') as zip_file:
                # Read template configuration
                config_data = json.loads(zip_file.read("template.json"))
                config = TemplateConfig(**config_data)
                
                # Update ownership
                config.id = uuid4()  # Generate new ID
                config.owner_id = user_id
                
                # Read metadata if available
                metadata = None
                try:
                    metadata_data = json.loads(zip_file.read("metadata.json"))
                    metadata = TemplateMetadata(
                        template_id=config.id,
                        name=metadata_data["name"],
                        description=metadata_data.get("description"),
                        category=TemplateCategory(metadata_data.get("category", "custom")),
                        tags=metadata_data.get("tags", []),
                        author=metadata_data.get("author", ""),
                        organization=metadata_data.get("organization", ""),
                        license=metadata_data.get("license", ""),
                        documentation=metadata_data.get("documentation", "")
                    )
                except:
                    # Create default metadata
                    metadata = TemplateMetadata(
                        template_id=config.id,
                        name=config.name,
                        description=config.description,
                        category=TemplateCategory.CUSTOM
                    )
                
                # Create template
                created_config, _ = await self.create_template_with_metadata(config, metadata)
                
                logger.info(f"Template imported: {created_config.id}")
                return created_config
                
        except Exception as e:
            logger.error(f"Failed to import template: {e}")
            raise
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive template manager statistics."""
        engine_stats = self._template_engine.get_engine_statistics()
        
        # Calculate additional statistics
        total_versions = sum(len(versions) for versions in self._versions.values())
        total_shares = sum(len(sharing_list) for sharing_list in self._sharing.values())
        
        category_counts = {
            category.value: len(templates) 
            for category, templates in self._categories.items()
        }
        
        return {
            **engine_stats,
            "total_versions": total_versions,
            "total_shares": total_shares,
            "total_collections": len(self._collections),
            "templates_by_category": category_counts,
            "search_index_size": {
                "tags": len(self._tag_index),
                "authors": len(self._author_index)
            }
        }
    
    def _update_search_indices(self, template_id: UUID, metadata: TemplateMetadata) -> None:
        """Update search indices for template."""
        # Update tag index
        for tag in metadata.tags:
            if tag not in self._tag_index:
                self._tag_index[tag] = set()
            self._tag_index[tag].add(template_id)
        
        # Update author index
        if metadata.author:
            if metadata.author not in self._author_index:
                self._author_index[metadata.author] = set()
            self._author_index[metadata.author].add(template_id)
    
    def _update_tag_index(self, template_id: UUID, old_tags: Set[str], new_tags: Set[str]) -> None:
        """Update tag index when tags change."""
        # Remove from old tags
        for tag in old_tags - new_tags:
            if tag in self._tag_index:
                self._tag_index[tag].discard(template_id)
                if not self._tag_index[tag]:
                    del self._tag_index[tag]
        
        # Add to new tags
        for tag in new_tags - old_tags:
            if tag not in self._tag_index:
                self._tag_index[tag] = set()
            self._tag_index[tag].add(template_id)


# Global template manager instance
_template_manager: Optional[TemplateManager] = None


def get_template_manager(session: Optional[Session] = None) -> TemplateManager:
    """Get the global template manager instance."""
    global _template_manager
    if _template_manager is None:
        _template_manager = TemplateManager(session)
    return _template_manager


def initialize_template_manager(session: Optional[Session] = None) -> TemplateManager:
    """Initialize the template manager."""
    global _template_manager
    _template_manager = TemplateManager(session)
    logger.info("Template Manager initialized successfully")
    return _template_manager