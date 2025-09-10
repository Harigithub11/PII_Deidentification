"""
Threat Indicator Management System

Manages threat indicators (IOCs), their storage, matching, and lifecycle management.
Supports various indicator types including IP addresses, domains, file hashes, and behavioral patterns.
"""

import asyncio
import hashlib
import ipaddress
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import sqlite3
import aiosqlite
from pathlib import Path

logger = logging.getLogger(__name__)


class IOCType(Enum):
    """Types of Indicators of Compromise (IOCs)."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain" 
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    USER_AGENT = "user_agent"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    PROCESS_NAME = "process_name"
    NETWORK_SIGNATURE = "network_signature"
    BEHAVIORAL_PATTERN = "behavioral_pattern"
    YARA_RULE = "yara_rule"
    CUSTOM = "custom"


class ThreatLevel(Enum):
    """Threat severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IndicatorStatus(Enum):
    """Status of threat indicators."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    EXPIRED = "expired"
    FALSE_POSITIVE = "false_positive"
    UNDER_REVIEW = "under_review"


@dataclass
class ThreatIndicator:
    """Represents a threat indicator (IOC)."""
    ioc_value: str
    ioc_type: IOCType
    threat_type: str
    severity: ThreatLevel
    confidence: float
    source: str
    description: str = ""
    tags: Set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expiration: Optional[datetime] = None
    status: IndicatorStatus = IndicatorStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)
    hit_count: int = 0
    false_positive_count: int = 0
    
    def __post_init__(self):
        """Post-initialization processing."""
        # Normalize IOC value based on type
        self.ioc_value = self._normalize_ioc_value()
        
        # Set expiration if not specified
        if not self.expiration:
            self.expiration = self.first_seen + timedelta(days=30)  # Default 30 days
    
    def _normalize_ioc_value(self) -> str:
        """Normalize IOC value based on its type."""
        value = self.ioc_value.strip().lower()
        
        if self.ioc_type == IOCType.IP_ADDRESS:
            try:
                # Validate and normalize IP address
                ip = ipaddress.ip_address(value)
                return str(ip)
            except ValueError:
                logger.warning(f"Invalid IP address: {value}")
                return value
        
        elif self.ioc_type == IOCType.DOMAIN:
            # Remove protocol and trailing slash
            value = re.sub(r'^https?://', '', value)
            value = value.rstrip('/')
            return value
        
        elif self.ioc_type in [IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256]:
            # Normalize hash to lowercase
            return value.lower()
        
        elif self.ioc_type == IOCType.EMAIL:
            return value.lower()
        
        return value
    
    def is_expired(self) -> bool:
        """Check if the indicator has expired."""
        if not self.expiration:
            return False
        return datetime.now(timezone.utc) > self.expiration
    
    def is_active(self) -> bool:
        """Check if the indicator is currently active."""
        return (self.status == IndicatorStatus.ACTIVE and 
                not self.is_expired())
    
    def calculate_reputation_score(self) -> float:
        """Calculate reputation score based on hit count and false positives."""
        if self.hit_count == 0:
            return self.confidence
        
        false_positive_rate = self.false_positive_count / self.hit_count
        reputation_adjustment = 1.0 - (false_positive_rate * 0.5)
        
        return min(self.confidence * reputation_adjustment, 1.0)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert indicator to dictionary format."""
        return {
            'ioc_value': self.ioc_value,
            'ioc_type': self.ioc_type.value,
            'threat_type': self.threat_type,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'source': self.source,
            'description': self.description,
            'tags': list(self.tags),
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'expiration': self.expiration.isoformat() if self.expiration else None,
            'status': self.status.value,
            'metadata': self.metadata,
            'hit_count': self.hit_count,
            'false_positive_count': self.false_positive_count,
            'reputation_score': self.calculate_reputation_score()
        }


class ThreatIndicatorMatcher:
    """Matches events against threat indicators."""
    
    def __init__(self):
        """Initialize the matcher."""
        self.ip_indicators: Dict[str, ThreatIndicator] = {}
        self.domain_indicators: Dict[str, ThreatIndicator] = {}
        self.hash_indicators: Dict[str, ThreatIndicator] = {}
        self.pattern_indicators: List[ThreatIndicator] = []
        self.compiled_patterns: Dict[str, re.Pattern] = {}
    
    def add_indicator(self, indicator: ThreatIndicator):
        """Add an indicator to the matcher."""
        if not indicator.is_active():
            return
        
        if indicator.ioc_type == IOCType.IP_ADDRESS:
            self.ip_indicators[indicator.ioc_value] = indicator
        
        elif indicator.ioc_type == IOCType.DOMAIN:
            self.domain_indicators[indicator.ioc_value] = indicator
        
        elif indicator.ioc_type in [IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256]:
            self.hash_indicators[indicator.ioc_value] = indicator
        
        elif indicator.ioc_type in [IOCType.USER_AGENT, IOCType.URL, IOCType.BEHAVIORAL_PATTERN]:
            self.pattern_indicators.append(indicator)
            # Compile regex pattern for efficient matching
            try:
                pattern = re.compile(indicator.ioc_value, re.IGNORECASE)
                self.compiled_patterns[indicator.ioc_value] = pattern
            except re.error:
                logger.warning(f"Invalid regex pattern for indicator: {indicator.ioc_value}")
    
    def remove_indicator(self, indicator: ThreatIndicator):
        """Remove an indicator from the matcher."""
        if indicator.ioc_type == IOCType.IP_ADDRESS:
            self.ip_indicators.pop(indicator.ioc_value, None)
        
        elif indicator.ioc_type == IOCType.DOMAIN:
            self.domain_indicators.pop(indicator.ioc_value, None)
        
        elif indicator.ioc_type in [IOCType.FILE_HASH_MD5, IOCType.FILE_HASH_SHA1, IOCType.FILE_HASH_SHA256]:
            self.hash_indicators.pop(indicator.ioc_value, None)
        
        elif indicator.ioc_type in [IOCType.USER_AGENT, IOCType.URL, IOCType.BEHAVIORAL_PATTERN]:
            self.pattern_indicators = [ind for ind in self.pattern_indicators if ind != indicator]
            self.compiled_patterns.pop(indicator.ioc_value, None)
    
    def match_event(self, event: Dict[str, Any]) -> List[ThreatIndicator]:
        """Match an event against all indicators."""
        matches = []
        
        # IP address matching
        source_ip = event.get('source_ip') or event.get('client_ip')
        if source_ip and source_ip in self.ip_indicators:
            matches.append(self.ip_indicators[source_ip])
        
        # Domain matching
        domain = event.get('domain') or event.get('hostname')
        if domain and domain in self.domain_indicators:
            matches.append(self.domain_indicators[domain])
        
        # URL domain extraction and matching
        url = event.get('url') or event.get('path')
        if url:
            extracted_domain = self._extract_domain_from_url(url)
            if extracted_domain and extracted_domain in self.domain_indicators:
                matches.append(self.domain_indicators[extracted_domain])
        
        # File hash matching
        file_hashes = []
        if 'file_hash' in event:
            file_hashes.append(event['file_hash'])
        if 'md5' in event:
            file_hashes.append(event['md5'])
        if 'sha1' in event:
            file_hashes.append(event['sha1'])
        if 'sha256' in event:
            file_hashes.append(event['sha256'])
        
        for file_hash in file_hashes:
            if file_hash and file_hash.lower() in self.hash_indicators:
                matches.append(self.hash_indicators[file_hash.lower()])
        
        # Pattern matching (User-Agent, URLs, etc.)
        text_fields = [
            event.get('user_agent', ''),
            event.get('url', ''),
            event.get('path', ''),
            event.get('query_string', ''),
            event.get('headers', ''),
            str(event.get('body', ''))
        ]
        
        for text_field in text_fields:
            if text_field:
                for pattern_value, compiled_pattern in self.compiled_patterns.items():
                    if compiled_pattern.search(text_field):
                        # Find the corresponding indicator
                        for indicator in self.pattern_indicators:
                            if indicator.ioc_value == pattern_value:
                                matches.append(indicator)
                                break
        
        return matches
    
    def _extract_domain_from_url(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            # Simple domain extraction
            if '://' in url:
                url = url.split('://', 1)[1]
            
            if '/' in url:
                url = url.split('/', 1)[0]
            
            if ':' in url:
                url = url.split(':', 1)[0]
            
            return url.lower() if url else None
        except Exception:
            return None


class ThreatIndicatorManager:
    """Manages threat indicators including storage, retrieval, and lifecycle."""
    
    def __init__(self, db_path: str = "threat_indicators.db"):
        """Initialize the indicator manager."""
        self.db_path = db_path
        self.matcher = ThreatIndicatorMatcher()
        self.indicators: Dict[str, ThreatIndicator] = {}
        self._lock = asyncio.Lock()
    
    async def initialize(self):
        """Initialize the indicator manager and database."""
        try:
            await self._create_database()
            await self._load_indicators()
            
            # Start background tasks
            asyncio.create_task(self._cleanup_expired_indicators())
            
            logger.info(f"Threat Indicator Manager initialized with {len(self.indicators)} indicators")
            
        except Exception as e:
            logger.error(f"Failed to initialize Threat Indicator Manager: {e}")
            raise
    
    async def _create_database(self):
        """Create the indicators database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    ioc_value TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source TEXT NOT NULL,
                    description TEXT,
                    tags TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    expiration TEXT,
                    status TEXT DEFAULT 'active',
                    metadata TEXT,
                    hit_count INTEGER DEFAULT 0,
                    false_positive_count INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for performance
            await db.execute("CREATE INDEX IF NOT EXISTS idx_ioc_type ON threat_indicators(ioc_type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_severity ON threat_indicators(severity)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_status ON threat_indicators(status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_source ON threat_indicators(source)")
            
            await db.commit()
    
    async def _load_indicators(self):
        """Load indicators from database into memory."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT * FROM threat_indicators WHERE status = 'active'") as cursor:
                async for row in cursor:
                    try:
                        indicator = self._row_to_indicator(row)
                        if indicator.is_active():
                            self.indicators[indicator.ioc_value] = indicator
                            self.matcher.add_indicator(indicator)
                    except Exception as e:
                        logger.error(f"Error loading indicator from database: {e}")
    
    def _row_to_indicator(self, row) -> ThreatIndicator:
        """Convert database row to ThreatIndicator object."""
        return ThreatIndicator(
            ioc_value=row[0],
            ioc_type=IOCType(row[1]),
            threat_type=row[2],
            severity=ThreatLevel(row[3]),
            confidence=row[4],
            source=row[5],
            description=row[6] or "",
            tags=set(json.loads(row[7] or "[]")),
            first_seen=datetime.fromisoformat(row[8]),
            last_seen=datetime.fromisoformat(row[9]),
            expiration=datetime.fromisoformat(row[10]) if row[10] else None,
            status=IndicatorStatus(row[11]),
            metadata=json.loads(row[12] or "{}"),
            hit_count=row[13],
            false_positive_count=row[14]
        )
    
    async def add_indicator(self, indicator: ThreatIndicator) -> bool:
        """Add a new threat indicator."""
        async with self._lock:
            try:
                # Check if indicator already exists
                if indicator.ioc_value in self.indicators:
                    # Update existing indicator
                    existing = self.indicators[indicator.ioc_value]
                    existing.last_seen = datetime.now(timezone.utc)
                    existing.hit_count += 1
                    
                    # Update confidence if new source has higher confidence
                    if indicator.confidence > existing.confidence:
                        existing.confidence = indicator.confidence
                        existing.source = indicator.source
                    
                    await self._update_indicator_in_db(existing)
                    return True
                
                # Add new indicator
                self.indicators[indicator.ioc_value] = indicator
                self.matcher.add_indicator(indicator)
                
                # Save to database
                await self._save_indicator_to_db(indicator)
                
                logger.debug(f"Added threat indicator: {indicator.ioc_value} ({indicator.ioc_type.value})")
                return True
                
            except Exception as e:
                logger.error(f"Error adding threat indicator: {e}")
                return False
    
    async def remove_indicator(self, ioc_value: str) -> bool:
        """Remove a threat indicator."""
        async with self._lock:
            try:
                if ioc_value in self.indicators:
                    indicator = self.indicators[ioc_value]
                    
                    # Remove from memory
                    del self.indicators[ioc_value]
                    self.matcher.remove_indicator(indicator)
                    
                    # Update status in database
                    indicator.status = IndicatorStatus.INACTIVE
                    await self._update_indicator_in_db(indicator)
                    
                    logger.debug(f"Removed threat indicator: {ioc_value}")
                    return True
                
                return False
                
            except Exception as e:
                logger.error(f"Error removing threat indicator: {e}")
                return False
    
    async def check_event(self, event: Dict[str, Any]) -> List[ThreatIndicator]:
        """Check an event against all threat indicators."""
        try:
            matches = self.matcher.match_event(event)
            
            # Update hit counts for matched indicators
            for indicator in matches:
                indicator.hit_count += 1
                indicator.last_seen = datetime.now(timezone.utc)
                
                # Update in database (async to avoid blocking)
                asyncio.create_task(self._update_indicator_in_db(indicator))
            
            return matches
            
        except Exception as e:
            logger.error(f"Error checking event against indicators: {e}")
            return []
    
    async def mark_false_positive(self, ioc_value: str) -> bool:
        """Mark an indicator as a false positive."""
        async with self._lock:
            try:
                if ioc_value in self.indicators:
                    indicator = self.indicators[ioc_value]
                    indicator.false_positive_count += 1
                    
                    # If false positive rate is too high, deactivate
                    if (indicator.false_positive_count / max(indicator.hit_count, 1)) > 0.5:
                        indicator.status = IndicatorStatus.FALSE_POSITIVE
                        self.matcher.remove_indicator(indicator)
                    
                    await self._update_indicator_in_db(indicator)
                    return True
                
                return False
                
            except Exception as e:
                logger.error(f"Error marking false positive: {e}")
                return False
    
    async def get_indicator_stats(self) -> Dict[str, Any]:
        """Get statistics about threat indicators."""
        try:
            total_indicators = len(self.indicators)
            active_indicators = sum(1 for ind in self.indicators.values() if ind.is_active())
            
            # Count by severity
            severity_counts = {}
            for severity in ThreatLevel:
                severity_counts[severity.value] = sum(
                    1 for ind in self.indicators.values() 
                    if ind.severity == severity and ind.is_active()
                )
            
            # Count by type
            type_counts = {}
            for ioc_type in IOCType:
                type_counts[ioc_type.value] = sum(
                    1 for ind in self.indicators.values() 
                    if ind.ioc_type == ioc_type and ind.is_active()
                )
            
            # Top sources
            source_counts = {}
            for indicator in self.indicators.values():
                if indicator.is_active():
                    source_counts[indicator.source] = source_counts.get(indicator.source, 0) + 1
            
            return {
                'total_indicators': total_indicators,
                'active_indicators': active_indicators,
                'expired_indicators': total_indicators - active_indicators,
                'severity_distribution': severity_counts,
                'type_distribution': type_counts,
                'top_sources': dict(sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10])
            }
            
        except Exception as e:
            logger.error(f"Error getting indicator stats: {e}")
            return {}
    
    async def _save_indicator_to_db(self, indicator: ThreatIndicator):
        """Save indicator to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO threat_indicators (
                    ioc_value, ioc_type, threat_type, severity, confidence, source,
                    description, tags, first_seen, last_seen, expiration, status,
                    metadata, hit_count, false_positive_count, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                indicator.ioc_value,
                indicator.ioc_type.value,
                indicator.threat_type,
                indicator.severity.value,
                indicator.confidence,
                indicator.source,
                indicator.description,
                json.dumps(list(indicator.tags)),
                indicator.first_seen.isoformat(),
                indicator.last_seen.isoformat(),
                indicator.expiration.isoformat() if indicator.expiration else None,
                indicator.status.value,
                json.dumps(indicator.metadata),
                indicator.hit_count,
                indicator.false_positive_count,
                datetime.now(timezone.utc).isoformat()
            ))
            await db.commit()
    
    async def _update_indicator_in_db(self, indicator: ThreatIndicator):
        """Update indicator in database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE threat_indicators SET
                    last_seen = ?, hit_count = ?, false_positive_count = ?,
                    confidence = ?, status = ?, updated_at = ?
                WHERE ioc_value = ?
            """, (
                indicator.last_seen.isoformat(),
                indicator.hit_count,
                indicator.false_positive_count,
                indicator.confidence,
                indicator.status.value,
                datetime.now(timezone.utc).isoformat(),
                indicator.ioc_value
            ))
            await db.commit()
    
    async def _cleanup_expired_indicators(self):
        """Periodically clean up expired indicators."""
        while True:
            try:
                expired_indicators = []
                
                async with self._lock:
                    for ioc_value, indicator in list(self.indicators.items()):
                        if indicator.is_expired():
                            expired_indicators.append(ioc_value)
                
                # Remove expired indicators
                for ioc_value in expired_indicators:
                    if ioc_value in self.indicators:
                        indicator = self.indicators[ioc_value]
                        indicator.status = IndicatorStatus.EXPIRED
                        
                        del self.indicators[ioc_value]
                        self.matcher.remove_indicator(indicator)
                        
                        await self._update_indicator_in_db(indicator)
                
                if expired_indicators:
                    logger.info(f"Cleaned up {len(expired_indicators)} expired indicators")
                
                # Run cleanup every hour
                await asyncio.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error in indicator cleanup: {e}")
                await asyncio.sleep(3600)
    
    async def shutdown(self):
        """Shutdown the indicator manager."""
        logger.info("Shutting down Threat Indicator Manager")
        # Any cleanup needed here