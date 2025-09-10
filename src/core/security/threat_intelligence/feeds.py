"""
External Threat Intelligence Feeds Integration

Integrates with external threat intelligence sources to enhance detection
capabilities with up-to-date threat indicators and intelligence.
"""

import asyncio
import logging
import json
import time
import aiohttp
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import xml.etree.ElementTree as ET
import csv
import re
import aiosqlite

from .indicators import ThreatIndicator, IOCType, ThreatLevel, IndicatorStatus

logger = logging.getLogger(__name__)


class FeedType(Enum):
    """Types of threat intelligence feeds."""
    IOC_FEED = "ioc_feed"
    REPUTATION_FEED = "reputation_feed"
    SIGNATURE_FEED = "signature_feed"
    MALWARE_FEED = "malware_feed"
    PHISHING_FEED = "phishing_feed"
    BOTNET_FEED = "botnet_feed"
    VULNERABILITY_FEED = "vulnerability_feed"
    CUSTOM_FEED = "custom_feed"


class FeedFormat(Enum):
    """Feed data formats."""
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    TEXT = "text"
    STIX = "stix"
    TAXII = "taxii"


class FeedStatus(Enum):
    """Status of threat feeds."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    UPDATING = "updating"
    PAUSED = "paused"


@dataclass
class ThreatFeed:
    """Represents a threat intelligence feed configuration."""
    feed_id: str
    name: str
    feed_type: FeedType
    url: str
    format: FeedFormat
    update_interval: int = 3600  # seconds
    api_key: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    last_update: Optional[datetime] = None
    last_error: Optional[str] = None
    status: FeedStatus = FeedStatus.ACTIVE
    indicators_count: int = 0
    reliability_score: float = 0.8  # 0.0 to 1.0
    parser_config: Dict[str, Any] = field(default_factory=dict)
    rate_limit: Optional[int] = None  # requests per hour
    timeout: int = 30  # seconds
    retries: int = 3
    tags: Set[str] = field(default_factory=set)
    
    def is_due_for_update(self) -> bool:
        """Check if feed is due for an update."""
        if not self.enabled or self.status != FeedStatus.ACTIVE:
            return False
        
        if not self.last_update:
            return True
        
        next_update = self.last_update + timedelta(seconds=self.update_interval)
        return datetime.now(timezone.utc) >= next_update


@dataclass 
class FeedUpdateResult:
    """Result of a feed update operation."""
    feed_id: str
    success: bool
    indicators_added: int = 0
    indicators_updated: int = 0
    indicators_removed: int = 0
    error_message: Optional[str] = None
    update_duration: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class BaseFeedParser:
    """Base class for feed parsers."""
    
    def __init__(self, feed_config: ThreatFeed):
        """Initialize parser with feed configuration."""
        self.feed_config = feed_config
        self.parser_config = feed_config.parser_config
    
    async def parse(self, data: str) -> List[ThreatIndicator]:
        """Parse feed data and extract threat indicators."""
        raise NotImplementedError("Subclasses must implement parse method")
    
    def _create_indicator(self, ioc_value: str, ioc_type: IOCType, 
                         threat_type: str = "unknown", 
                         confidence: float = None,
                         severity: ThreatLevel = ThreatLevel.MEDIUM,
                         metadata: Dict[str, Any] = None) -> ThreatIndicator:
        """Create a threat indicator from parsed data."""
        return ThreatIndicator(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            threat_type=threat_type,
            severity=severity,
            confidence=confidence or self.feed_config.reliability_score,
            source=self.feed_config.name,
            description=f"Indicator from {self.feed_config.name} feed",
            tags=self.feed_config.tags.copy(),
            metadata=metadata or {}
        )


class JSONFeedParser(BaseFeedParser):
    """Parser for JSON format threat feeds."""
    
    async def parse(self, data: str) -> List[ThreatIndicator]:
        """Parse JSON threat feed data."""
        try:
            json_data = json.loads(data)
            indicators = []
            
            # Handle different JSON structures
            if isinstance(json_data, list):
                # Direct list of indicators
                for item in json_data:
                    parsed_indicators = self._parse_json_item(item)
                    indicators.extend(parsed_indicators)
            
            elif isinstance(json_data, dict):
                # Nested structure
                if 'indicators' in json_data:
                    for item in json_data['indicators']:
                        parsed_indicators = self._parse_json_item(item)
                        indicators.extend(parsed_indicators)
                elif 'data' in json_data:
                    for item in json_data['data']:
                        parsed_indicators = self._parse_json_item(item)
                        indicators.extend(parsed_indicators)
                else:
                    # Single indicator
                    parsed_indicators = self._parse_json_item(json_data)
                    indicators.extend(parsed_indicators)
            
            return indicators
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON feed {self.feed_config.feed_id}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing JSON feed {self.feed_config.feed_id}: {e}")
            return []
    
    def _parse_json_item(self, item: Dict[str, Any]) -> List[ThreatIndicator]:
        """Parse individual JSON item."""
        indicators = []
        
        try:
            # Common field mappings
            ioc_mappings = {
                'ip': IOCType.IP_ADDRESS,
                'ip_address': IOCType.IP_ADDRESS,
                'domain': IOCType.DOMAIN,
                'hostname': IOCType.DOMAIN,
                'url': IOCType.URL,
                'hash': IOCType.FILE_HASH_SHA256,
                'md5': IOCType.FILE_HASH_MD5,
                'sha1': IOCType.FILE_HASH_SHA1,
                'sha256': IOCType.FILE_HASH_SHA256,
                'email': IOCType.EMAIL,
                'user_agent': IOCType.USER_AGENT
            }
            
            # Extract IOCs from item
            for field, ioc_type in ioc_mappings.items():
                if field in item and item[field]:
                    ioc_value = str(item[field]).strip()
                    if ioc_value:
                        # Determine threat type and severity
                        threat_type = item.get('threat_type', item.get('type', 'unknown'))
                        severity = self._parse_severity(item.get('severity', item.get('risk', 'medium')))
                        confidence = item.get('confidence', self.feed_config.reliability_score)
                        
                        # Create metadata
                        metadata = {
                            'feed_item': item,
                            'first_seen': item.get('first_seen'),
                            'last_seen': item.get('last_seen'),
                            'source_feed': self.feed_config.name,
                            'malware_family': item.get('malware_family'),
                            'campaign': item.get('campaign')
                        }
                        
                        indicator = self._create_indicator(
                            ioc_value=ioc_value,
                            ioc_type=ioc_type,
                            threat_type=threat_type,
                            confidence=confidence,
                            severity=severity,
                            metadata=metadata
                        )
                        
                        indicators.append(indicator)
            
        except Exception as e:
            logger.error(f"Error parsing JSON item: {e}")
        
        return indicators
    
    def _parse_severity(self, severity_str: str) -> ThreatLevel:
        """Parse severity string to ThreatLevel."""
        severity_mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL,
            'info': ThreatLevel.INFO
        }
        return severity_mapping.get(str(severity_str).lower(), ThreatLevel.MEDIUM)


class CSVFeedParser(BaseFeedParser):
    """Parser for CSV format threat feeds."""
    
    async def parse(self, data: str) -> List[ThreatIndicator]:
        """Parse CSV threat feed data."""
        try:
            indicators = []
            reader = csv.DictReader(data.splitlines())
            
            for row in reader:
                parsed_indicators = self._parse_csv_row(row)
                indicators.extend(parsed_indicators)
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error parsing CSV feed {self.feed_config.feed_id}: {e}")
            return []
    
    def _parse_csv_row(self, row: Dict[str, str]) -> List[ThreatIndicator]:
        """Parse individual CSV row."""
        indicators = []
        
        try:
            # Get column mappings from parser config
            column_mappings = self.parser_config.get('column_mappings', {})
            
            # Default mappings if not specified
            if not column_mappings:
                column_mappings = {
                    'ip': 'ip_address',
                    'domain': 'domain',
                    'url': 'url', 
                    'hash': 'file_hash',
                    'type': 'threat_type',
                    'severity': 'severity'
                }
            
            # Extract IOC value and type
            ioc_value = None
            ioc_type = None
            
            for csv_col, ioc_field in column_mappings.items():
                if csv_col in row and row[csv_col]:
                    value = row[csv_col].strip()
                    if value:
                        ioc_value = value
                        ioc_type = self._determine_ioc_type(ioc_field, value)
                        break
            
            if ioc_value and ioc_type:
                threat_type = row.get('type', row.get('threat_type', 'unknown'))
                severity = self._parse_severity(row.get('severity', 'medium'))
                confidence = float(row.get('confidence', self.feed_config.reliability_score))
                
                metadata = {
                    'csv_row': row,
                    'source_feed': self.feed_config.name
                }
                
                indicator = self._create_indicator(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    threat_type=threat_type,
                    confidence=confidence,
                    severity=severity,
                    metadata=metadata
                )
                
                indicators.append(indicator)
        
        except Exception as e:
            logger.error(f"Error parsing CSV row: {e}")
        
        return indicators
    
    def _determine_ioc_type(self, field_name: str, value: str) -> IOCType:
        """Determine IOC type based on field name and value."""
        field_name = field_name.lower()
        
        if 'ip' in field_name:
            return IOCType.IP_ADDRESS
        elif 'domain' in field_name or 'hostname' in field_name:
            return IOCType.DOMAIN
        elif 'url' in field_name:
            return IOCType.URL
        elif 'hash' in field_name:
            # Determine hash type by length
            value_clean = value.replace('-', '').replace(':', '')
            if len(value_clean) == 32:
                return IOCType.FILE_HASH_MD5
            elif len(value_clean) == 40:
                return IOCType.FILE_HASH_SHA1
            elif len(value_clean) == 64:
                return IOCType.FILE_HASH_SHA256
            else:
                return IOCType.FILE_HASH_SHA256  # Default
        elif 'email' in field_name:
            return IOCType.EMAIL
        else:
            return IOCType.CUSTOM
    
    def _parse_severity(self, severity_str: str) -> ThreatLevel:
        """Parse severity string to ThreatLevel."""
        severity_mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL,
            'info': ThreatLevel.INFO
        }
        return severity_mapping.get(str(severity_str).lower(), ThreatLevel.MEDIUM)


class TextFeedParser(BaseFeedParser):
    """Parser for plain text threat feeds."""
    
    async def parse(self, data: str) -> List[ThreatIndicator]:
        """Parse plain text threat feed data."""
        try:
            indicators = []
            lines = data.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip comments
                    parsed_indicators = self._parse_text_line(line)
                    indicators.extend(parsed_indicators)
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error parsing text feed {self.feed_config.feed_id}: {e}")
            return []
    
    def _parse_text_line(self, line: str) -> List[ThreatIndicator]:
        """Parse individual text line."""
        indicators = []
        
        try:
            # Split line if it contains multiple fields
            parts = line.split()
            ioc_value = parts[0] if parts else line
            
            # Determine IOC type from value pattern
            ioc_type = self._detect_ioc_type(ioc_value)
            
            if ioc_type:
                # Extract additional info if present
                threat_type = parts[1] if len(parts) > 1 else 'unknown'
                severity = self._parse_severity(parts[2] if len(parts) > 2 else 'medium')
                
                metadata = {
                    'line_data': line,
                    'source_feed': self.feed_config.name
                }
                
                indicator = self._create_indicator(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    threat_type=threat_type,
                    severity=severity,
                    metadata=metadata
                )
                
                indicators.append(indicator)
        
        except Exception as e:
            logger.error(f"Error parsing text line: {e}")
        
        return indicators
    
    def _detect_ioc_type(self, value: str) -> Optional[IOCType]:
        """Detect IOC type from value pattern."""
        # IP address pattern
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if re.match(ip_pattern, value):
            return IOCType.IP_ADDRESS
        
        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$'
        if re.match(domain_pattern, value):
            return IOCType.DOMAIN
        
        # URL pattern
        if value.startswith(('http://', 'https://', 'ftp://')):
            return IOCType.URL
        
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return IOCType.FILE_HASH_MD5
        elif re.match(r'^[a-fA-F0-9]{40}$', value):
            return IOCType.FILE_HASH_SHA1
        elif re.match(r'^[a-fA-F0-9]{64}$', value):
            return IOCType.FILE_HASH_SHA256
        
        # Email pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, value):
            return IOCType.EMAIL
        
        return None
    
    def _parse_severity(self, severity_str: str) -> ThreatLevel:
        """Parse severity string to ThreatLevel."""
        severity_mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL,
            'info': ThreatLevel.INFO
        }
        return severity_mapping.get(str(severity_str).lower(), ThreatLevel.MEDIUM)


class ExternalFeedConnector:
    """Connects to external threat intelligence feeds."""
    
    def __init__(self):
        """Initialize feed connector."""
        self.session: Optional[aiohttp.ClientSession] = None
        self.parsers = {
            FeedFormat.JSON: JSONFeedParser,
            FeedFormat.CSV: CSVFeedParser,
            FeedFormat.TEXT: TextFeedParser
        }
    
    async def initialize(self):
        """Initialize the connector."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300),  # 5 minutes
            headers={
                'User-Agent': 'ThreatIntelligence-System/1.0'
            }
        )
    
    async def fetch_feed_data(self, feed: ThreatFeed) -> Optional[str]:
        """Fetch data from a threat feed."""
        if not self.session:
            await self.initialize()
        
        try:
            # Prepare request parameters
            headers = feed.headers.copy()
            if feed.api_key:
                headers['Authorization'] = f'Bearer {feed.api_key}'
            
            params = feed.params.copy()
            
            # Make request with retries
            for attempt in range(feed.retries + 1):
                try:
                    async with self.session.get(
                        feed.url,
                        headers=headers,
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=feed.timeout)
                    ) as response:
                        if response.status == 200:
                            data = await response.text()
                            logger.debug(f"Successfully fetched feed {feed.feed_id}, {len(data)} bytes")
                            return data
                        elif response.status == 429:  # Rate limited
                            retry_after = int(response.headers.get('Retry-After', 60))
                            logger.warning(f"Feed {feed.feed_id} rate limited, waiting {retry_after} seconds")
                            await asyncio.sleep(retry_after)
                        else:
                            logger.error(f"HTTP {response.status} error for feed {feed.feed_id}")
                            
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout fetching feed {feed.feed_id}, attempt {attempt + 1}")
                except Exception as e:
                    logger.error(f"Error fetching feed {feed.feed_id}, attempt {attempt + 1}: {e}")
                
                if attempt < feed.retries:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to fetch feed {feed.feed_id}: {e}")
            return None
    
    async def parse_feed_data(self, feed: ThreatFeed, data: str) -> List[ThreatIndicator]:
        """Parse feed data into threat indicators."""
        try:
            parser_class = self.parsers.get(feed.format)
            if not parser_class:
                logger.error(f"No parser available for format {feed.format.value}")
                return []
            
            parser = parser_class(feed)
            indicators = await parser.parse(data)
            
            logger.info(f"Parsed {len(indicators)} indicators from feed {feed.feed_id}")
            return indicators
            
        except Exception as e:
            logger.error(f"Error parsing feed {feed.feed_id}: {e}")
            return []
    
    async def shutdown(self):
        """Shutdown the connector."""
        if self.session:
            await self.session.close()
            self.session = None


class ThreatFeedManager:
    """Manages multiple threat intelligence feeds."""
    
    def __init__(self, db_path: str = "threat_feeds.db"):
        """Initialize feed manager."""
        self.db_path = db_path
        self.feeds: Dict[str, ThreatFeed] = {}
        self.connector = ExternalFeedConnector()
        self.update_stats: Dict[str, FeedUpdateResult] = {}
        self._setup_default_feeds()
    
    def _setup_default_feeds(self):
        """Setup default threat intelligence feeds."""
        # Example feeds (would be configured based on available services)
        default_feeds = [
            {
                'feed_id': 'abuse_ch_malware',
                'name': 'Abuse.ch Malware Hashes',
                'feed_type': FeedType.MALWARE_FEED,
                'url': 'https://urlhaus.abuse.ch/downloads/text/',
                'format': FeedFormat.TEXT,
                'update_interval': 3600,
                'reliability_score': 0.9,
                'tags': {'malware', 'hashes'}
            },
            {
                'feed_id': 'malwaredomainlist',
                'name': 'MalwareDomainList',
                'url': 'http://www.malwaredomainlist.com/hostslist/hosts.txt',
                'feed_type': FeedType.PHISHING_FEED,
                'format': FeedFormat.TEXT,
                'update_interval': 7200,
                'reliability_score': 0.8,
                'tags': {'phishing', 'domains'}
            },
            {
                'feed_id': 'emergingthreats_compromised',
                'name': 'Emerging Threats Compromised IPs',
                'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                'feed_type': FeedType.IOC_FEED,
                'format': FeedFormat.TEXT,
                'update_interval': 1800,
                'reliability_score': 0.85,
                'tags': {'compromised', 'ips'}
            }
        ]
        
        for feed_data in default_feeds:
            feed = ThreatFeed(**feed_data)
            self.feeds[feed.feed_id] = feed
    
    async def initialize(self):
        """Initialize the feed manager."""
        try:
            await self._create_database()
            await self.connector.initialize()
            await self._load_feeds_from_db()
            
            # Start background update task
            asyncio.create_task(self._feed_update_scheduler())
            
            logger.info(f"Threat Feed Manager initialized with {len(self.feeds)} feeds")
            
        except Exception as e:
            logger.error(f"Failed to initialize Threat Feed Manager: {e}")
            raise
    
    async def _create_database(self):
        """Create feeds database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    feed_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    feed_type TEXT NOT NULL,
                    url TEXT NOT NULL,
                    format TEXT NOT NULL,
                    update_interval INTEGER DEFAULT 3600,
                    api_key TEXT,
                    headers TEXT,
                    params TEXT,
                    enabled INTEGER DEFAULT 1,
                    last_update TEXT,
                    last_error TEXT,
                    status TEXT DEFAULT 'active',
                    indicators_count INTEGER DEFAULT 0,
                    reliability_score REAL DEFAULT 0.8,
                    parser_config TEXT,
                    rate_limit INTEGER,
                    timeout INTEGER DEFAULT 30,
                    retries INTEGER DEFAULT 3,
                    tags TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS feed_update_history (
                    update_id TEXT PRIMARY KEY,
                    feed_id TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    indicators_added INTEGER DEFAULT 0,
                    indicators_updated INTEGER DEFAULT 0,
                    indicators_removed INTEGER DEFAULT 0,
                    error_message TEXT,
                    update_duration REAL DEFAULT 0.0,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (feed_id) REFERENCES threat_feeds (feed_id)
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_feed_status ON threat_feeds(status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_feed_enabled ON threat_feeds(enabled)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_update_timestamp ON feed_update_history(timestamp)")
            
            await db.commit()
    
    async def _load_feeds_from_db(self):
        """Load feed configurations from database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT * FROM threat_feeds") as cursor:
                    async for row in cursor:
                        feed = self._row_to_feed(row)
                        self.feeds[feed.feed_id] = feed
        except Exception as e:
            logger.error(f"Error loading feeds from database: {e}")
    
    def _row_to_feed(self, row) -> ThreatFeed:
        """Convert database row to ThreatFeed object."""
        return ThreatFeed(
            feed_id=row[0],
            name=row[1],
            feed_type=FeedType(row[2]),
            url=row[3],
            format=FeedFormat(row[4]),
            update_interval=row[5],
            api_key=row[6],
            headers=json.loads(row[7] or "{}"),
            params=json.loads(row[8] or "{}"),
            enabled=bool(row[9]),
            last_update=datetime.fromisoformat(row[10]) if row[10] else None,
            last_error=row[11],
            status=FeedStatus(row[12]),
            indicators_count=row[13],
            reliability_score=row[14],
            parser_config=json.loads(row[15] or "{}"),
            rate_limit=row[16],
            timeout=row[17],
            retries=row[18],
            tags=set(json.loads(row[19] or "[]"))
        )
    
    async def add_feed(self, feed: ThreatFeed) -> bool:
        """Add a new threat feed."""
        try:
            self.feeds[feed.feed_id] = feed
            await self._save_feed_to_db(feed)
            logger.info(f"Added threat feed: {feed.feed_id}")
            return True
        except Exception as e:
            logger.error(f"Error adding feed {feed.feed_id}: {e}")
            return False
    
    async def remove_feed(self, feed_id: str) -> bool:
        """Remove a threat feed."""
        try:
            if feed_id in self.feeds:
                del self.feeds[feed_id]
                
                async with aiosqlite.connect(self.db_path) as db:
                    await db.execute("DELETE FROM threat_feeds WHERE feed_id = ?", (feed_id,))
                    await db.commit()
                
                logger.info(f"Removed threat feed: {feed_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing feed {feed_id}: {e}")
            return False
    
    async def update_feed(self, feed_id: str) -> FeedUpdateResult:
        """Update a specific threat feed."""
        if feed_id not in self.feeds:
            return FeedUpdateResult(
                feed_id=feed_id,
                success=False,
                error_message="Feed not found"
            )
        
        feed = self.feeds[feed_id]
        start_time = time.time()
        
        try:
            feed.status = FeedStatus.UPDATING
            
            # Fetch feed data
            data = await self.connector.fetch_feed_data(feed)
            if not data:
                result = FeedUpdateResult(
                    feed_id=feed_id,
                    success=False,
                    error_message="Failed to fetch feed data",
                    update_duration=time.time() - start_time
                )
                feed.status = FeedStatus.ERROR
                feed.last_error = "Failed to fetch data"
                return result
            
            # Parse indicators
            indicators = await self.connector.parse_feed_data(feed, data)
            
            # Update feed status
            feed.status = FeedStatus.ACTIVE
            feed.last_update = datetime.now(timezone.utc)
            feed.last_error = None
            feed.indicators_count = len(indicators)
            
            # Create update result
            result = FeedUpdateResult(
                feed_id=feed_id,
                success=True,
                indicators_added=len(indicators),
                update_duration=time.time() - start_time
            )
            
            # Save update result
            await self._save_update_result(result)
            await self._update_feed_in_db(feed)
            
            # Store update result for retrieval
            self.update_stats[feed_id] = result
            
            logger.info(f"Updated feed {feed_id}: {len(indicators)} indicators in {result.update_duration:.2f}s")
            
            # Return indicators for processing by indicator manager
            # (This would typically be handled by the calling system)
            
            return result
            
        except Exception as e:
            feed.status = FeedStatus.ERROR
            feed.last_error = str(e)
            
            result = FeedUpdateResult(
                feed_id=feed_id,
                success=False,
                error_message=str(e),
                update_duration=time.time() - start_time
            )
            
            await self._save_update_result(result)
            await self._update_feed_in_db(feed)
            
            logger.error(f"Error updating feed {feed_id}: {e}")
            return result
    
    async def update_all_feeds(self) -> Dict[str, FeedUpdateResult]:
        """Update all enabled feeds that are due for update."""
        results = {}
        
        # Get feeds that need updating
        feeds_to_update = [
            feed for feed in self.feeds.values()
            if feed.is_due_for_update()
        ]
        
        logger.info(f"Updating {len(feeds_to_update)} feeds")
        
        # Update feeds concurrently (with rate limiting)
        semaphore = asyncio.Semaphore(3)  # Max 3 concurrent updates
        
        async def update_with_semaphore(feed):
            async with semaphore:
                return await self.update_feed(feed.feed_id)
        
        update_tasks = [update_with_semaphore(feed) for feed in feeds_to_update]
        
        if update_tasks:
            update_results = await asyncio.gather(*update_tasks, return_exceptions=True)
            
            for result in update_results:
                if isinstance(result, FeedUpdateResult):
                    results[result.feed_id] = result
                elif isinstance(result, Exception):
                    logger.error(f"Exception during feed update: {result}")
        
        return results
    
    async def _feed_update_scheduler(self):
        """Background task to schedule feed updates."""
        while True:
            try:
                # Update all due feeds
                await self.update_all_feeds()
                
                # Sleep for 5 minutes before checking again
                await asyncio.sleep(300)
                
            except Exception as e:
                logger.error(f"Error in feed update scheduler: {e}")
                await asyncio.sleep(300)
    
    async def _save_feed_to_db(self, feed: ThreatFeed):
        """Save feed configuration to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO threat_feeds (
                    feed_id, name, feed_type, url, format, update_interval,
                    api_key, headers, params, enabled, last_update, last_error,
                    status, indicators_count, reliability_score, parser_config,
                    rate_limit, timeout, retries, tags, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                feed.feed_id,
                feed.name,
                feed.feed_type.value,
                feed.url,
                feed.format.value,
                feed.update_interval,
                feed.api_key,
                json.dumps(feed.headers),
                json.dumps(feed.params),
                feed.enabled,
                feed.last_update.isoformat() if feed.last_update else None,
                feed.last_error,
                feed.status.value,
                feed.indicators_count,
                feed.reliability_score,
                json.dumps(feed.parser_config),
                feed.rate_limit,
                feed.timeout,
                feed.retries,
                json.dumps(list(feed.tags)),
                datetime.now(timezone.utc).isoformat()
            ))
            await db.commit()
    
    async def _update_feed_in_db(self, feed: ThreatFeed):
        """Update feed in database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE threat_feeds SET
                    last_update = ?, last_error = ?, status = ?,
                    indicators_count = ?, updated_at = ?
                WHERE feed_id = ?
            """, (
                feed.last_update.isoformat() if feed.last_update else None,
                feed.last_error,
                feed.status.value,
                feed.indicators_count,
                datetime.now(timezone.utc).isoformat(),
                feed.feed_id
            ))
            await db.commit()
    
    async def _save_update_result(self, result: FeedUpdateResult):
        """Save update result to database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO feed_update_history (
                        update_id, feed_id, success, indicators_added,
                        indicators_updated, indicators_removed, error_message,
                        update_duration, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    result.feed_id,
                    result.success,
                    result.indicators_added,
                    result.indicators_updated,
                    result.indicators_removed,
                    result.error_message,
                    result.update_duration,
                    result.timestamp.isoformat()
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error saving update result: {e}")
    
    async def get_feed_status(self) -> Dict[str, Any]:
        """Get status of all feeds."""
        try:
            total_feeds = len(self.feeds)
            active_feeds = sum(1 for feed in self.feeds.values() if feed.status == FeedStatus.ACTIVE)
            error_feeds = sum(1 for feed in self.feeds.values() if feed.status == FeedStatus.ERROR)
            
            # Count by type
            type_counts = {}
            for feed_type in FeedType:
                type_counts[feed_type.value] = sum(
                    1 for feed in self.feeds.values() if feed.feed_type == feed_type
                )
            
            # Recent updates
            recent_updates = len([
                result for result in self.update_stats.values()
                if (datetime.now(timezone.utc) - result.timestamp).total_seconds() < 3600
            ])
            
            return {
                'total_feeds': total_feeds,
                'active_feeds': active_feeds,
                'error_feeds': error_feeds,
                'feed_type_distribution': type_counts,
                'recent_updates_1h': recent_updates,
                'total_indicators': sum(feed.indicators_count for feed in self.feeds.values())
            }
            
        except Exception as e:
            logger.error(f"Error getting feed status: {e}")
            return {}
    
    async def enable_feed(self, feed_id: str) -> bool:
        """Enable a threat feed."""
        if feed_id in self.feeds:
            self.feeds[feed_id].enabled = True
            await self._update_feed_in_db(self.feeds[feed_id])
            return True
        return False
    
    async def disable_feed(self, feed_id: str) -> bool:
        """Disable a threat feed."""
        if feed_id in self.feeds:
            self.feeds[feed_id].enabled = False
            await self._update_feed_in_db(self.feeds[feed_id])
            return True
        return False
    
    async def shutdown(self):
        """Shutdown the feed manager."""
        await self.connector.shutdown()
        logger.info("Threat Feed Manager shutdown complete")