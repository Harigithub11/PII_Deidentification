"""
Forensic Capabilities and Evidence Collection

Provides comprehensive forensic evidence collection, chain of custody tracking,
and analysis capabilities for security incidents.
"""

import asyncio
import logging
import json
import hashlib
import time
import gzip
import shutil
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import uuid
import aiosqlite
from cryptography.fernet import Fernet
import tarfile
import zipfile

logger = logging.getLogger(__name__)


class EvidenceType(Enum):
    """Types of forensic evidence."""
    LOG_FILES = "log_files"
    NETWORK_CAPTURE = "network_capture"
    SYSTEM_SNAPSHOT = "system_snapshot"
    MEMORY_DUMP = "memory_dump"
    FILE_ARTIFACT = "file_artifact"
    DATABASE_DUMP = "database_dump"
    CONFIGURATION_FILES = "configuration_files"
    USER_ACTIVITY = "user_activity"
    API_REQUESTS = "api_requests"
    AUTHENTICATION_LOGS = "authentication_logs"
    ERROR_LOGS = "error_logs"
    SECURITY_EVENTS = "security_events"
    PROCESS_INFORMATION = "process_information"
    NETWORK_CONNECTIONS = "network_connections"
    CUSTOM_EVIDENCE = "custom_evidence"


class EvidenceStatus(Enum):
    """Status of evidence collection."""
    PENDING = "pending"
    COLLECTING = "collecting"
    COLLECTED = "collected"
    PROCESSED = "processed"
    ARCHIVED = "archived"
    ERROR = "error"
    EXPIRED = "expired"


class ChainOfCustodyAction(Enum):
    """Chain of custody actions."""
    CREATED = "created"
    ACCESSED = "accessed"
    MODIFIED = "modified"
    COPIED = "copied"
    MOVED = "moved"
    ARCHIVED = "archived"
    DELETED = "deleted"
    ANALYZED = "analyzed"
    EXPORTED = "exported"


@dataclass
class ChainOfCustodyEntry:
    """Chain of custody tracking entry."""
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action: ChainOfCustodyAction = ChainOfCustodyAction.ACCESSED
    actor: str = "system"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    location: str = ""
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    digital_signature: Optional[str] = None


@dataclass
class EvidenceItem:
    """Represents a piece of forensic evidence."""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: EvidenceType = EvidenceType.LOG_FILES
    name: str = ""
    description: str = ""
    source: str = ""
    file_path: Optional[str] = None
    file_size: int = 0
    file_hash: str = ""
    hash_algorithm: str = "sha256"
    content_type: str = "application/octet-stream"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    collected_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    status: EvidenceStatus = EvidenceStatus.PENDING
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    chain_of_custody: List[ChainOfCustodyEntry] = field(default_factory=list)
    related_incidents: List[str] = field(default_factory=list)
    related_threats: List[str] = field(default_factory=list)
    encryption_key_id: Optional[str] = None
    compression_method: Optional[str] = None
    integrity_verified: bool = False
    
    def add_custody_entry(self, action: ChainOfCustodyAction, actor: str, 
                         description: str = "", location: str = "", 
                         metadata: Dict[str, Any] = None):
        """Add a chain of custody entry."""
        entry = ChainOfCustodyEntry(
            action=action,
            actor=actor,
            timestamp=datetime.now(timezone.utc),
            location=location,
            description=description,
            metadata=metadata or {},
            digital_signature=self._generate_signature(action, actor, description)
        )
        self.chain_of_custody.append(entry)
    
    def _generate_signature(self, action: ChainOfCustodyAction, actor: str, description: str) -> str:
        """Generate digital signature for custody entry."""
        content = f"{self.evidence_id}:{action.value}:{actor}:{datetime.now(timezone.utc).isoformat()}:{description}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify evidence integrity using hash."""
        if not self.file_path or not Path(self.file_path).exists():
            return False
        
        try:
            current_hash = self._calculate_file_hash(self.file_path)
            return current_hash == self.file_hash
        except Exception as e:
            logger.error(f"Error verifying evidence integrity: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate file hash."""
        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()


class EvidenceCollector:
    """Collects various types of forensic evidence."""
    
    def __init__(self, storage_path: str = "evidence_storage"):
        """Initialize evidence collector."""
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        # Create subdirectories for organization
        (self.storage_path / "logs").mkdir(exist_ok=True)
        (self.storage_path / "network").mkdir(exist_ok=True)
        (self.storage_path / "system").mkdir(exist_ok=True)
        (self.storage_path / "artifacts").mkdir(exist_ok=True)
        (self.storage_path / "temp").mkdir(exist_ok=True)
        
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for evidence protection."""
        key_file = self.storage_path / ".encryption_key"
        
        if key_file.exists():
            try:
                with open(key_file, 'rb') as f:
                    return f.read()
            except Exception:
                pass
        
        # Create new key
        key = Fernet.generate_key()
        try:
            with open(key_file, 'wb') as f:
                f.write(key)
            # Make key file read-only
            key_file.chmod(0o600)
        except Exception as e:
            logger.error(f"Error saving encryption key: {e}")
        
        return key
    
    async def collect_log_evidence(self, log_paths: List[str], 
                                 incident_id: str = None,
                                 time_range: Tuple[datetime, datetime] = None) -> EvidenceItem:
        """Collect log file evidence."""
        try:
            evidence = EvidenceItem(
                evidence_type=EvidenceType.LOG_FILES,
                name=f"log_evidence_{int(time.time())}",
                description="Collected log files for forensic analysis",
                source="log_collector"
            )
            
            if incident_id:
                evidence.related_incidents.append(incident_id)
            
            # Create evidence directory
            evidence_dir = self.storage_path / "logs" / evidence.evidence_id
            evidence_dir.mkdir(exist_ok=True)
            
            collected_files = []
            total_size = 0
            
            for log_path in log_paths:
                source_path = Path(log_path)
                if source_path.exists() and source_path.is_file():
                    # Filter by time range if specified
                    if time_range:
                        filtered_content = await self._filter_logs_by_time(source_path, time_range)
                        if not filtered_content:
                            continue
                        
                        # Save filtered content
                        dest_path = evidence_dir / f"filtered_{source_path.name}"
                        with open(dest_path, 'w') as f:
                            f.write(filtered_content)
                    else:
                        # Copy entire file
                        dest_path = evidence_dir / source_path.name
                        shutil.copy2(source_path, dest_path)
                    
                    collected_files.append(str(dest_path))
                    total_size += dest_path.stat().st_size
            
            if collected_files:
                # Create archive
                archive_path = evidence_dir / f"{evidence.evidence_id}_logs.tar.gz"
                await self._create_archive(collected_files, archive_path)
                
                # Encrypt archive
                encrypted_path = await self._encrypt_file(archive_path)
                
                # Update evidence metadata
                evidence.file_path = str(encrypted_path)
                evidence.file_size = encrypted_path.stat().st_size
                evidence.file_hash = evidence._calculate_file_hash(str(encrypted_path))
                evidence.status = EvidenceStatus.COLLECTED
                evidence.collected_at = datetime.now(timezone.utc)
                evidence.metadata = {
                    'original_files': log_paths,
                    'collected_files': len(collected_files),
                    'archive_method': 'tar.gz',
                    'encrypted': True,
                    'time_range': [t.isoformat() for t in time_range] if time_range else None
                }
                
                # Add custody entry
                evidence.add_custody_entry(
                    ChainOfCustodyAction.CREATED,
                    "evidence_collector",
                    f"Collected {len(collected_files)} log files",
                    str(evidence_dir)
                )
                
                # Clean up temporary files
                for file_path in collected_files:
                    Path(file_path).unlink(missing_ok=True)
                archive_path.unlink(missing_ok=True)
            
            else:
                evidence.status = EvidenceStatus.ERROR
                evidence.metadata['error'] = "No valid log files found"
            
            return evidence
            
        except Exception as e:
            logger.error(f"Error collecting log evidence: {e}")
            evidence.status = EvidenceStatus.ERROR
            evidence.metadata['error'] = str(e)
            return evidence
    
    async def collect_network_evidence(self, connection_info: Dict[str, Any],
                                     duration: int = 300) -> EvidenceItem:
        """Collect network traffic evidence."""
        try:
            evidence = EvidenceItem(
                evidence_type=EvidenceType.NETWORK_CAPTURE,
                name=f"network_evidence_{int(time.time())}",
                description="Network traffic capture for forensic analysis",
                source="network_collector"
            )
            
            # Create evidence file
            evidence_file = self.storage_path / "network" / f"{evidence.evidence_id}_network.json"
            
            # Simulate network capture (in production, would integrate with actual network monitoring)
            network_data = {
                'capture_start': datetime.now(timezone.utc).isoformat(),
                'duration': duration,
                'connection_info': connection_info,
                'captured_packets': [],  # Would contain actual packet data
                'metadata': {
                    'capture_method': 'simulated',
                    'filter_applied': connection_info.get('filter'),
                    'interfaces': connection_info.get('interfaces', ['eth0'])
                }
            }
            
            # Add simulated packet data
            for i in range(10):  # Simulate 10 packets
                packet = {
                    'timestamp': (datetime.now(timezone.utc) + timedelta(seconds=i)).isoformat(),
                    'src_ip': connection_info.get('src_ip', '192.168.1.100'),
                    'dst_ip': connection_info.get('dst_ip', '10.0.0.1'),
                    'protocol': connection_info.get('protocol', 'TCP'),
                    'src_port': connection_info.get('src_port', 80),
                    'dst_port': connection_info.get('dst_port', 443),
                    'payload_size': 1024 + i * 64,
                    'flags': ['SYN', 'ACK'][i % 2]
                }
                network_data['captured_packets'].append(packet)
            
            # Save and encrypt network data
            with open(evidence_file, 'w') as f:
                json.dump(network_data, f, indent=2)
            
            encrypted_path = await self._encrypt_file(evidence_file)
            
            # Update evidence metadata
            evidence.file_path = str(encrypted_path)
            evidence.file_size = encrypted_path.stat().st_size
            evidence.file_hash = evidence._calculate_file_hash(str(encrypted_path))
            evidence.status = EvidenceStatus.COLLECTED
            evidence.collected_at = datetime.now(timezone.utc)
            evidence.metadata = {
                'capture_duration': duration,
                'packet_count': len(network_data['captured_packets']),
                'connection_info': connection_info,
                'encrypted': True
            }
            
            # Add custody entry
            evidence.add_custody_entry(
                ChainOfCustodyAction.CREATED,
                "network_collector",
                f"Captured network traffic for {duration} seconds",
                str(evidence_file.parent)
            )
            
            # Clean up unencrypted file
            evidence_file.unlink(missing_ok=True)
            
            return evidence
            
        except Exception as e:
            logger.error(f"Error collecting network evidence: {e}")
            evidence.status = EvidenceStatus.ERROR
            evidence.metadata['error'] = str(e)
            return evidence
    
    async def collect_system_snapshot(self, components: List[str] = None) -> EvidenceItem:
        """Collect system state snapshot."""
        try:
            evidence = EvidenceItem(
                evidence_type=EvidenceType.SYSTEM_SNAPSHOT,
                name=f"system_snapshot_{int(time.time())}",
                description="System state snapshot for forensic analysis",
                source="system_collector"
            )
            
            components = components or ['processes', 'network', 'files', 'users', 'services']
            
            # Create snapshot data
            snapshot_data = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'hostname': 'localhost',  # Would get actual hostname
                'components': components,
                'data': {}
            }
            
            # Collect system information (simulated)
            if 'processes' in components:
                snapshot_data['data']['processes'] = [
                    {'pid': 1234, 'name': 'python', 'user': 'app', 'cpu': 5.2, 'memory': 128.5},
                    {'pid': 5678, 'name': 'nginx', 'user': 'www-data', 'cpu': 1.1, 'memory': 64.2}
                ]
            
            if 'network' in components:
                snapshot_data['data']['network'] = {
                    'active_connections': [
                        {'local': '127.0.0.1:8000', 'remote': '192.168.1.100:45678', 'state': 'ESTABLISHED'},
                        {'local': '0.0.0.0:443', 'remote': '*', 'state': 'LISTEN'}
                    ],
                    'interfaces': [
                        {'name': 'eth0', 'ip': '192.168.1.10', 'status': 'UP'},
                        {'name': 'lo', 'ip': '127.0.0.1', 'status': 'UP'}
                    ]
                }
            
            if 'users' in components:
                snapshot_data['data']['users'] = [
                    {'username': 'admin', 'uid': 1000, 'last_login': datetime.now(timezone.utc).isoformat()},
                    {'username': 'app', 'uid': 1001, 'last_login': (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()}
                ]
            
            # Save snapshot
            snapshot_file = self.storage_path / "system" / f"{evidence.evidence_id}_snapshot.json"
            with open(snapshot_file, 'w') as f:
                json.dump(snapshot_data, f, indent=2)
            
            # Encrypt snapshot
            encrypted_path = await self._encrypt_file(snapshot_file)
            
            # Update evidence metadata
            evidence.file_path = str(encrypted_path)
            evidence.file_size = encrypted_path.stat().st_size
            evidence.file_hash = evidence._calculate_file_hash(str(encrypted_path))
            evidence.status = EvidenceStatus.COLLECTED
            evidence.collected_at = datetime.now(timezone.utc)
            evidence.metadata = {
                'components': components,
                'snapshot_time': snapshot_data['timestamp'],
                'encrypted': True
            }
            
            # Add custody entry
            evidence.add_custody_entry(
                ChainOfCustodyAction.CREATED,
                "system_collector",
                f"Created system snapshot with components: {', '.join(components)}",
                str(snapshot_file.parent)
            )
            
            # Clean up unencrypted file
            snapshot_file.unlink(missing_ok=True)
            
            return evidence
            
        except Exception as e:
            logger.error(f"Error collecting system snapshot: {e}")
            evidence.status = EvidenceStatus.ERROR
            evidence.metadata['error'] = str(e)
            return evidence
    
    async def collect_user_activity(self, user_id: str, 
                                  time_range: Tuple[datetime, datetime] = None) -> EvidenceItem:
        """Collect user activity evidence."""
        try:
            evidence = EvidenceItem(
                evidence_type=EvidenceType.USER_ACTIVITY,
                name=f"user_activity_{user_id}_{int(time.time())}",
                description=f"User activity evidence for {user_id}",
                source="activity_collector"
            )
            
            # Simulate user activity collection
            activity_data = {
                'user_id': user_id,
                'collection_time': datetime.now(timezone.utc).isoformat(),
                'time_range': [t.isoformat() for t in time_range] if time_range else None,
                'activities': []
            }
            
            # Generate sample activity data
            activities = [
                {'timestamp': datetime.now(timezone.utc).isoformat(), 'action': 'login', 'ip': '192.168.1.100'},
                {'timestamp': (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(), 'action': 'document_access', 'resource': 'document_123'},
                {'timestamp': (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat(), 'action': 'api_request', 'endpoint': '/api/v1/documents'},
                {'timestamp': (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), 'action': 'file_upload', 'filename': 'sensitive_data.pdf'}
            ]
            
            # Filter by time range if specified
            if time_range:
                start_time, end_time = time_range
                activities = [
                    act for act in activities
                    if start_time <= datetime.fromisoformat(act['timestamp']) <= end_time
                ]
            
            activity_data['activities'] = activities
            
            # Save activity data
            activity_file = self.storage_path / "artifacts" / f"{evidence.evidence_id}_activity.json"
            with open(activity_file, 'w') as f:
                json.dump(activity_data, f, indent=2)
            
            # Encrypt file
            encrypted_path = await self._encrypt_file(activity_file)
            
            # Update evidence metadata
            evidence.file_path = str(encrypted_path)
            evidence.file_size = encrypted_path.stat().st_size
            evidence.file_hash = evidence._calculate_file_hash(str(encrypted_path))
            evidence.status = EvidenceStatus.COLLECTED
            evidence.collected_at = datetime.now(timezone.utc)
            evidence.metadata = {
                'user_id': user_id,
                'activity_count': len(activities),
                'time_range': [t.isoformat() for t in time_range] if time_range else None,
                'encrypted': True
            }
            
            # Add custody entry
            evidence.add_custody_entry(
                ChainOfCustodyAction.CREATED,
                "activity_collector",
                f"Collected activity evidence for user {user_id}",
                str(activity_file.parent)
            )
            
            # Clean up unencrypted file
            activity_file.unlink(missing_ok=True)
            
            return evidence
            
        except Exception as e:
            logger.error(f"Error collecting user activity: {e}")
            evidence.status = EvidenceStatus.ERROR
            evidence.metadata['error'] = str(e)
            return evidence
    
    async def _filter_logs_by_time(self, log_path: Path, 
                                 time_range: Tuple[datetime, datetime]) -> str:
        """Filter log file content by time range."""
        try:
            filtered_lines = []
            start_time, end_time = time_range
            
            with open(log_path, 'r') as f:
                for line in f:
                    # Extract timestamp from log line (simplified)
                    # In production, would parse various log formats
                    timestamp_match = re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', line)
                    if timestamp_match:
                        try:
                            log_time = datetime.fromisoformat(timestamp_match.group().replace(' ', 'T'))
                            if start_time <= log_time <= end_time:
                                filtered_lines.append(line)
                        except ValueError:
                            # If timestamp parsing fails, include the line
                            filtered_lines.append(line)
                    else:
                        # Include lines without timestamps
                        filtered_lines.append(line)
            
            return ''.join(filtered_lines)
            
        except Exception as e:
            logger.error(f"Error filtering logs: {e}")
            return ""
    
    async def _create_archive(self, file_paths: List[str], archive_path: Path):
        """Create compressed archive of files."""
        try:
            with tarfile.open(archive_path, 'w:gz') as tar:
                for file_path in file_paths:
                    if Path(file_path).exists():
                        tar.add(file_path, arcname=Path(file_path).name)
        except Exception as e:
            logger.error(f"Error creating archive: {e}")
            raise
    
    async def _encrypt_file(self, file_path: Path) -> Path:
        """Encrypt a file and return path to encrypted version."""
        try:
            encrypted_path = file_path.with_suffix(file_path.suffix + '.enc')
            
            with open(file_path, 'rb') as infile:
                with open(encrypted_path, 'wb') as outfile:
                    data = infile.read()
                    encrypted_data = self.cipher_suite.encrypt(data)
                    outfile.write(encrypted_data)
            
            return encrypted_path
            
        except Exception as e:
            logger.error(f"Error encrypting file: {e}")
            raise
    
    async def decrypt_evidence(self, evidence: EvidenceItem, output_path: str = None) -> str:
        """Decrypt evidence file."""
        try:
            if not evidence.file_path or not Path(evidence.file_path).exists():
                raise ValueError("Evidence file not found")
            
            if not output_path:
                output_path = str(Path(evidence.file_path).with_suffix(''))
                if output_path.endswith('.enc'):
                    output_path = output_path[:-4]
            
            with open(evidence.file_path, 'rb') as infile:
                with open(output_path, 'wb') as outfile:
                    encrypted_data = infile.read()
                    decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                    outfile.write(decrypted_data)
            
            # Add custody entry
            evidence.add_custody_entry(
                ChainOfCustodyAction.ACCESSED,
                "evidence_collector",
                "Evidence decrypted for analysis",
                output_path
            )
            
            return output_path
            
        except Exception as e:
            logger.error(f"Error decrypting evidence: {e}")
            raise


class EvidenceManager:
    """Manages forensic evidence storage and retrieval."""
    
    def __init__(self, db_path: str = "forensic_evidence.db"):
        """Initialize evidence manager."""
        self.db_path = db_path
        self.evidence_storage: Dict[str, EvidenceItem] = {}
        self._retention_days = 365  # Keep evidence for 1 year by default
    
    async def initialize(self):
        """Initialize the evidence manager."""
        try:
            await self._create_database()
            await self._load_evidence_from_db()
            
            # Start background cleanup task
            asyncio.create_task(self._evidence_cleanup_task())
            
            logger.info(f"Evidence Manager initialized with {len(self.evidence_storage)} evidence items")
            
        except Exception as e:
            logger.error(f"Failed to initialize Evidence Manager: {e}")
            raise
    
    async def _create_database(self):
        """Create evidence database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS evidence_items (
                    evidence_id TEXT PRIMARY KEY,
                    evidence_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    source TEXT NOT NULL,
                    file_path TEXT,
                    file_size INTEGER DEFAULT 0,
                    file_hash TEXT,
                    hash_algorithm TEXT DEFAULT 'sha256',
                    content_type TEXT DEFAULT 'application/octet-stream',
                    created_at TEXT NOT NULL,
                    collected_at TEXT,
                    expires_at TEXT,
                    status TEXT DEFAULT 'pending',
                    tags TEXT,
                    metadata TEXT,
                    related_incidents TEXT,
                    related_threats TEXT,
                    encryption_key_id TEXT,
                    compression_method TEXT,
                    integrity_verified INTEGER DEFAULT 0
                )
            """)
            
            await db.execute("""
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    entry_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    location TEXT,
                    description TEXT,
                    metadata TEXT,
                    digital_signature TEXT,
                    FOREIGN KEY (evidence_id) REFERENCES evidence_items (evidence_id)
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence_items(evidence_type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence_items(status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_custody_evidence ON chain_of_custody(evidence_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_custody_timestamp ON chain_of_custody(timestamp)")
            
            await db.commit()
    
    async def store_evidence(self, evidence: EvidenceItem) -> bool:
        """Store evidence item."""
        try:
            self.evidence_storage[evidence.evidence_id] = evidence
            await self._save_evidence_to_db(evidence)
            
            logger.info(f"Stored evidence: {evidence.evidence_id} ({evidence.evidence_type.value})")
            return True
            
        except Exception as e:
            logger.error(f"Error storing evidence {evidence.evidence_id}: {e}")
            return False
    
    async def retrieve_evidence(self, evidence_id: str) -> Optional[EvidenceItem]:
        """Retrieve evidence item."""
        evidence = self.evidence_storage.get(evidence_id)
        if evidence:
            # Add custody entry for access
            evidence.add_custody_entry(
                ChainOfCustodyAction.ACCESSED,
                "evidence_manager",
                "Evidence retrieved from storage"
            )
            await self._update_custody_in_db(evidence)
        
        return evidence
    
    async def search_evidence(self, criteria: Dict[str, Any]) -> List[EvidenceItem]:
        """Search evidence based on criteria."""
        matching_evidence = []
        
        for evidence in self.evidence_storage.values():
            if self._matches_criteria(evidence, criteria):
                matching_evidence.append(evidence)
        
        return matching_evidence
    
    def _matches_criteria(self, evidence: EvidenceItem, criteria: Dict[str, Any]) -> bool:
        """Check if evidence matches search criteria."""
        try:
            if 'evidence_type' in criteria:
                if evidence.evidence_type.value != criteria['evidence_type']:
                    return False
            
            if 'status' in criteria:
                if evidence.status.value != criteria['status']:
                    return False
            
            if 'source' in criteria:
                if evidence.source != criteria['source']:
                    return False
            
            if 'tags' in criteria:
                required_tags = set(criteria['tags'])
                if not required_tags.issubset(evidence.tags):
                    return False
            
            if 'incident_id' in criteria:
                if criteria['incident_id'] not in evidence.related_incidents:
                    return False
            
            if 'date_range' in criteria:
                start_date, end_date = criteria['date_range']
                if not (start_date <= evidence.created_at <= end_date):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error matching criteria: {e}")
            return False
    
    async def _load_evidence_from_db(self):
        """Load evidence from database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT * FROM evidence_items") as cursor:
                    async for row in cursor:
                        evidence = await self._row_to_evidence(row)
                        self.evidence_storage[evidence.evidence_id] = evidence
        except Exception as e:
            logger.error(f"Error loading evidence from database: {e}")
    
    async def _row_to_evidence(self, row) -> EvidenceItem:
        """Convert database row to EvidenceItem."""
        evidence = EvidenceItem(
            evidence_id=row[0],
            evidence_type=EvidenceType(row[1]),
            name=row[2],
            description=row[3] or "",
            source=row[4],
            file_path=row[5],
            file_size=row[6],
            file_hash=row[7] or "",
            hash_algorithm=row[8],
            content_type=row[9],
            created_at=datetime.fromisoformat(row[10]),
            collected_at=datetime.fromisoformat(row[11]) if row[11] else None,
            expires_at=datetime.fromisoformat(row[12]) if row[12] else None,
            status=EvidenceStatus(row[13]),
            tags=set(json.loads(row[14] or "[]")),
            metadata=json.loads(row[15] or "{}"),
            related_incidents=json.loads(row[16] or "[]"),
            related_threats=json.loads(row[17] or "[]"),
            encryption_key_id=row[18],
            compression_method=row[19],
            integrity_verified=bool(row[20])
        )
        
        # Load chain of custody
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT * FROM chain_of_custody WHERE evidence_id = ? ORDER BY timestamp",
                (evidence.evidence_id,)
            ) as cursor:
                async for custody_row in cursor:
                    entry = ChainOfCustodyEntry(
                        entry_id=custody_row[0],
                        action=ChainOfCustodyAction(custody_row[2]),
                        actor=custody_row[3],
                        timestamp=datetime.fromisoformat(custody_row[4]),
                        location=custody_row[5] or "",
                        description=custody_row[6] or "",
                        metadata=json.loads(custody_row[7] or "{}"),
                        digital_signature=custody_row[8]
                    )
                    evidence.chain_of_custody.append(entry)
        
        return evidence
    
    async def _save_evidence_to_db(self, evidence: EvidenceItem):
        """Save evidence to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO evidence_items (
                    evidence_id, evidence_type, name, description, source,
                    file_path, file_size, file_hash, hash_algorithm, content_type,
                    created_at, collected_at, expires_at, status, tags, metadata,
                    related_incidents, related_threats, encryption_key_id,
                    compression_method, integrity_verified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence.evidence_id,
                evidence.evidence_type.value,
                evidence.name,
                evidence.description,
                evidence.source,
                evidence.file_path,
                evidence.file_size,
                evidence.file_hash,
                evidence.hash_algorithm,
                evidence.content_type,
                evidence.created_at.isoformat(),
                evidence.collected_at.isoformat() if evidence.collected_at else None,
                evidence.expires_at.isoformat() if evidence.expires_at else None,
                evidence.status.value,
                json.dumps(list(evidence.tags)),
                json.dumps(evidence.metadata),
                json.dumps(evidence.related_incidents),
                json.dumps(evidence.related_threats),
                evidence.encryption_key_id,
                evidence.compression_method,
                evidence.integrity_verified
            ))
            
            # Save chain of custody
            for entry in evidence.chain_of_custody:
                await db.execute("""
                    INSERT OR REPLACE INTO chain_of_custody (
                        entry_id, evidence_id, action, actor, timestamp,
                        location, description, metadata, digital_signature
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.entry_id,
                    evidence.evidence_id,
                    entry.action.value,
                    entry.actor,
                    entry.timestamp.isoformat(),
                    entry.location,
                    entry.description,
                    json.dumps(entry.metadata),
                    entry.digital_signature
                ))
            
            await db.commit()
    
    async def _update_custody_in_db(self, evidence: EvidenceItem):
        """Update chain of custody in database."""
        async with aiosqlite.connect(self.db_path) as db:
            # Get the latest custody entry
            if evidence.chain_of_custody:
                entry = evidence.chain_of_custody[-1]
                await db.execute("""
                    INSERT INTO chain_of_custody (
                        entry_id, evidence_id, action, actor, timestamp,
                        location, description, metadata, digital_signature
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.entry_id,
                    evidence.evidence_id,
                    entry.action.value,
                    entry.actor,
                    entry.timestamp.isoformat(),
                    entry.location,
                    entry.description,
                    json.dumps(entry.metadata),
                    entry.digital_signature
                ))
                await db.commit()
    
    async def _evidence_cleanup_task(self):
        """Background task to clean up expired evidence."""
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                expired_evidence = []
                
                for evidence_id, evidence in list(self.evidence_storage.items()):
                    # Check for expiration
                    if evidence.expires_at and current_time > evidence.expires_at:
                        expired_evidence.append(evidence_id)
                    
                    # Check retention policy
                    elif (current_time - evidence.created_at).days > self._retention_days:
                        expired_evidence.append(evidence_id)
                
                # Archive and remove expired evidence
                for evidence_id in expired_evidence:
                    evidence = self.evidence_storage[evidence_id]
                    evidence.status = EvidenceStatus.EXPIRED
                    evidence.add_custody_entry(
                        ChainOfCustodyAction.ARCHIVED,
                        "evidence_manager",
                        "Evidence archived due to expiration"
                    )
                    
                    # Remove from storage
                    del self.evidence_storage[evidence_id]
                    
                    # Update database
                    await self._save_evidence_to_db(evidence)
                
                if expired_evidence:
                    logger.info(f"Archived {len(expired_evidence)} expired evidence items")
                
                # Run cleanup every 24 hours
                await asyncio.sleep(24 * 3600)
                
            except Exception as e:
                logger.error(f"Error in evidence cleanup task: {e}")
                await asyncio.sleep(3600)
    
    async def get_evidence_summary(self) -> Dict[str, Any]:
        """Get evidence management summary."""
        try:
            total_evidence = len(self.evidence_storage)
            
            # Count by type
            type_counts = {}
            for evidence_type in EvidenceType:
                type_counts[evidence_type.value] = sum(
                    1 for evidence in self.evidence_storage.values()
                    if evidence.evidence_type == evidence_type
                )
            
            # Count by status
            status_counts = {}
            for status in EvidenceStatus:
                status_counts[status.value] = sum(
                    1 for evidence in self.evidence_storage.values()
                    if evidence.status == status
                )
            
            # Calculate total storage size
            total_size = sum(
                evidence.file_size for evidence in self.evidence_storage.values()
                if evidence.file_size
            )
            
            return {
                'total_evidence': total_evidence,
                'type_distribution': type_counts,
                'status_distribution': status_counts,
                'total_storage_bytes': total_size,
                'retention_days': self._retention_days
            }
            
        except Exception as e:
            logger.error(f"Error getting evidence summary: {e}")
            return {}
    
    async def shutdown(self):
        """Shutdown the evidence manager."""
        logger.info("Evidence Manager shutdown complete")


class ForensicsCollector:
    """Main forensics coordinator."""
    
    def __init__(self, storage_path: str = "forensic_evidence"):
        """Initialize forensics collector."""
        self.evidence_collector = EvidenceCollector(storage_path)
        self.evidence_manager = EvidenceManager()
    
    async def initialize(self):
        """Initialize forensics collector."""
        await self.evidence_manager.initialize()
        logger.info("Forensics Collector initialized")
    
    async def collect_evidence(self, threat_context: Any) -> List[EvidenceItem]:
        """Collect evidence for a threat context."""
        evidence_items = []
        
        try:
            # Determine what evidence to collect based on threat type
            threat_type = getattr(threat_context, 'threat_type', 'unknown')
            threat_id = getattr(threat_context, 'threat_id', 'unknown')
            metadata = getattr(threat_context, 'metadata', {})
            
            # Collect system snapshot for high-severity threats
            if hasattr(threat_context, 'severity') and threat_context.severity.value in ['high', 'critical']:
                system_evidence = await self.evidence_collector.collect_system_snapshot()
                system_evidence.related_threats.append(threat_id)
                evidence_items.append(system_evidence)
                await self.evidence_manager.store_evidence(system_evidence)
            
            # Collect user activity if user involved
            if 'user_id' in metadata:
                user_evidence = await self.evidence_collector.collect_user_activity(metadata['user_id'])
                user_evidence.related_threats.append(threat_id)
                evidence_items.append(user_evidence)
                await self.evidence_manager.store_evidence(user_evidence)
            
            # Collect network evidence for network-related threats
            if threat_type in ['brute_force_attack', 'network_intrusion', 'data_exfiltration']:
                network_info = {
                    'src_ip': metadata.get('source_ip'),
                    'threat_type': threat_type
                }
                network_evidence = await self.evidence_collector.collect_network_evidence(network_info)
                network_evidence.related_threats.append(threat_id)
                evidence_items.append(network_evidence)
                await self.evidence_manager.store_evidence(network_evidence)
            
            # Collect relevant logs
            log_paths = ['/var/log/security.log', '/var/log/auth.log', '/var/log/application.log']
            log_evidence = await self.evidence_collector.collect_log_evidence(
                log_paths,
                incident_id=threat_id
            )
            log_evidence.related_threats.append(threat_id)
            evidence_items.append(log_evidence)
            await self.evidence_manager.store_evidence(log_evidence)
            
            logger.info(f"Collected {len(evidence_items)} evidence items for threat {threat_id}")
            
        except Exception as e:
            logger.error(f"Error collecting evidence for threat: {e}")
        
        return evidence_items
    
    async def get_evidence_for_incident(self, incident_id: str) -> List[EvidenceItem]:
        """Get all evidence related to an incident."""
        return await self.evidence_manager.search_evidence({'incident_id': incident_id})
    
    async def get_forensics_summary(self) -> Dict[str, Any]:
        """Get forensics system summary."""
        return await self.evidence_manager.get_evidence_summary()
    
    async def shutdown(self):
        """Shutdown forensics collector."""
        await self.evidence_manager.shutdown()
        logger.info("Forensics Collector shutdown complete")