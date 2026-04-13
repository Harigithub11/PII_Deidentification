"""
Redis Service for Queue Management and Caching

Provides Redis-based persistent queues and caching functionality
for the batch processing system.
"""

import logging
import json
import pickle
import asyncio
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
import redis.asyncio as redis
from redis.asyncio.retry import Retry
from redis.asyncio.backoff import ExponentialBackoff

from ..config.settings import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class RedisService:
    """Redis service for queue management and caching."""
    
    def __init__(self):
        self._pool: Optional[redis.ConnectionPool] = None
        self._redis: Optional[redis.Redis] = None
        self._connected = False
        
        # Configuration
        self.host = getattr(settings, 'redis_host', 'localhost')
        self.port = getattr(settings, 'redis_port', 6379)
        self.db = getattr(settings, 'redis_db', 0)
        self.password = getattr(settings, 'redis_password', None)
        self.max_connections = getattr(settings, 'redis_max_connections', 20)
        self.connection_timeout = getattr(settings, 'redis_connection_timeout', 5)
        self.socket_keepalive = getattr(settings, 'redis_socket_keepalive', True)
        self.socket_keepalive_options = getattr(settings, 'redis_socket_keepalive_options', {})
        self.retry_on_timeout = getattr(settings, 'redis_retry_on_timeout', True)
        
        # Queue settings
        self.default_queue_name = 'batch_jobs'
        self.priority_queue_prefix = 'priority_jobs'
        self.result_queue_name = 'job_results'
        self.dead_letter_queue_name = 'failed_jobs'
        
        # Cache settings
        self.cache_prefix = 'batch_cache'
        self.default_ttl = 3600  # 1 hour
        
        logger.info(f"Redis service configured for {self.host}:{self.port}/{self.db}")
    
    async def connect(self) -> bool:
        """Establish Redis connection."""
        try:
            if self._connected:
                return True
            
            # Create connection pool
            self._pool = redis.ConnectionPool(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                max_connections=self.max_connections,
                socket_connect_timeout=self.connection_timeout,
                socket_keepalive=self.socket_keepalive,
                socket_keepalive_options=self.socket_keepalive_options,
                retry_on_timeout=self.retry_on_timeout,
                retry=Retry(ExponentialBackoff(), 3),
                decode_responses=False  # We'll handle encoding ourselves
            )
            
            # Create Redis client
            self._redis = redis.Redis(connection_pool=self._pool)
            
            # Test connection
            await self._redis.ping()
            
            self._connected = True
            logger.info("✅ Redis connection established")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._connected = False
            return False
    
    async def disconnect(self) -> None:
        """Close Redis connection."""
        try:
            if self._redis:
                await self._redis.close()
            if self._pool:
                await self._pool.disconnect()
            
            self._connected = False
            logger.info("Redis connection closed")
            
        except Exception as e:
            logger.error(f"Error closing Redis connection: {e}")
    
    async def is_connected(self) -> bool:
        """Check if Redis is connected."""
        try:
            if not self._redis or not self._connected:
                return False
            
            await self._redis.ping()
            return True
            
        except Exception:
            self._connected = False
            return False
    
    @asynccontextmanager
    async def get_redis(self):
        """Get Redis client with automatic connection management."""
        if not await self.is_connected():
            if not await self.connect():
                raise ConnectionError("Failed to connect to Redis")
        
        try:
            yield self._redis
        finally:
            # Connection pool handles cleanup
            pass
    
    # Queue Operations
    
    async def enqueue_job(self, job_data: Dict[str, Any], 
                         priority: str = 'normal',
                         queue_name: Optional[str] = None) -> bool:
        """
        Enqueue a job for processing.
        
        Args:
            job_data: Job data to enqueue
            priority: Job priority (urgent, critical, high, normal, low)
            queue_name: Custom queue name (optional)
            
        Returns:
            True if successful
        """
        try:
            async with self.get_redis() as redis_client:
                # Serialize job data
                serialized_data = json.dumps({
                    **job_data,
                    'enqueued_at': datetime.now(timezone.utc).isoformat(),
                    'priority': priority
                }, default=str)
                
                # Determine queue name based on priority
                if queue_name:
                    target_queue = queue_name
                elif priority in ['urgent', 'critical']:
                    target_queue = f"{self.priority_queue_prefix}:{priority}"
                else:
                    target_queue = self.default_queue_name
                
                # Add to queue (LPUSH for FIFO via BRPOP)
                await redis_client.lpush(target_queue, serialized_data)
                
                # Track queue statistics
                await self._update_queue_stats(redis_client, target_queue, 'enqueued')
                
                logger.debug(f"Enqueued job to {target_queue}: {job_data.get('id')}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to enqueue job: {e}")
            return False
    
    async def dequeue_job(self, queue_names: Optional[List[str]] = None,
                         timeout: int = 5) -> Optional[Dict[str, Any]]:
        """
        Dequeue a job from the specified queues.
        
        Args:
            queue_names: List of queue names to check (in priority order)
            timeout: Blocking timeout in seconds
            
        Returns:
            Job data or None
        """
        try:
            async with self.get_redis() as redis_client:
                if not queue_names:
                    # Default priority order
                    queue_names = [
                        f"{self.priority_queue_prefix}:urgent",
                        f"{self.priority_queue_prefix}:critical", 
                        f"{self.priority_queue_prefix}:high",
                        self.default_queue_name
                    ]
                
                # Blocking right pop from multiple queues
                result = await redis_client.brpop(queue_names, timeout=timeout)
                
                if result:
                    queue_name, serialized_data = result
                    job_data = json.loads(serialized_data)
                    
                    # Track queue statistics
                    await self._update_queue_stats(redis_client, queue_name.decode(), 'dequeued')
                    
                    logger.debug(f"Dequeued job from {queue_name.decode()}: {job_data.get('id')}")
                    return job_data
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to dequeue job: {e}")
            return None
    
    async def get_queue_length(self, queue_name: str) -> int:
        """Get the length of a queue."""
        try:
            async with self.get_redis() as redis_client:
                return await redis_client.llen(queue_name)
        except Exception as e:
            logger.error(f"Failed to get queue length for {queue_name}: {e}")
            return 0
    
    async def get_all_queue_lengths(self) -> Dict[str, int]:
        """Get lengths of all known queues."""
        try:
            async with self.get_redis() as redis_client:
                queues = [
                    self.default_queue_name,
                    f"{self.priority_queue_prefix}:urgent",
                    f"{self.priority_queue_prefix}:critical",
                    f"{self.priority_queue_prefix}:high",
                    self.dead_letter_queue_name
                ]
                
                lengths = {}
                for queue in queues:
                    lengths[queue] = await redis_client.llen(queue)
                
                return lengths
                
        except Exception as e:
            logger.error(f"Failed to get queue lengths: {e}")
            return {}
    
    async def move_to_dead_letter_queue(self, job_data: Dict[str, Any], 
                                       error_info: Dict[str, Any]) -> bool:
        """
        Move a failed job to dead letter queue.
        
        Args:
            job_data: Original job data
            error_info: Error information
            
        Returns:
            True if successful
        """
        try:
            async with self.get_redis() as redis_client:
                dead_letter_data = {
                    **job_data,
                    'failed_at': datetime.now(timezone.utc).isoformat(),
                    'error_info': error_info,
                    'original_queue': job_data.get('original_queue', self.default_queue_name)
                }
                
                serialized_data = json.dumps(dead_letter_data, default=str)
                await redis_client.lpush(self.dead_letter_queue_name, serialized_data)
                
                logger.info(f"Moved job to dead letter queue: {job_data.get('id')}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to move job to dead letter queue: {e}")
            return False
    
    async def retry_dead_letter_jobs(self, max_jobs: int = 10) -> int:
        """
        Retry jobs from dead letter queue.
        
        Args:
            max_jobs: Maximum number of jobs to retry
            
        Returns:
            Number of jobs retried
        """
        try:
            async with self.get_redis() as redis_client:
                retried = 0
                
                for _ in range(max_jobs):
                    # Get job from dead letter queue
                    result = await redis_client.rpop(self.dead_letter_queue_name)
                    if not result:
                        break
                    
                    try:
                        job_data = json.loads(result)
                        original_queue = job_data.get('original_queue', self.default_queue_name)
                        
                        # Remove dead letter specific fields
                        clean_job_data = {k: v for k, v in job_data.items() 
                                        if k not in ['failed_at', 'error_info', 'original_queue']}
                        
                        # Re-enqueue to original queue
                        if await self.enqueue_job(clean_job_data, queue_name=original_queue):
                            retried += 1
                            logger.info(f"Retried job from dead letter queue: {job_data.get('id')}")
                        else:
                            # Put back in dead letter queue if re-enqueue fails
                            await redis_client.rpush(self.dead_letter_queue_name, result)
                            
                    except Exception as e:
                        logger.error(f"Failed to retry dead letter job: {e}")
                        # Put back in dead letter queue
                        await redis_client.rpush(self.dead_letter_queue_name, result)
                
                return retried
                
        except Exception as e:
            logger.error(f"Failed to retry dead letter jobs: {e}")
            return 0
    
    # Caching Operations
    
    async def cache_set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set a cache value.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            
        Returns:
            True if successful
        """
        try:
            async with self.get_redis() as redis_client:
                cache_key = f"{self.cache_prefix}:{key}"
                
                # Serialize value
                if isinstance(value, (dict, list)):
                    serialized_value = json.dumps(value, default=str)
                elif isinstance(value, (str, int, float, bool)):
                    serialized_value = str(value)
                else:
                    # Use pickle for complex objects
                    serialized_value = pickle.dumps(value)
                
                # Set with TTL
                ttl = ttl or self.default_ttl
                await redis_client.setex(cache_key, ttl, serialized_value)
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to set cache key {key}: {e}")
            return False
    
    async def cache_get(self, key: str, default: Any = None) -> Any:
        """
        Get a cache value.
        
        Args:
            key: Cache key
            default: Default value if not found
            
        Returns:
            Cached value or default
        """
        try:
            async with self.get_redis() as redis_client:
                cache_key = f"{self.cache_prefix}:{key}"
                value = await redis_client.get(cache_key)
                
                if value is None:
                    return default
                
                # Try to deserialize as JSON first
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    # Try pickle
                    try:
                        return pickle.loads(value)
                    except (pickle.PickleError, TypeError):
                        # Return as string
                        return value.decode() if isinstance(value, bytes) else value
                        
        except Exception as e:
            logger.error(f"Failed to get cache key {key}: {e}")
            return default
    
    async def cache_delete(self, key: str) -> bool:
        """Delete a cache key."""
        try:
            async with self.get_redis() as redis_client:
                cache_key = f"{self.cache_prefix}:{key}"
                result = await redis_client.delete(cache_key)
                return result > 0
        except Exception as e:
            logger.error(f"Failed to delete cache key {key}: {e}")
            return False
    
    async def cache_exists(self, key: str) -> bool:
        """Check if a cache key exists."""
        try:
            async with self.get_redis() as redis_client:
                cache_key = f"{self.cache_prefix}:{key}"
                result = await redis_client.exists(cache_key)
                return result > 0
        except Exception as e:
            logger.error(f"Failed to check cache key {key}: {e}")
            return False
    
    # Distributed Locks
    
    async def acquire_lock(self, lock_name: str, timeout: int = 10, 
                          blocking_timeout: int = 5) -> Optional[str]:
        """
        Acquire a distributed lock.
        
        Args:
            lock_name: Name of the lock
            timeout: Lock timeout in seconds
            blocking_timeout: How long to wait for lock
            
        Returns:
            Lock identifier or None
        """
        try:
            async with self.get_redis() as redis_client:
                lock_key = f"lock:{lock_name}"
                lock_value = f"{datetime.now(timezone.utc).isoformat()}"
                
                # Try to acquire lock with timeout
                end_time = datetime.now(timezone.utc) + timedelta(seconds=blocking_timeout)
                
                while datetime.now(timezone.utc) < end_time:
                    # Try to set lock with NX (only if not exists) and EX (expiry)
                    result = await redis_client.set(lock_key, lock_value, nx=True, ex=timeout)
                    if result:
                        return lock_value
                    
                    await asyncio.sleep(0.1)
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to acquire lock {lock_name}: {e}")
            return None
    
    async def release_lock(self, lock_name: str, lock_value: str) -> bool:
        """
        Release a distributed lock.
        
        Args:
            lock_name: Name of the lock
            lock_value: Lock identifier from acquire_lock
            
        Returns:
            True if successful
        """
        try:
            async with self.get_redis() as redis_client:
                lock_key = f"lock:{lock_name}"
                
                # Lua script to atomically check and delete lock
                lua_script = """
                if redis.call('get', KEYS[1]) == ARGV[1] then
                    return redis.call('del', KEYS[1])
                else
                    return 0
                end
                """
                
                result = await redis_client.eval(lua_script, 1, lock_key, lock_value)
                return result == 1
                
        except Exception as e:
            logger.error(f"Failed to release lock {lock_name}: {e}")
            return False
    
    # Statistics and Monitoring
    
    async def _update_queue_stats(self, redis_client: redis.Redis, 
                                 queue_name: str, operation: str) -> None:
        """Update queue statistics."""
        try:
            stats_key = f"stats:queue:{queue_name}"
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Increment operation counter
            await redis_client.hincrby(stats_key, f"{operation}_count", 1)
            await redis_client.hset(stats_key, f"last_{operation}_at", timestamp)
            
            # Set expiry for stats (keep for 7 days)
            await redis_client.expire(stats_key, 604800)
            
        except Exception as e:
            logger.debug(f"Failed to update queue stats: {e}")
    
    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        try:
            async with self.get_redis() as redis_client:
                stats = {}
                
                # Get queue lengths
                queue_lengths = await self.get_all_queue_lengths()
                stats['queue_lengths'] = queue_lengths
                
                # Get detailed stats for each queue
                queue_stats = {}
                for queue_name in queue_lengths.keys():
                    stats_key = f"stats:queue:{queue_name}"
                    queue_stat_data = await redis_client.hgetall(stats_key)
                    
                    if queue_stat_data:
                        # Decode bytes keys and values
                        decoded_stats = {}
                        for k, v in queue_stat_data.items():
                            key = k.decode() if isinstance(k, bytes) else k
                            value = v.decode() if isinstance(v, bytes) else v
                            
                            # Convert count values to integers
                            if key.endswith('_count'):
                                try:
                                    value = int(value)
                                except ValueError:
                                    pass
                            
                            decoded_stats[key] = value
                        
                        queue_stats[queue_name] = decoded_stats
                
                stats['queue_stats'] = queue_stats
                
                # Get Redis info
                redis_info = await redis_client.info()
                stats['redis_info'] = {
                    'connected_clients': redis_info.get('connected_clients', 0),
                    'used_memory_human': redis_info.get('used_memory_human', '0B'),
                    'total_commands_processed': redis_info.get('total_commands_processed', 0),
                    'keyspace_hits': redis_info.get('keyspace_hits', 0),
                    'keyspace_misses': redis_info.get('keyspace_misses', 0)
                }
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get queue stats: {e}")
            return {}
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform Redis health check."""
        try:
            start_time = datetime.now(timezone.utc)
            
            # Test connection
            connected = await self.is_connected()
            
            if connected:
                async with self.get_redis() as redis_client:
                    # Test ping
                    ping_start = datetime.now(timezone.utc)
                    await redis_client.ping()
                    ping_time = (datetime.now(timezone.utc) - ping_start).total_seconds() * 1000
                    
                    # Test set/get
                    test_key = f"{self.cache_prefix}:health_check"
                    test_value = "health_check_value"
                    
                    await redis_client.set(test_key, test_value, ex=60)
                    retrieved_value = await redis_client.get(test_key)
                    await redis_client.delete(test_key)
                    
                    # Get basic info
                    info = await redis_client.info()
                    
                    total_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                    
                    return {
                        "status": "healthy",
                        "connected": True,
                        "ping_time_ms": ping_time,
                        "total_check_time_ms": total_time,
                        "redis_version": info.get('redis_version', 'unknown'),
                        "used_memory": info.get('used_memory_human', '0B'),
                        "connected_clients": info.get('connected_clients', 0),
                        "operations_per_sec": info.get('instantaneous_ops_per_sec', 0)
                    }
            else:
                return {
                    "status": "unhealthy",
                    "connected": False,
                    "error": "Not connected to Redis"
                }
                
        except Exception as e:
            return {
                "status": "unhealthy", 
                "connected": False,
                "error": str(e)
            }


# Global Redis service instance
_redis_service: Optional[RedisService] = None


def get_redis_service() -> RedisService:
    """Get the global Redis service instance."""
    global _redis_service
    if _redis_service is None:
        _redis_service = RedisService()
    return _redis_service


async def initialize_redis_service() -> RedisService:
    """Initialize the Redis service and establish connection."""
    redis_service = get_redis_service()
    if await redis_service.connect():
        logger.info("Redis service initialized successfully")
        return redis_service
    else:
        raise ConnectionError("Failed to initialize Redis service")