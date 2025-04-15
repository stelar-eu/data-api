import redis
from flask import current_app

from exceptions import (
    BackendError,
    NotFoundError,
)


class RedisClient:
    _pool = None

    def _initialize_redis(cls):
        app = current_app._get_current_object()
        with app.app_context():
            config = app.config["settings"]
            cls._pool = redis.ConnectionPool(
                host=config["REDIS_HOST"],
                port=config["REDIS_PORT"],
                db=1,
                decode_responses=True,
                max_connections=10,
            )
            return cls._pool

    def set(self, key, value):
        """Set a value in Redis using a connection from the pool."""
        try:
            if self._pool is None:
                self._initialize_redis()
            conn = redis.Redis(connection_pool=self._pool)
            conn.set(key, value)
        except Exception as e:
            raise BackendError(f"Redis error: {str(e)}")

    def get(self, key):
        """Get a value from Redis using a connection from the pool."""
        try:
            if self._pool is None:
                self._initialize_redis()
            conn = redis.Redis(connection_pool=self._pool)
            value = conn.get(key)
            return value
        except Exception as e:
            raise BackendError(f"Redis error: {str(e)}")


# Create a singleton instance of RedisClient
REDIS = RedisClient()
