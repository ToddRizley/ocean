import asyncio
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from logging.handlers import MemoryHandler
from typing import Any

from loguru import logger

from port_ocean import Ocean
from port_ocean.context.ocean import ocean


def _serialize_record(record: logging.LogRecord) -> dict[str, Any]:
    return {
        "message": record.msg,
        "level": record.levelname,
        "timestamp": datetime.utcfromtimestamp(record.created).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        "extra": record.__dict__["extra"],
    }


class HTTPMemoryHandler(MemoryHandler):
    def __init__(
        self,
        capacity: int = 100,
        flush_level: int = logging.FATAL,
        flush_interval: int = 5,
        flush_size: int = 1024,
    ):
        super().__init__(capacity, flushLevel=flush_level, target=None)
        self.flush_interval = flush_interval
        self.flush_size = flush_size
        self.last_flush_time = time.time()
        self._serialized_buffer: list[dict[str, Any]] = []

    @property
    def ocean(self) -> Ocean | None:
        # We want to wait for the context to be initialized before we can send logs
        if ocean.initialized:
            return ocean.app
        return None

    def emit(self, record: logging.LogRecord) -> None:
        self._serialized_buffer.append(_serialize_record(record))
        super().emit(record)

    def shouldFlush(self, record: logging.LogRecord) -> bool:
        """
        Extending shouldFlush to include size and time validation as part of the decision whether to flush
        """
        if bool(self.buffer) and (
            super(HTTPMemoryHandler, self).shouldFlush(record)
            or sys.getsizeof(self.buffer) >= self.flush_size
            or time.time() - self.last_flush_time >= self.flush_interval
        ):
            return True
        return False

    def flush(self) -> None:
        if self.ocean is None or not self.buffer:
            return

        self.acquire()
        logs = list(self._serialized_buffer)
        if logs:
            self.buffer.clear()
            self._serialized_buffer.clear()
            self.last_flush_time = time.time()
            loop = asyncio.new_event_loop()
            with ThreadPoolExecutor() as executor:
                executor.submit(
                    lambda: asyncio.run_coroutine_threadsafe(
                        self.send_logs(self.ocean, logs), loop
                    )
                )
        self.release()

    async def send_logs(
        self, _ocean: Ocean, logs_to_send: list[dict[str, Any]]
    ) -> None:
        try:
            await _ocean.port_client.ingest_integration_logs(logs_to_send)
        except Exception as e:
            logger.debug(f"Failed to send logs to Port with error: {e}")
