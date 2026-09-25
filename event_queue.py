"""
Async Event Queue - SwarmSentinel
=================================

Decouples event ingestion from processing with an async queue that
supports backpressure, batch processing, and throughput metrics.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from api.logging_utils import logfmt

logger = logging.getLogger(__name__)


@dataclass
class QueueMetrics:
    enqueued_total: int = 0
    processed_total: int = 0
    dropped_total: int = 0
    batch_count: int = 0
    last_batch_size: int = 0
    last_batch_time_ms: float = 0
    _throughput_window: deque = field(default_factory=lambda: deque(maxlen=100))

    @property
    def depth(self) -> int:
        return self.enqueued_total - self.processed_total - self.dropped_total

    @property
    def throughput_eps(self) -> float:
        if len(self._throughput_window) < 2:
            return 0.0
        window = list(self._throughput_window)
        duration = window[-1][0] - window[0][0]
        if duration <= 0:
            return 0.0
        return sum(count for _, count in window) / duration

    def record_batch(self, count: int, duration_ms: float) -> None:
        self.processed_total += count
        self.batch_count += 1
        self.last_batch_size = count
        self.last_batch_time_ms = duration_ms
        self._throughput_window.append((time.time(), count))

    def reset(self) -> None:
        self.enqueued_total = 0
        self.processed_total = 0
        self.dropped_total = 0
        self.batch_count = 0
        self.last_batch_size = 0
        self.last_batch_time_ms = 0
        self._throughput_window.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "queue_depth": self.depth,
            "enqueued_total": self.enqueued_total,
            "processed_total": self.processed_total,
            "dropped_total": self.dropped_total,
            "throughput_eps": round(self.throughput_eps, 1),
            "batch_count": self.batch_count,
            "last_batch_size": self.last_batch_size,
            "last_batch_time_ms": round(self.last_batch_time_ms, 1),
        }


class EventQueue:
    def __init__(self, max_size: int = 10000, batch_size: int = 50, flush_interval: float = 0.5) -> None:
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=max_size)
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None
        self._handler: Optional[Callable] = None
        self.metrics = QueueMetrics()
        logger.info(logfmt("event_queue_init", max_size=max_size, batch_size=batch_size, flush_interval=flush_interval))

    async def enqueue(self, event: Dict[str, Any]) -> bool:
        try:
            self._queue.put_nowait(event)
            self.metrics.enqueued_total += 1
            return True
        except asyncio.QueueFull:
            self.metrics.dropped_total += 1
            logger.warning(logfmt("event_queue_backpressure", max_size=self._queue.maxsize))
            return False

    async def start(self, handler: Callable) -> None:
        if self._running:
            return
        self._handler = handler
        self._running = True
        self._processor_task = asyncio.create_task(self._process_loop())
        logger.info(logfmt("event_queue_start"))

    async def stop(self) -> None:
        self._running = False
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        if self._handler:
            remaining = await self._drain_batch(self._queue.qsize())
            if remaining:
                await self._handler(remaining)
                self.metrics.record_batch(len(remaining), 0.0)
        logger.info(logfmt("event_queue_stop", processed_total=self.metrics.processed_total))

    async def _process_loop(self) -> None:
        while self._running:
            try:
                batch = await self._drain_batch(self._batch_size)
                if batch and self._handler:
                    start = time.perf_counter()
                    await self._handler(batch)
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    self.metrics.record_batch(len(batch), elapsed_ms)
                    logger.info(logfmt("event_queue_batch_processed", batch_size=len(batch), duration_ms=elapsed_ms))
                await asyncio.sleep(self._flush_interval)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception(logfmt("event_queue_processor_error", error=exc))
                await asyncio.sleep(1.0)

    async def _drain_batch(self, max_items: int) -> List[Dict[str, Any]]:
        batch: List[Dict[str, Any]] = []
        for _ in range(max_items):
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch

    def reset(self) -> None:
        if self._processor_task and not self._processor_task.done():
            self._processor_task.cancel()
        self._queue = asyncio.Queue(maxsize=self._queue.maxsize)
        self._handler = None
        self._running = False
        self._processor_task = None
        self.metrics.reset()
        logger.info(logfmt("event_queue_reset", max_size=self._queue.maxsize))

    def stats(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "current_depth": self._queue.qsize(),
            "max_size": self._queue.maxsize,
            "backpressure_active": self._queue.qsize() >= self._queue.maxsize * 0.9,
            **self.metrics.to_dict(),
        }


event_queue = EventQueue()
