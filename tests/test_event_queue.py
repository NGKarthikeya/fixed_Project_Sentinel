import pytest
import asyncio
from event_queue import EventQueue

@pytest.mark.asyncio
async def test_event_queue_lifecycle():
    queue = EventQueue(max_size=10, batch_size=2, flush_interval=0.1)
    
    handled_batches = []
    
    async def handler(batch):
        handled_batches.append(batch)
    
    await queue.start(handler)
    
    # Enqueue events
    success = await queue.enqueue({"id": 1})
    assert success
    await queue.enqueue({"id": 2})
    await queue.enqueue({"id": 3})
    
    # Wait for flush
    await asyncio.sleep(0.3)
    
    assert len(handled_batches) >= 1
    
    await queue.stop()
    assert queue._running is False

@pytest.mark.asyncio
async def test_event_queue_backpressure():
    queue = EventQueue(max_size=2, batch_size=2, flush_interval=0.1)
    
    # Don't start the queue processor, just fill it up
    await queue.enqueue({"id": 1})
    await queue.enqueue({"id": 2})
    
    # Third should hit backpressure
    success = await queue.enqueue({"id": 3})
    assert success is False
    
    stats = queue.stats()
    assert stats["dropped_total"] == 1
    assert stats["backpressure_active"] is True
    
@pytest.mark.asyncio
async def test_event_queue_reset():
    queue = EventQueue(max_size=10)
    await queue.enqueue({"id": 1})
    
    stats = queue.stats()
    assert stats["current_depth"] == 1
    
    queue.reset()
    stats_after = queue.stats()
    assert stats_after["current_depth"] == 0
    assert stats_after["running"] is False
