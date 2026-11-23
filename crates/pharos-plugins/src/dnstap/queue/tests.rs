use std::{collections::VecDeque, sync::Arc, time::Duration};

use super::*;

fn filled(queue: &Queue, byte: u8) -> bool {
    let Some(mut buffer) = queue.acquire() else {
        return false;
    };
    buffer.push(byte);
    queue.push(buffer);
    true
}

fn drain(queue: &Queue) -> Vec<Vec<u8>> {
    let mut batch = VecDeque::new();
    if queue.try_batch(&mut batch) {
        batch.into_iter().collect()
    } else {
        Vec::new()
    }
}

// CoreDNS v1.15.0 plugin/dnstap/io.go dio.Dnstap: a full queue drops instead of blocking.
#[test]
fn acquire_stops_at_capacity_and_resumes_after_recycle() {
    let queue = Queue::new(2);
    assert!(filled(&queue, 1));
    assert!(filled(&queue, 2));
    assert!(!filled(&queue, 3));
    let mut spent = drain(&queue);
    queue.recycle(&mut spent);
    assert!(spent.is_empty());
    assert!(filled(&queue, 4));
    assert!(filled(&queue, 5));
    assert!(!filled(&queue, 6));
}

#[test]
fn payloads_come_out_in_push_order() {
    let queue = Queue::new(8);
    for byte in 0..5 {
        assert!(filled(&queue, byte));
    }
    let batch = drain(&queue);
    assert_eq!(batch, (0..5).map(|byte| vec![byte]).collect::<Vec<_>>());
    assert!(drain(&queue).is_empty());
}

#[test]
fn recycled_buffers_are_empty_and_keep_their_allocation() {
    let queue = Queue::new(1);
    let mut buffer = queue.acquire().unwrap();
    buffer.extend_from_slice(&[7; 1000]);
    let address = buffer.as_ptr();
    let capacity = buffer.capacity();
    queue.push(buffer);
    let mut spent = drain(&queue);
    queue.recycle(&mut spent);
    let again = queue.acquire().unwrap();
    assert!(again.is_empty());
    assert_eq!(again.as_ptr(), address);
    assert_eq!(again.capacity(), capacity);
}

#[test]
fn oversized_buffers_are_not_retained() {
    let queue = Queue::new(1);
    let mut buffer = queue.acquire().unwrap();
    buffer.resize(MAX_RETAINED_BUFFER + 1, 0);
    queue.push(buffer);
    let mut spent = drain(&queue);
    queue.recycle(&mut spent);
    let again = queue.acquire().unwrap();
    assert!(again.is_empty());
    assert!(again.capacity() <= MAX_RETAINED_BUFFER);
}

#[tokio::test]
async fn next_batch_waits_for_a_push() {
    let queue = Arc::new(Queue::new(4));
    let waiter = {
        let queue = Arc::clone(&queue);
        tokio::spawn(async move {
            let mut batch = VecDeque::new();
            queue.next_batch(&mut batch).await;
            batch.len()
        })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiter.is_finished());
    assert!(filled(&queue, 1));
    assert_eq!(waiter.await.unwrap(), 1);
}

// A push that lands between the writer's empty check and its wait must still wake it.
#[tokio::test]
async fn push_before_wait_is_not_lost() {
    let queue = Queue::new(4);
    assert!(filled(&queue, 1));
    let mut batch = VecDeque::new();
    tokio::time::timeout(Duration::from_secs(5), queue.next_batch(&mut batch))
        .await
        .unwrap();
    assert_eq!(batch.len(), 1);
}

// Many producer threads against one consumer: every message is either delivered or counted as refused.
#[test]
fn concurrent_producers_lose_nothing_silently() {
    const THREADS: usize = 8;
    const EACH: usize = 20_000;
    let queue = Arc::new(Queue::new(64));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let refused = Arc::new(AtomicUsize::new(0));
    let producers: Vec<_> = (0..THREADS)
        .map(|_| {
            let queue = Arc::clone(&queue);
            let refused = Arc::clone(&refused);
            std::thread::spawn(move || {
                for _ in 0..EACH {
                    if !filled(&queue, 1) {
                        refused.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    let delivered = runtime.block_on(async {
        let mut delivered = 0;
        let mut batch = VecDeque::new();
        let mut spent = Vec::new();
        while delivered + refused.load(Ordering::Relaxed) < THREADS * EACH {
            let waited =
                tokio::time::timeout(Duration::from_millis(50), queue.next_batch(&mut batch)).await;
            if waited.is_err() {
                continue;
            }
            delivered += batch.len();
            spent.extend(batch.drain(..));
            queue.recycle(&mut spent);
        }
        delivered
    });
    for producer in producers {
        producer.join().unwrap();
    }
    assert_eq!(delivered + refused.load(Ordering::Relaxed), THREADS * EACH);
    assert!(delivered > 0);
}
