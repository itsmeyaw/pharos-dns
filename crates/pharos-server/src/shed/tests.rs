use super::*;
use crate::metrics::Registry;

#[test]
fn stack_evicts_oldest_and_pops_newest() {
    let registry = Registry::new("v", "r", "rust");
    let stack = ShedStack::new(3, registry.shed("dns://:53"));
    let peer = "127.0.0.1:53".parse().unwrap();
    for value in 1..=5 {
        let mut data = stack.checkout().unwrap();
        data.push(value);
        stack.push(data, peer);
    }
    assert!(stack.full());
    for value in [5, 4, 3] {
        let (data, _) = stack.pop().unwrap();
        assert_eq!(data, [value]);
        stack.release(data);
    }
    assert!(stack.pop().is_none());
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(
        text.contains("reason=\"response\",server=\"dns://:53\"} 2"),
        "{text}"
    );
}

#[test]
fn close_rejects_new_responses_and_drains_accepted_entries() {
    let registry = Registry::new("v", "r", "rust");
    let stack = ShedStack::new(3, registry.shed("dns://:53"));
    let peer = "127.0.0.1:53".parse().unwrap();
    let mut first = stack.checkout().unwrap();
    first.push(1);
    stack.push(first, peer);
    stack.close();
    let second = stack.checkout().unwrap();
    stack.push(second, peer);
    assert_eq!(stack.pop().unwrap().0, [1]);
    assert!(stack.pop().is_none());
    let mut output = String::new();
    registry.encode(&mut output);
    assert!(
        output.contains("reason=\"response\",server=\"dns://:53\"} 1"),
        "{output}"
    );
}

#[test]
fn abandoned_stack_counts_pending_responses() {
    let registry = Registry::new("v", "r", "rust");
    let stack = ShedStack::new(3, registry.shed("dns://:53"));
    let peer = "127.0.0.1:53".parse().unwrap();
    stack.push(stack.checkout().unwrap(), peer);
    stack.push(stack.checkout().unwrap(), peer);
    drop(stack);
    let mut output = String::new();
    registry.encode(&mut output);
    assert!(
        output.contains("reason=\"response\",server=\"dns://:53\"} 2"),
        "{output}"
    );
}

#[tokio::test]
async fn concurrent_buffer_waiters_all_wake_after_release() {
    let registry = Registry::new("v", "r", "rust");
    let stack = Arc::new(ShedStack::new(1, registry.shed("dns://:53")));
    let held = (0..3)
        .map(|_| stack.checkout().unwrap())
        .collect::<Vec<_>>();
    let one = tokio::spawn({
        let stack = Arc::clone(&stack);
        async move { stack.checkout_wait().await }
    });
    let two = tokio::spawn({
        let stack = Arc::clone(&stack);
        async move { stack.checkout_wait().await }
    });
    tokio::task::yield_now().await;
    for data in held {
        stack.release(data);
    }
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        one.await.unwrap();
        two.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_buffer_waiter_does_not_strand_others() {
    let stack = Arc::new(ShedStack::new(1, Registry::default().shed("dns://:53")));
    let mut held = (0..3)
        .map(|_| stack.checkout().unwrap())
        .collect::<Vec<_>>();
    let (first_ready, first_started) = tokio::sync::oneshot::channel();
    let (second_ready, second_started) = tokio::sync::oneshot::channel();
    let first = tokio::spawn({
        let stack = stack.clone();
        async move {
            let _ = first_ready.send(());
            stack.checkout_wait().await
        }
    });
    let second = tokio::spawn({
        let stack = stack.clone();
        async move {
            let _ = second_ready.send(());
            stack.checkout_wait().await
        }
    });
    first_started.await.unwrap();
    second_started.await.unwrap();
    first.abort();
    let _ = first.await;
    stack.release(held.pop().unwrap());
    // Tokio Notify::notified: cancelling a waiter does not strand the next waiter.
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), second)
        .await
        .unwrap()
        .unwrap();
    held.push(response);
    for buffer in held {
        stack.release(buffer);
    }
}

#[tokio::test]
async fn failed_deferred_write_increments_response_counter() {
    let registry = Registry::new("v", "r", "rust");
    let stack = Arc::new(ShedStack::new(3, registry.shed("dns://:53")));
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer = "[::1]:53".parse().unwrap();
    let mut data = stack.checkout().unwrap();
    data.push(1);
    stack.push(data, peer);
    stack.close();
    Arc::clone(&stack).writer(socket).await;
    let mut output = String::new();
    registry.encode(&mut output);
    assert!(
        output.contains("reason=\"response\",server=\"dns://:53\"} 1"),
        "{output}"
    );
}

#[tokio::test]
async fn writer_recovers_panics() {
    assert!(
        recover_write(async { panic!("writer exploded") })
            .await
            .is_none()
    );
    assert_eq!(recover_write(async { Ok(7) }).await.unwrap().unwrap(), 7);
}
