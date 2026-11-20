use super::{BufferPool, MAX_IDLE_SCRATCH, max_attempts, primary_attempt_limit};

#[test]
fn returned_buffers_keep_their_contents_and_are_reused() {
    let pool = BufferPool::default();
    {
        let mut buffer = pool.get();
        buffer.parts().bytes[65534] = 123;
    }
    let mut buffer = pool.get();
    assert_eq!(buffer.parts().bytes[65534], 123);
}

#[test]
fn buffer_pool_drops_idle_scratch_above_its_bound() {
    let pool = BufferPool::default();
    let held = (0..MAX_IDLE_SCRATCH + 2)
        .map(|_| pool.get())
        .collect::<Vec<_>>();
    drop(held);
    assert_eq!(pool.0.lock().unwrap().len(), MAX_IDLE_SCRATCH);
}

#[test]
fn connect_attempts_never_exceed_three() {
    assert_eq!(max_attempts(None), 2);
    assert_eq!(max_attempts(Some(0)), 1);
    assert_eq!(max_attempts(Some(2)), 2);
    assert_eq!(max_attempts(Some(9)), 3);
    assert_eq!(primary_attempt_limit(Some(3), true), 2);
    assert_eq!(primary_attempt_limit(Some(3), false), 3);
}
