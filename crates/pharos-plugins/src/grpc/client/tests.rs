use super::*;
use tokio::net::TcpListener;

#[test]
fn timeouts_are_whole_milliseconds() {
    for (millis, text) in [(1, "1m"), (5000, "5000m"), (99_999_999, "99999999m")] {
        assert_eq!(timeout_value(millis), text);
    }
}

#[test]
fn a_buffer_returns_to_the_pool_only_when_nothing_else_holds_it() {
    let pool = Pool::default();
    let mut loan = pool.take();
    loan.buffer().extend_from_slice(b"abc");
    let pointer = loan.wire().chunk().as_ptr();
    drop(loan);
    let mut again = pool.take();
    assert_eq!(again.buffer().as_ptr(), pointer);
    again.buffer().extend_from_slice(b"xyz");
    let wire = again.wire();
    drop(again);
    assert!(pool.0.take().is_none());
    assert_eq!(wire.chunk(), b"xyz");
}

// RFC 1035 §4.2.2: a Message of 65,535 octets must not allocate again on the next call.
#[test]
fn pool_keeps_the_buffer_of_a_maximum_size_message() {
    let pool = Pool::default();
    let mut loan = pool.take();
    loan.buffer().resize(usize::from(u16::MAX), 0);
    drop(loan);
    let mut again = pool.take();
    assert!(again.buffer().capacity() >= usize::from(u16::MAX));
}

async fn reaches(bind: &str, host: &str) {
    let Ok(listener) = TcpListener::bind(bind).await else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let target = Target::Host {
        host: host.into(),
        port,
    };
    let client = Client::new(target, None, "localhost").unwrap();
    let (accepted, connected) = tokio::join!(listener.accept(), client.connect());
    connected.unwrap();
    accepted.unwrap();
}

// Go net: a name is resolved when dialling.
#[tokio::test]
async fn a_host_name_is_resolved_at_dial() {
    reaches("127.0.0.1:0", "localhost").await;
}

// Go net: an IPv6 zone is resolved when dialling; interface index 1 is the loopback.
#[tokio::test]
async fn a_scoped_ipv6_address_is_dialled_with_its_zone() {
    reaches("[::1]:0", "::1%1").await;
}

#[tokio::test]
async fn an_invalid_target_fails_every_dial() {
    let client = Client::new(Target::Invalid("bad".into()), None, "localhost").unwrap();
    let error = client.connect().await.err().unwrap();
    assert_eq!(error.to_string(), "bad");
}
