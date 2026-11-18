#![forbid(unsafe_code)]

use pharos_proto::{Message, Name, Rcode, Type};
use pharos_server::{
    Action, Chain, Context, Error, Handler, ListenerKey, Outcome, Protocol, Router, Server,
    Transport,
};
use std::sync::{Arc, Mutex};

static DEPTHS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct Recurse;

impl Chain for Recurse {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        DEPTHS.lock().unwrap().push(cx.self_lookup_depth());
        let name: Name = "loop.example.".parse().unwrap();
        match cx.self_lookup(&name, Type::A).await {
            Ok(response) => {
                assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
                Outcome::Error(Error::InvalidQuery)
            }
            Err(error) => Outcome::Error(error),
        }
    }
    fn is_empty(&self) -> bool {
        false
    }
}

// Inline levels share the caller's stack, so the 10-deep limit must fit a small worker stack.
#[test]
fn deepest_self_lookup_chain_fits_a_one_mebibyte_stack() {
    let thread = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(|| {
            let key = ListenerKey {
                transport: Transport::Dns,
                address: "127.0.0.1:53".parse().unwrap(),
            };
            let mut router = Router::default();
            router.add(key, "example.".parse().unwrap(), Some(Recurse), vec![]);
            let server = Arc::new(Server::new(router, key));
            let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x04loop\x07example\0\0\x01\0\x01";
            let mut response = Vec::with_capacity(512);
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(async {
                    assert_eq!(
                        Handler::handle_shared(
                            &server,
                            query,
                            "192.0.2.10:1234".parse().unwrap(),
                            Protocol::Udp,
                            &mut response,
                        )
                        .await,
                        Action::Respond
                    );
                });
        })
        .unwrap();
    thread.join().unwrap();
    assert_eq!(*DEPTHS.lock().unwrap(), (0..=10).collect::<Vec<u8>>());
}
